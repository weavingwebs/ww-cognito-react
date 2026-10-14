import { Amplify } from 'aws-amplify';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';

// Discarding the session Amplify has stored for ONE named user, rather than
// whichever user is current (`signOut`): after a race with another tab the
// current user may not be the one we mean to discard.
//
// ASSUMPTION (not testable without Cognito): the `username` passed in, the ID
// token's `cognito:username`, is also the name Amplify stored the tokens under
// (the challenge's USERNAME / USER_ID_FOR_SRP). If they ever differ nothing is
// removed here and the session stays stored.

// The per-user keys Amplify's TokenStore writes (@aws-amplify/auth 6.21.1,
// bundled by aws-amplify 6.22.1: storeTokens / clearTokens). Device keys are
// left alone: Amplify's own clearTokens keeps them too.
const TOKEN_KEY_SUFFIXES = [
  'accessToken',
  'idToken',
  'refreshToken',
  'signInDetails',
  'clockDrift',
  'oauthMetadata',
];

// A stalled connection to Cognito must not hold anything up.
const REVOKE_TIMEOUT_MS = 4000;

function keyPrefix(): string | null {
  const clientId = Amplify.getConfig().Auth?.Cognito?.userPoolClientId;
  return clientId ? `CognitoIdentityServiceProvider.${clientId}.` : null;
}

// Through Amplify's configured storage, never localStorage directly.
const storage = () =>
  cognitoUserPoolsTokenProvider.authTokenStore.getKeyValueStorage();

function cognitoEndpoint(): string {
  const { userPoolId, userPoolEndpoint } =
    Amplify.getConfig().Auth?.Cognito ?? {};
  if (userPoolEndpoint) return userPoolEndpoint;
  const region = userPoolId?.split('_')[0];
  if (!region || !/^[a-z]{2}(-[a-z]+)+-\d+$/.test(region)) {
    throw new Error('Cognito is not configured');
  }
  const suffix = region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
  return `https://cognito-idp.${region}.${suffix}/`;
}

function decodePayload(jwt: string | null): Record<string, unknown> | null {
  try {
    const part = jwt?.split('.')[1];
    return part
      ? (JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/'))) as Record<
          string,
          unknown
        >)
      : null;
  } catch {
    return null;
  }
}

async function revokeRefreshToken(refreshToken: string): Promise<void> {
  const clientId = Amplify.getConfig().Auth?.Cognito?.userPoolClientId;
  if (!clientId) throw new Error('Cognito is not configured');
  // AbortSignal.timeout is missing before Safari 16 / older Chromium.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REVOKE_TIMEOUT_MS);
  try {
    // RevokeToken is unauthenticated for a public app client: the token is the
    // credential, and goes in the body only. Never log it. keepalive lets the
    // request outlive a page that is closing or reloading.
    const res = await fetch(cognitoEndpoint(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.RevokeToken',
      },
      body: JSON.stringify({ Token: refreshToken, ClientId: clientId }),
      keepalive: true,
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`RevokeToken failed with status ${res.status}`);
    }
  } finally {
    clearTimeout(timer);
  }
}

export type DiscardResult = {
  // Settles when the revoke has finished; never rejects. false if there was
  // nothing to revoke or the revoke failed (the refresh token then stays valid
  // server-side until it expires).
  revoked: Promise<boolean>;
};

// Removes that user's stored tokens, then starts revoking their refresh token
// WITHOUT waiting for it: the caller can act on the local state at once.
// LastAuthUser (the one key that picks the current user) is removed only if it
// still names this user, so another user's session is never logged out by it.
// NOTE: the check and the removal are not atomic, so another tab signing in
// between them can lose its LastAuthUser pointer (its tokens stay stored);
// Amplify gives no way to close that gap. Best-effort: never throws.
export async function discardStoredSession(
  username: string,
): Promise<DiscardResult> {
  const none: DiscardResult = { revoked: Promise.resolve(false) };
  let prefix: string | null;
  let kv: ReturnType<typeof storage>;
  try {
    prefix = keyPrefix();
    if (!prefix) return none;
    kv = storage();
  } catch {
    return none;
  }
  // Read the token now rather than trusting an earlier snapshot. NOTE: by
  // name, so if a newer login as the same user landed in the last few
  // microtasks it is discarded too (the old signOut() had the same limit).
  let refreshToken: string | null = null;
  let revocable = false;
  try {
    refreshToken = await kv.getItem(`${prefix}${username}.refreshToken`);
    // Like Amplify's signOut: only tokens carrying origin_jti can be revoked.
    revocable =
      decodePayload(await kv.getItem(`${prefix}${username}.accessToken`))
        ?.origin_jti !== undefined;
  } catch {
    // Best-effort.
  }
  // Remove the local keys first: this must happen even if the revoke is slow
  // or fails.
  try {
    if ((await kv.getItem(`${prefix}LastAuthUser`)) === username) {
      await kv.removeItem(`${prefix}LastAuthUser`);
    }
  } catch {
    // Best-effort.
  }
  for (const suffix of TOKEN_KEY_SUFFIXES) {
    try {
      await kv.removeItem(`${prefix}${username}.${suffix}`);
    } catch {
      // Best-effort.
    }
  }
  if (!refreshToken || !revocable) return none;
  return {
    revoked: revokeRefreshToken(refreshToken).then(
      () => true,
      (err: unknown) => {
        // eslint-disable-next-line no-console
        console.error(
          'Could not revoke the discarded session:',
          err instanceof Error ? err.message : 'unknown error',
        );
        return false;
      },
    ),
  };
}

// Makes `username` the current user again, but only if no one is current and
// that user still has a refresh token stored. Used when an attempt took
// LastAuthUser from the user this tab is showing and was then discarded.
export async function restoreStoredSession(username: string): Promise<boolean> {
  try {
    const prefix = keyPrefix();
    if (!prefix) return false;
    const kv = storage();
    if (await kv.getItem(`${prefix}LastAuthUser`)) return false;
    if (!(await kv.getItem(`${prefix}${username}.refreshToken`))) return false;
    await kv.setItem(`${prefix}LastAuthUser`, username);
    return true;
  } catch {
    return false;
  }
}
