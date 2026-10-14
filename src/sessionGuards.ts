import { fetchAuthSession, signIn } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import {
  cleanUpReplacedSession,
  isSameLogin,
  readStoredSession,
} from './storedSession';

export const ALREADY_SIGNED_IN_EXCEPTION = 'AlreadySignedInException';

export type OnExistingSession = 'replace' | 'reject';

export const REPLACE_CANCELLED_EXCEPTION = 'ReplaceCancelledException';

export function isReplaceCancelledError(err: unknown): err is Error {
  return err instanceof Error && err.name === REPLACE_CANCELLED_EXCEPTION;
}

// Asked before a login replaces a DIFFERENT user's stored session (a stale
// login form in a second tab). Resolve false to cancel. It runs before the
// password is checked.
export type ConfirmReplace = (existing: {
  // The Cognito username (may be a UUID rather than the email).
  username: string;
  // The email on that user's stored ID token, when readable.
  email?: string;
}) => boolean | Promise<boolean>;

export function isAlreadySignedInError(err: unknown): err is Error {
  return err instanceof Error && err.name === ALREADY_SIGNED_IN_EXCEPTION;
}

// Mirrors the error names (prefix match) for which Amplify's TokenOrchestrator
// clears the stored tokens after a failed refresh (6.20.x,
// isAuthenticationError). App state follows Amplify: where it has cleared the
// tokens we log the app out too; for transient errors (network, throttling)
// the tokens are kept, so we do nothing. The mount check and 'reject' path
// reuse the same names to decide a failed call means the tokens are dead.
const TOKEN_CLEARING_ERRORS = [
  'NotAuthorizedException',
  'TokenRevokedException',
  'UserNotFoundException',
  'PasswordResetRequiredException',
  'UserNotConfirmedException',
  'RefreshTokenReuseException',
];

export function isTokenClearingError(err: unknown): boolean {
  const name = (err as { name?: unknown } | null | undefined)?.name;
  return (
    typeof name === 'string' &&
    TOKEN_CLEARING_ERRORS.some((n) => name.startsWith(n))
  );
}

// Clears locally stored tokens only - unlike `signOut()` this does not revoke
// the refresh token. NOTE: tokens live in shared storage (localStorage by
// default, one session per origin + client id), so this removes the session
// from storage for every tab (other tabs' React state is not updated until
// they next fetch a session); it just avoids the server-side revoke.
async function clearLocalTokens(): Promise<void> {
  await cognitoUserPoolsTokenProvider.tokenOrchestrator.clearTokens();
}

// Wraps a `signIn` call with handling for Amplify's
// UserAlreadyAuthenticatedException (only thrown when the stored tokens are
// currently usable - Amplify refreshes expired ones first).
//  - 'replace' (default): sign in again WITHOUT signing out first
//    (`doSignInIgnoringSession`), so a wrong password or an abandoned
//    challenge leaves the existing session alone. The session it replaced is
//    cleaned up by `onReplaced`'s callback once Amplify reports success (see
//    cleanUpReplacedSession). If `confirmReplace` is given and the stored user
//    is a different login, it is asked first; false throws
//    ReplaceCancelledException with nothing touched.
//  - 'reject': if the existing session is valid, try to adopt it into this
//    tab (`adoptSession`) and throw AlreadySignedInException; the session is
//    never revoked. If adopting fails because the tokens are definitively
//    dead (e.g. revoked server-side), clear them locally (no revoke) and
//    retry once, so the user is not locked out. If there are no tokens (a
//    race with another tab) do the same.
export async function signInHandlingExistingSession(deps: {
  // The login as typed.
  login: string;
  doSignIn: () => ReturnType<typeof signIn>;
  doSignInIgnoringSession: () => ReturnType<typeof signIn>;
  onExistingSession?: OnExistingSession;
  adoptSession?: () => Promise<unknown>;
  confirmReplace?: ConfirmReplace;
  // Receives the cleanup to run once the new session has been stored.
  onReplaced: (cleanup: () => Promise<void>) => void;
}): Promise<Awaited<ReturnType<typeof signIn>>> {
  const {
    login,
    doSignIn,
    doSignInIgnoringSession,
    onExistingSession = 'replace',
    adoptSession,
    confirmReplace,
    onReplaced,
  } = deps;
  try {
    return await doSignIn();
  } catch (err) {
    if (
      !(err instanceof Error) ||
      err.name !== 'UserAlreadyAuthenticatedException'
    ) {
      throw err;
    }
    if (onExistingSession === 'reject') {
      // If this throws (e.g. a network failure during a refresh) we can't
      // tell a dead session from a live one, so rethrow rather than clear.
      const session = await fetchAuthSession();
      if (session.tokens) {
        try {
          await adoptSession?.();
        } catch (adoptErr) {
          if (!isTokenClearingError(adoptErr)) {
            // Transient: leave the tokens alone.
            throw alreadySignedIn();
          }
          await clearLocalTokens();
          return doSignIn();
        }
        throw alreadySignedIn();
      }
      await clearLocalTokens();
      return doSignIn();
    }
    const previous = await readStoredSession();
    if (previous) {
      if (confirmReplace && !isSameLogin(previous, login)) {
        const proceed = await confirmReplace({
          username: previous.username,
          ...(previous.email !== undefined ? { email: previous.email } : {}),
        });
        if (!proceed) {
          const cancelled = new Error('Replacing the existing session was declined');
          cancelled.name = REPLACE_CANCELLED_EXCEPTION;
          throw cancelled;
        }
      }
      onReplaced(() => cleanUpReplacedSession(previous));
    }
    return doSignInIgnoringSession();
  }
}

function alreadySignedIn(): Error {
  const rejection = new Error('A session is already active');
  rejection.name = ALREADY_SIGNED_IN_EXCEPTION;
  return rejection;
}

export function isRefreshTokenRejected(payload: {
  event: string;
  data?: unknown;
}): boolean {
  if (payload?.event !== 'tokenRefresh_failure') return false;
  return isTokenClearingError(
    (payload.data as { error?: unknown } | undefined)?.error,
  );
}

// Mount-time session check. A failure at any step never signs out (that
// revokes the refresh token). If loading the user fails with an error for
// which Amplify itself would clear tokens (e.g. the access token was revoked
// server-side while still unexpired), the dead tokens are cleared locally
// (no revoke) so they can't block a later sign in. Transient failures leave
// the tokens alone. `isStale` reports that the pool changed while awaiting.
export async function checkSessionOnMount(deps: {
  fetchSession: () => Promise<{ tokens?: unknown }>;
  loadUser: () => Promise<unknown>;
  clearCurrentUser: () => void;
  isStale: () => boolean;
}): Promise<void> {
  const { fetchSession, loadUser, clearCurrentUser, isStale } = deps;
  try {
    const session = await fetchSession();
    if (isStale()) return;
    if (session.tokens) {
      await loadUser();
      return;
    }
  } catch (err) {
    if (isStale()) return;
    if (isTokenClearingError(err)) {
      try {
        await clearLocalTokens();
      } catch {
        // Best effort.
      }
    }
  }
  clearCurrentUser();
}
