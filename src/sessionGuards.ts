import { fetchAuthSession, signIn } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import {
  isSameLogin,
  readStoredSession,
  type StoredSession,
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
  // Awaited just before the replacing sign-in; throws if this attempt has been
  // superseded (e.g. while the confirm prompt was open).
  beforeSignIn?: () => Promise<void>;
  // Receives the session about to be replaced, to clean up once the new one
  // has been stored.
  onReplaced: (previous: StoredSession) => void;
}): Promise<Awaited<ReturnType<typeof signIn>>> {
  const {
    login,
    doSignIn,
    doSignInIgnoringSession,
    onExistingSession = 'replace',
    adoptSession,
    confirmReplace,
    beforeSignIn,
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
    let previous = await readStoredSession();
    if (previous && confirmReplace && !isSameLogin(previous, login)) {
      const proceed = await confirmReplace({
        username: previous.username,
        ...(previous.email !== undefined ? { email: previous.email } : {}),
      });
      if (!proceed) throw replaceCancelled('Replacing the existing session was declined');
      // The prompt can stay open for a long time: another tab may have
      // changed the session since, and the user only agreed to replace the
      // one they were shown.
      const again = await readStoredSession();
      // A different user now: they were never shown or asked about. (The same
      // user with a rotated refresh token is fine; a vanished session leaves
      // nothing to clean up.)
      if (again && again.username !== previous.username) {
        throw replaceCancelled(
          'The stored session changed while waiting for confirmation; try again',
        );
      }
      previous = again;
    }
    await beforeSignIn?.();
    if (previous) onReplaced(previous);
    return doSignInIgnoringSession();
  }
}

function replaceCancelled(message: string): Error {
  const cancelled = new Error(message);
  cancelled.name = REPLACE_CANCELLED_EXCEPTION;
  return cancelled;
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
  // Opt-in: retry transient failures after each delay, and if they all fail
  // call onTransientFailure and leave the state alone (neither logged in nor
  // out) instead of logging the tab out.
  retry?: {
    delaysMs: number[];
    onTransientFailure: () => void;
    sleep?: (ms: number) => Promise<void>;
  };
}): Promise<void> {
  const { fetchSession, loadUser, clearCurrentUser, isStale, retry } = deps;
  const sleep =
    retry?.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let attempt = 0; ; attempt++) {
    try {
      const session = await fetchSession();
      if (isStale()) return;
      if (session.tokens) {
        await loadUser();
        return;
      }
      break;
    } catch (err) {
      if (isStale()) return;
      if (isTokenClearingError(err)) {
        try {
          await clearLocalTokens();
        } catch {
          // Best-effort.
        }
        break;
      }
      if (retry) {
        if (attempt < retry.delaysMs.length) {
          await sleep(retry.delaysMs[attempt]);
          if (isStale()) return;
          continue;
        }
        retry.onTransientFailure();
        return;
      }
      break;
    }
  }
  clearCurrentUser();
}
