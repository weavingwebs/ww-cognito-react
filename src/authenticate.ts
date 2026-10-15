import { signIn } from 'aws-amplify/auth';
import { Hub } from 'aws-amplify/utils';
import {
  createReauthGuard,
  isAmplifyInternalsChangedError,
  createSupersessionGuard,
  defaultReauthDeps,
  signInIgnoringSession,
} from './reauth';
import {
  signInHandlingExistingSession,
  type OnExistingSession,
} from './sessionGuards';
import { cleanUpReplacedSession } from './storedSession';
import { beginOwnSignIn, duringOwnSignIn } from './userChange';
import type { ReauthGuard, ReauthGuardDeps } from './reauth';
import type { AuthenticateOptions, AuthenticateResult } from './types';

type SignInOutput = Awaited<ReturnType<typeof signIn>>;
type AuthFlowType = 'USER_SRP_AUTH' | 'CUSTOM_WITH_SRP';
type MapSignInResult = (
  output: SignInOutput,
  clientMetadata?: Record<string, string>,
  guard?: ReauthGuard,
) => Promise<AuthenticateResult>;

function signInInput(
  username: string,
  password: string,
  authFlowType: AuthFlowType,
  clientMetadata?: Record<string, string>,
) {
  return {
    username,
    password,
    options: {
      authFlowType,
      ...(clientMetadata ? { clientMetadata } : {}),
    },
  };
}

// Records the user Amplify reports signing in (Hub `signedIn`, which it
// dispatches right after storing the tokens), so the cleanup of a replaced
// session does not have to trust LastAuthUser a moment later. Ends at the first
// event, when stopped, or when a newer authenticate starts (an abandoned
// attempt must not keep listening).
let stopOlderCapture: (() => void) | undefined;
function captureSignedInUser() {
  stopOlderCapture?.();
  let username: string | undefined;
  let stop: (() => void) | undefined = Hub.listen('auth', ({ payload }) => {
    if (payload.event !== 'signedIn') return;
    const name = (payload.data as { username?: unknown } | undefined)?.username;
    if (typeof name === 'string') username = name;
    stop?.();
  });
  const end = () => {
    stop?.();
    stop = undefined;
  };
  stopOlderCapture = end;
  return { username: () => username, stop: end };
}

// The body of AuthState.authenticate, extracted so it is unit-testable without
// a React tree.
export async function authenticateWith(deps: {
  email: string;
  pass: string;
  opts?: AuthenticateOptions;
  authFlowType: AuthFlowType;
  mapSignInResult: MapSignInResult;
  loadUserFromSession: () => Promise<unknown>;
}): Promise<AuthenticateResult> {
  const { email, pass, opts, authFlowType, mapSignInResult } = deps;
  const clientMetadata = opts?.clientMetadata;
  // Set when a 'replace' login finds a session to clean up; run by the guard
  // once Amplify reports success.
  let cleanUp: (() => Promise<void>) | undefined;
  let capture: ReturnType<typeof captureSignedInUser> | undefined;
  // Amplify has one global sign-in state: this starts a new exchange, and ends
  // any older one. NOTE: that happens even if a confirmReplace prompt is then
  // declined.
  const guard = createSupersessionGuard(async () => {
    const run = cleanUp;
    cleanUp = undefined;
    try {
      await run?.();
    } finally {
      capture?.stop();
    }
  });
  stopOlderCapture?.();

  // Amplify refuses to sign in if it thinks a session is already active, even
  // if our app state disagrees (e.g. a stale local session). See
  // signInHandlingExistingSession.
  const login = email.trim();
  const input = signInInput(login, pass, authFlowType, clientMetadata);
  // Storage flips to the new user inside Amplify's calls, before this tab has
  // loaded them, so those calls and the load after them are marked as this
  // tab's own (never the confirmReplace prompt between them, which can last
  // minutes). Held from the first Amplify call until the load has finished.
  let release: (() => void) | undefined;
  const hold = () => {
    release ??= beginOwnSignIn();
  };
  const drop = () => {
    release?.();
    release = undefined;
  };
  let result: Awaited<ReturnType<typeof signIn>>;
  try {
    result = await signInHandlingExistingSession({
      login,
      doSignIn: async () => {
        hold();
        try {
          return await signIn(input);
        } catch (err) {
          drop(); // refused or failed: nothing flipped
          throw err;
        }
      },
      doSignInIgnoringSession: async () => {
        hold();
        try {
          return await signInIgnoringSession(input);
        } catch (err) {
          // Amplify throws these AFTER storing the new tokens, so the replaced
          // session must still be cleaned up. The cleanup decides from what is
          // stored, so it is safe to run. The tab is NOT loaded from storage
          // here: with no `signedIn` event there is no way to tell that the
          // stored user is the one this attempt signed in (another tab may have
          // swapped it), so the error asks for a reload. (Other causes, e.g.
          // storage that drops writes, leave nothing to clean up.)
          const name = (err as { name?: unknown } | null)?.name;
          if (
            isAmplifyInternalsChangedError(err) ||
            name === 'UnexpectedSignInInterruptionException'
          ) {
            await guard.beforeSuccess();
          }
          drop();
          throw err;
        }
      },
      onExistingSession: opts?.onExistingSession,
      adoptSession: deps.loadUserFromSession,
      // Not for an empty submit (nothing was tried). Any non-empty pair still
      // shows the stored identity to whoever is at the form.
      confirmReplace: login && pass ? opts?.confirmReplace : undefined,
      beforeSignIn: () => guard.beforeStep(),
      onReplaced: (previous) => {
        capture = captureSignedInUser();
        const recorded = capture;
        cleanUp = () => cleanUpReplacedSession(previous, recorded.username());
      },
    });
  } catch (err) {
    // The sign-in failed (or was declined): the existing session stays.
    cleanUp = undefined;
    capture?.stop();
    drop();
    throw err;
  }
  try {
    return await mapSignInResult(result, clientMetadata, guard);
  } finally {
    drop();
  }
}

// The body of AuthStateLoggedIn.reauthenticate. The live session is left alone
// until Amplify stores the new tokens over it on success.
export async function reauthenticateWith(deps: {
  username: string;
  pass: string;
  clientMetadata?: Record<string, string>;
  authFlowType: AuthFlowType;
  mapSignInResult: MapSignInResult;
  // The tab's current user (a logout clears it) and the session's auth_time.
  tabUsername: () => string | undefined;
  startAuthTime: number | undefined;
  clearTabUser: () => void;
  // Overrides for tests.
  guardDeps?: Partial<ReauthGuardDeps>;
}): Promise<AuthenticateResult> {
  const { username, pass, clientMetadata, authFlowType } = deps;
  const guardDeps = { ...defaultReauthDeps, ...deps.guardDeps };
  // The tab's snapshot can be older than the stored session (another tab may
  // have re-authenticated): the new auth_time must beat whichever is newer.
  const stored = await guardDeps.liveAuthTime().catch(() => undefined);
  const guard = createReauthGuard({
    username,
    startAuthTime:
      deps.startAuthTime === undefined || stored === undefined
        ? (deps.startAuthTime ?? stored)
        : Math.max(deps.startAuthTime, stored),
    tabUsername: deps.tabUsername,
    clearTabUser: deps.clearTabUser,
    ...guardDeps,
  });
  // Amplify stores the new tokens as soon as it succeeds, so with no challenge
  // this is the only chance to see that the session changed since this tab
  // loaded it.
  await guard.beforeStep();
  return duringOwnSignIn(async () => {
    let result: Awaited<ReturnType<typeof signInIgnoringSession>>;
    try {
      result = await signInIgnoringSession(
        signInInput(username, pass, authFlowType, clientMetadata),
      );
    } catch (err) {
      if (isAmplifyInternalsChangedError(err)) {
        // The tokens may be stored although the user was not loaded. Run the
        // success checks so a session this tab logged out of meanwhile is still
        // discarded; if they fail, that error (which already did the
        // discarding) is the more useful one.
        await guard.beforeSuccess();
      }
      throw err;
    }
    return deps.mapSignInResult(result, clientMetadata, guard);
  });
}
