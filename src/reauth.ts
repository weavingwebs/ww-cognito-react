import { Amplify, createAmplifyContext } from 'aws-amplify';
import {
  fetchAuthSession,
  getCurrentUser,
  signIn,
  signOut,
  type SignInInput,
  type SignInOutput,
} from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';

type GetTokens = typeof cognitoUserPoolsTokenProvider.getTokens;

export const REAUTH_ABORTED_EXCEPTION = 'ReauthAbortedException';
export const REAUTH_NOT_FRESH_EXCEPTION = 'ReauthNotFreshException';

export const REAUTH_NOT_LOGGED_IN_EXCEPTION = 'ReauthNotLoggedInException';

export const isReauthNotLoggedInError = (err: unknown): boolean =>
  (err as { name?: unknown } | null | undefined)?.name ===
  REAUTH_NOT_LOGGED_IN_EXCEPTION;

export const isReauthAbortedError =(err: unknown): boolean =>
  (err as { name?: unknown } | null | undefined)?.name ===
  REAUTH_ABORTED_EXCEPTION;
export const isReauthNotFreshError = (err: unknown): boolean =>
  (err as { name?: unknown } | null | undefined)?.name ===
  REAUTH_NOT_FRESH_EXCEPTION;

export function reauthError(name: string, message: string): Error {
  const err = new Error(message);
  err.name = name;
  return err;
}

// Amplify's signIn refuses to run while a session exists, so a signed-in user
// cannot re-authenticate (e.g. to reset `auth_time`) without signing out.
// This signs in through a throwaway context whose first token read (that
// check) sees no session; every later read & write uses the real one, so the
// new tokens replace the live ones only when Amplify stores them on success.
// NOTE: relies on Amplify internals (verified against aws-amplify 6.22.1,
// pinned by reauth.test.ts). If a later Amplify stops making that read first,
// the failure is not guaranteed to be a clean refusal: the sign-in could store
// the new tokens and then throw. The test asserts the read happens before any
// request, so upgrade Amplify with `yarn test` as the gate.
export function signInIgnoringSession(
  input: SignInInput,
  hooks?: { onHiddenRead?: () => void },
): Promise<SignInOutput> {
  let hidden = true;
  const getTokens: GetTokens = (options) => {
    if (hidden) {
      hidden = false;
      hooks?.onHiddenRead?.();
      return Promise.resolve(null);
    }
    return cognitoUserPoolsTokenProvider.getTokens(options);
  };
  const ctx = createAmplifyContext(Amplify.getConfig(), {
    Auth: { tokenProvider: { getTokens } },
  });
  return signIn(ctx, input);
}

// Amplify keeps one global sign-in state, so only the latest attempt (or plain
// sign-in) can be answered: an older attempt's callbacks would otherwise
// answer the newer one's challenge.
let latestAttempt = 0;
export function supersedeReauthAttempts(): number {
  return ++latestAttempt;
}

export type ReauthGuard = {
  // Before each confirmSignIn: still the same attempt, still logged in as the
  // same user.
  beforeStep: () => Promise<void>;
  // When Amplify reports success, before the user is loaded: as above, then
  // the session must carry a newer auth_time (see below).
  beforeSuccess: () => Promise<void>;
};

// For a plain authenticate(): its challenge callbacks must stop working once
// anything newer has started (Amplify has one global sign-in state). Only the
// steps are guarded: by the time Amplify reports success it has already stored
// the tokens and fired Hub `signedIn`, so refusing to load the user would leave
// the tab logged out over a valid stored session (e.g. a double-submitted login).
export function createSupersessionGuard(): ReauthGuard {
  const attempt = supersedeReauthAttempts();
  return {
    beforeStep: async () => {
      if (attempt !== latestAttempt) {
        throw reauthError(
          REAUTH_ABORTED_EXCEPTION,
          'This sign-in attempt was superseded by a newer one',
        );
      }
    },
    beforeSuccess: async () => {},
  };
}

export type ReauthGuardDeps = {
  username: string;
  // auth_time (seconds) of the session when the attempt started, if known.
  startAuthTime: number | undefined;
  // This tab's view: the username it believes is logged in.
  tabUsername: () => string | undefined;
  // Amplify's view of the live session; undefined when logged out. Must
  // rethrow anything that is not a plain "no session" (e.g. network errors).
  liveUsername: () => Promise<string | undefined>;
  liveAuthTime: () => Promise<number | undefined>;
  signOut: () => Promise<unknown>;
  // Resets this tab's logged-in state, for when the session it showed has been
  // replaced and discarded.
  clearTabUser: () => void;
};

export const defaultReauthDeps = {
  liveUsername: async (): Promise<string | undefined> => {
    try {
      return (await getCurrentUser()).username;
    } catch (err) {
      if ((err as { name?: unknown } | null)?.name === 'UserUnAuthenticatedException') {
        return undefined;
      }
      throw err;
    }
  },
  liveAuthTime: async (): Promise<number | undefined> => {
    const authTime = (await fetchAuthSession()).tokens?.idToken?.payload
      .auth_time;
    return typeof authTime === 'number' ? authTime : undefined;
  },
  signOut: () => signOut(),
};

export function createReauthGuard(deps: ReauthGuardDeps): ReauthGuard {
  const attempt = supersedeReauthAttempts();

  const assertSameUser = async () => {
    if (attempt !== latestAttempt) {
      throw reauthError(
        REAUTH_ABORTED_EXCEPTION,
        'Re-authentication was superseded by a newer sign-in attempt',
      );
    }
    // This tab (a logout here clears it) and Amplify's storage (a logout or
    // user change in another tab). A transient failure reading the latter
    // throws as itself: it is not a logout.
    const live = await deps.liveUsername();
    if (deps.tabUsername() !== deps.username || live !== deps.username) {
      throw reauthError(
        REAUTH_ABORTED_EXCEPTION,
        'The session changed during re-authentication (logged out or a different user)',
      );
    }
  };

  return {
    beforeStep: assertSameUser,
    beforeSuccess: async () => {
      try {
        // Amplify has stored the new tokens by now, so a failure here means
        // the tab logged out while the last answer was in flight: discard the
        // session that answer created rather than resurrect it.
        await assertSameUser();
      } catch (err) {
        const tabUser = deps.tabUsername();
        if (isReauthAbortedError(err) && tabUser !== deps.username) {
          await deps.signOut();
          // The tab showed another user, whose tokens this attempt has just
          // overwritten & discarded: it must not keep showing them.
          if (tabUser !== undefined) deps.clearTabUser();
        }
        throw err;
      }
      // A token refresh in flight at the same time can store tokens from the
      // old refresh token after the new sign-in, restoring the old auth_time.
      if (deps.startAuthTime !== undefined) {
        const authTime = await deps.liveAuthTime();
        if (authTime === undefined || authTime <= deps.startAuthTime) {
          throw reauthError(
            REAUTH_NOT_FRESH_EXCEPTION,
            'Re-authentication did not produce a newer auth_time; try again',
          );
        }
      }
    },
  };
}
