import type { ConfirmReplace, OnExistingSession } from './sessionGuards';
import type { OnUserChange } from './userChange';
import type { AuthUser, FetchUserAttributesOutput } from 'aws-amplify/auth';

export type UserPoolConfig = {
  userPoolId: string;
  userPoolClientId: string;
  authFlowType?: 'USER_SRP_AUTH' | 'CUSTOM_WITH_SRP';
};

/**
 * Must be pure: fully reconstruct the returned object from `attributes` on
 * every call. Never conditionally omit a field, and never mutate/reuse a
 * previous return value - the provider relies on this to detect when the
 * user object hasn't actually changed.
 */
/**
 * Everything here is opt-in: with no options the provider behaves as in 3.2.
 */
export type AuthProviderOptions = {
  /**
   * Keep this tab in step with the session in browser storage: follow a
   * login/logout in another tab (re-checking storage, not trusting the event),
   * refresh the claims after a token refresh, and react when another tab
   * signed in as a DIFFERENT user (see `onUserChange`).
   */
  syncTabs?: boolean;
  /**
   * How to react when the stored user is no longer the one this tab shows.
   * `'reload'` (the default with `syncTabs`) reloads the page once (logging the
   * tab out if it cannot); a function is called instead and must stop
   * presenting the old user itself. Without `syncTabs` or this option, the tab silently
   * switches user as in 3.2.
   */
  onUserChange?: OnUserChange;
  /**
   * `getIdJwt` / `getAccessJwt` stop hiding problems behind `null`: a transient
   * failure throws, a session Amplify has dropped logs the tab out, and tokens
   * belonging to a different user than the state object the getter came from
   * throw `UserChangedException` (`isUserChangedError`) so code written for the
   * old user cannot send the new user's token. Callers must catch.
   */
  strictTokens?: boolean;
  /**
   * Retry a failed mount-time session check (3 tries) and, if it still fails,
   * stay at `isLoggedIn: null` with `sessionCheckFailed` instead of logging the
   * tab out. Anything that treats `null` as "loading" must handle that state.
   */
  retrySessionCheck?: boolean;
};

export type BuildUserFn<User> = (
  authUser: AuthUser,
  attributes: FetchUserAttributesOutput,
) => User;

export type CompleteNewPasswordChallengeFn = (
  newPassword: string,
  attributes?: Record<string, string>,
  // Defaults to the clientMetadata the exchange started with.
  clientMetadata?: Record<string, string>,
) => Promise<AuthenticateResult>;

export type RespondToTotpChallengeFn = (
  totpCode: string,
) => Promise<AuthenticateResult>;

export type CompleteMfaSetupChallengeFn = (
  totpCode: string,
  friendlyDeviceName: string,
) => Promise<AuthenticateResult>;

export type SendCustomChallengeAnswerFn = (
  answerChallenge: string,
  // Defaults to the clientMetadata the exchange started with.
  clientMetadata?: Record<string, string>,
) => Promise<AuthenticateResult>;

export type AuthenticateOptions = {
  /** What to do if a session already exists. */
  onExistingSession?: OnExistingSession;
  /**
   * With `onExistingSession: 'replace'` (the default), called before the
   * sign-in when the browser holds a session for a DIFFERENT user (e.g. a stale
   * login form in a second tab), so the app can warn that continuing replaces
   * it. Resolve `false` to cancel: `authenticate` then throws
   * `ReplaceCancelledException` (`isReplaceCancelledError`) and nothing is
   * touched. Without it the session is replaced silently. Not called for the
   * same user, for `'reject'`, or when there is no session. It runs before the
   * password is checked.
   */
  confirmReplace?: ConfirmReplace;
  /**
   * Sent with the sign-in and re-sent on every step of the exchange (Cognito
   * does not carry it between calls), e.g. `{ mfaAction: 'setup' }`.
   */
  clientMetadata?: Record<string, string>;
};

export type AuthenticateResult =
  | { result: 'SUCCESS' }
  | {
      result: 'NEW_PASSWORD_REQUIRED';
      completeNewPasswordChallenge: CompleteNewPasswordChallengeFn;
    }
  | {
      result: 'TOTP_REQUIRED';
      respondToTotpChallenge: RespondToTotpChallengeFn;
    }
  | {
      result: 'MFA_SETUP';
      beginMfaSetupChallenge: () => Promise<{ secret: string }>;
      completeMfaSetupChallenge: CompleteMfaSetupChallengeFn;
    }
  | {
      result: 'CUSTOM_CHALLENGE';
      challengeParameters: Record<string, string>;
      sendCustomChallengeAnswer: SendCustomChallengeAnswerFn;
    };

export type AuthStateUnknown = {
  isLoggedIn: null;
  /**
   * Only with `options.retrySessionCheck`: the mount-time session check failed
   * (e.g. offline) after retries. The tab is neither logged in nor out;
   * `retrySessionCheck()` tries again.
   */
  sessionCheckFailed?: boolean;
  retrySessionCheck?: () => void;
};

export type AuthStateAnon = {
  isLoggedIn: false;
  authenticate: (
    email: string,
    pass: string,
    opts?: AuthenticateOptions,
  ) => Promise<AuthenticateResult>;
  resetPassword: (email: string) => Promise<void>;
  confirmResetPassword: (
    email: string,
    code: string,
    newPassword: string,
  ) => Promise<void>;
};

export type AuthStateLoggedIn<User> = {
  isLoggedIn: true;
  user: User;
  getAccessJwt: () => Promise<string | null>;
  getIdJwt: () => Promise<string | null>;
  /**
   * ID token claims, held beside `user` (not inside it). UI hints only: never
   * gate anything on them (a backend read failure can yield `mfaEnrolled:
   * false`). `emailVerified` is undefined when the claim is missing.
   */
  emailVerified: boolean | undefined;
  mfaEnrolled: boolean;
  mfaRequired: boolean;
  /**
   * Forces a token refresh then reloads the user and claims, e.g. after MFA
   * enrolment. NOTE: not a re-authentication, the refreshed ID token keeps its
   * original `auth_time` (use `reauthenticate`).
   */
  refreshSession: () => Promise<void>;
  /**
   * Signs the current user in again without signing out, e.g. to get a fresh
   * `auth_time`. The live session is untouched unless the attempt succeeds.
   * Throws `ReauthAbortedException` / `ReauthNotFreshException`, or
   * `AmplifyInternalsChangedException` if a changed Amplify broke the sign-in
   * (see README).
   */
  reauthenticate: (
    pass: string,
    opts?: { clientMetadata?: Record<string, string> },
  ) => Promise<AuthenticateResult>;
  logout: () => Promise<void>;
  changePassword: (oldPwd: string, newPwd: string) => Promise<void>;
  updateEmail: (
    email: string,
  ) => Promise<{ verifyEmail: (code: string) => Promise<void> }>;
  /** Sends a code to the current email address, to re-verify it. */
  sendEmailVerificationCode: () => Promise<void>;
  /** Confirms that code, then refreshes the claims (`emailVerified`). */
  confirmEmailVerificationCode: (code: string) => Promise<void>;
  associateTotp: () => Promise<string>;
  verifyTotp: (totpCode: string, friendlyDeviceName: string) => Promise<void>;
  authenticate: (
    email: string,
    pass: string,
    opts?: AuthenticateOptions,
  ) => Promise<AuthenticateResult>;
  resetPassword: (email: string) => Promise<void>;
  confirmResetPassword: (
    email: string,
    code: string,
    newPassword: string,
  ) => Promise<void>;
};

export type AuthState<User> =
  | AuthStateUnknown
  | AuthStateAnon
  | AuthStateLoggedIn<User>;
