import type { OnExistingSession } from './sessionGuards';
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

export type AuthStateUnknown = { isLoggedIn: null };

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
