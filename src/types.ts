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
  /** What to do if a session already exists. Ignored when `allowWhileLoggedIn` is set. */
  onExistingSession?: OnExistingSession;
  /**
   * Sent with the sign-in and re-sent on every step of the exchange (Cognito
   * does not carry it between calls), e.g. `{ mfaAction: 'setup' }`.
   */
  clientMetadata?: Record<string, string>;
  /**
   * Re-authenticate while signed in without touching the live session unless
   * the attempt succeeds (see README, "Re-authentication"). Bypasses
   * `onExistingSession`. Must be the signed-in user; see
   * `isReauthUserMismatchError`. With no session it behaves like a plain
   * login.
   */
  allowWhileLoggedIn?: boolean;
  /** Aborting (e.g. on unmount) ends a pending `allowWhileLoggedIn` attempt. */
  signal?: AbortSignal;
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
   * enrolment. The refreshed ID token keeps its original `auth_time` (measured against a Cognito pool: `iat`/`exp` move, `auth_time` does not), so this is not a re-authentication. Throws
   * during an `allowWhileLoggedIn` attempt.
   */
  refreshSession: () => Promise<void>;
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
