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
  clientMetadata?: Record<string, string>,
) => Promise<AuthenticateResult>;

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
  authenticate: (email: string, pass: string) => Promise<AuthenticateResult>;
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
  logout: () => Promise<void>;
  changePassword: (oldPwd: string, newPwd: string) => Promise<void>;
  updateEmail: (
    email: string,
  ) => Promise<{ verifyEmail: (code: string) => Promise<void> }>;
  associateTotp: () => Promise<string>;
  verifyTotp: (totpCode: string, friendlyDeviceName: string) => Promise<void>;
  authenticate: (email: string, pass: string) => Promise<AuthenticateResult>;
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
