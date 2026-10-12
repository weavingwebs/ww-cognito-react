export type {
  AuthenticateOptions,
  AuthState,
  AuthenticateResult,
  BuildUserFn,
  CompleteMfaSetupChallengeFn,
  CompleteNewPasswordChallengeFn,
  RespondToTotpChallengeFn,
  SendCustomChallengeAnswerFn,
  UserPoolConfig,
} from './types';
export { createCognitoAuth, forceSignOut } from './authContext';
export { buildTotpUri } from './totp';
export { fetchMfaPreference, setTotpPreference } from './mfaPreference';
export type { OnExistingSession } from './sessionGuards';
export {
  ALREADY_SIGNED_IN_EXCEPTION,
  isAlreadySignedInError,
} from './sessionGuards';
export {
  REAUTH_ABORTED_EXCEPTION,
  REAUTH_NOT_FRESH_EXCEPTION,
  REAUTH_NOT_LOGGED_IN_EXCEPTION,
  isReauthAbortedError,
  isReauthNotFreshError,
  isReauthNotLoggedInError,
} from './reauth';
