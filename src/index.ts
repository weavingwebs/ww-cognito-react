export type {
  AuthenticateOptions,
  AuthProviderOptions,
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
export type { ConfirmReplace, OnExistingSession } from './sessionGuards';
export {
  ALREADY_SIGNED_IN_EXCEPTION,
  REPLACE_CANCELLED_EXCEPTION,
  isAlreadySignedInError,
  isReplaceCancelledError,
} from './sessionGuards';
export {
  REAUTH_ABORTED_EXCEPTION,
  REAUTH_NOT_FRESH_EXCEPTION,
  REAUTH_NOT_LOGGED_IN_EXCEPTION,
  AMPLIFY_INTERNALS_CHANGED_EXCEPTION,
  isAmplifyInternalsChangedError,
  isReauthAbortedError,
  isReauthNotFreshError,
  isReauthNotLoggedInError,
} from './reauth';
export type { OnUserChange, UserChange } from './userChange';
export { USER_CHANGED_EXCEPTION, isUserChangedError } from './userChange';
