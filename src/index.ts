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
  REAUTH_ATTEMPT_ENDED_EXCEPTION,
  REAUTH_USER_MISMATCH_EXCEPTION,
  clearPersistedSignInState,
  isReauthAttemptEndedError,
  isReauthUserMismatchError,
  rollbackPendingReauth,
} from './reauthGuard';
