import { confirmSignIn, signIn } from 'aws-amplify/auth';
import type { AuthenticateResult } from './types';

type SignInOutput = Awaited<ReturnType<typeof signIn>>;

// Extracted as a factory (rather than a free function) so it's unit-testable
// without a React tree - loadUserFromSession is the one piece of state it
// needs from the provider.
export function createMapSignInResult(loadUserFromSession: () => Promise<unknown>) {
  const mapSignInResult = async (
    output: SignInOutput,
  ): Promise<AuthenticateResult> => {
    if (output.isSignedIn) {
      await loadUserFromSession();
      return { result: 'SUCCESS' };
    }

    const { signInStep } = output.nextStep;

    switch (signInStep) {
      case 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED':
        return {
          result: 'NEW_PASSWORD_REQUIRED',
          completeNewPasswordChallenge: async (newPassword, attributes = {}) =>
            mapSignInResult(
              await confirmSignIn({
                challengeResponse: newPassword,
                options: { userAttributes: attributes },
              }),
            ),
        };

      case 'CONFIRM_SIGN_IN_WITH_TOTP_CODE':
        return {
          result: 'TOTP_REQUIRED',
          respondToTotpChallenge: async (totpCode) =>
            mapSignInResult(await confirmSignIn({ challengeResponse: totpCode })),
        };

      case 'CONTINUE_SIGN_IN_WITH_TOTP_SETUP': {
        const secret = output.nextStep.totpSetupDetails.sharedSecret;
        return {
          result: 'MFA_SETUP',
          beginMfaSetupChallenge: async () => ({ secret }),
          completeMfaSetupChallenge: async (totpCode, friendlyDeviceName) =>
            mapSignInResult(
              await confirmSignIn({
                challengeResponse: totpCode,
                options: { friendlyDeviceName },
              }),
            ),
        };
      }

      case 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE':
        return {
          result: 'CUSTOM_CHALLENGE',
          challengeParameters: output.nextStep.additionalInfo ?? {},
          sendCustomChallengeAnswer: async (answerChallenge, clientMetadata) =>
            mapSignInResult(
              await confirmSignIn({
                challengeResponse: answerChallenge,
                options: clientMetadata ? { clientMetadata } : undefined,
              }),
            ),
        };

      // Amplify resolves these into a signInStep instead of throwing (unlike
      // amazon-cognito-identity-js) - re-throw as a catchable error carrying
      // the original exception name so existing err.name checks keep
      // working. See MIGRATION.md.
      case 'RESET_PASSWORD': {
        const err = new Error('Password reset required');
        err.name = 'PasswordResetRequiredException';
        throw err;
      }

      case 'CONFIRM_SIGN_UP': {
        const err = new Error('User is not confirmed');
        err.name = 'UserNotConfirmedException';
        throw err;
      }

      default:
        throw new Error(`Unhandled signInStep: ${signInStep}`);
    }
  };

  return mapSignInResult;
}
