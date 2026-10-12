import { confirmSignIn, signIn } from 'aws-amplify/auth';
import { assertReauthLive, type ReauthGuard } from './reauthGuard';
import type { AuthenticateResult } from './types';

type SignInOutput = Awaited<ReturnType<typeof signIn>>;
type ClientMetadata = Record<string, string>;

// A mistyped code / weak new password leaves the Cognito session valid, so
// (as without a guard) the user can retry the same step instead of restarting
// from the password. Anything else, including a failed custom challenge
// (terminal after 3 wrong answers server-side), ends the attempt. Prefix match.
const RETRYABLE_STEP_ERRORS = [
  'CodeMismatchException',
  'InvalidPasswordException',
  'EnableSoftwareTokenMFAException',
];

function isRetryableStepError(err: unknown): boolean {
  const name = (err as { name?: unknown } | null | undefined)?.name;
  return (
    typeof name === 'string' &&
    RETRYABLE_STEP_ERRORS.some((n) => name.indexOf(n) === 0)
  );
}

// Extracted as a factory (rather than a free function) so it's unit-testable
// without a React tree - loadUserFromSession is the one piece of state it
// needs from the provider.
//
// `guard` is the re-auth guard (allowWhileLoggedIn) when there is one: it is
// committed when sign-in completes and rolled back on any failure (bar the
// retryable step errors) or dead-end step, and challenge callbacks refuse to
// run once it has been rolled back.
// `clientMetadata` is the exchange's metadata: Cognito does not carry it
// between calls, so it is resent on every confirmSignIn. A per-call override
// (new password / custom answer) replaces it for that call and the rest of
// the exchange.
export function createMapSignInResult(loadUserFromSession: () => Promise<unknown>) {
  const mapSignInResult = async (
    output: SignInOutput,
    guard: ReauthGuard | null = null,
    clientMetadata?: ClientMetadata,
  ): Promise<AuthenticateResult> => {
    // Runs one confirmSignIn and maps the next step. A failed confirmSignIn
    // ends the whole attempt (rolls the guard back) before rethrowing, except
    // for the retryable errors below, where Cognito keeps the session and the
    // same callback can be called again.
    const continueExchange = async (
      confirm: (metadata: ClientMetadata | undefined) => ReturnType<typeof confirmSignIn>,
      metadata: ClientMetadata | undefined,
    ): Promise<AuthenticateResult> => {
      assertReauthLive(guard);
      let next: SignInOutput;
      try {
        // Tracked so a rollback landing mid-call cannot let the late response
        // write into the real storage (see reauthGuard.ts).
        next = guard
          ? await guard.track(() => confirm(metadata))
          : await confirm(metadata);
      } catch (err) {
        if (!isRetryableStepError(err)) await guard?.rollback();
        throw err;
      }
      try {
        return await mapSignInResult(next, guard, metadata);
      } catch (err) {
        await guard?.rollback();
        throw err;
      }
    };

    if (output.isSignedIn) {
      // Commit strictly before loading the user: the load reads the real
      // storage.
      await guard?.commit();
      await loadUserFromSession();
      return { result: 'SUCCESS' };
    }

    const { signInStep } = output.nextStep;

    switch (signInStep) {
      case 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED':
        return {
          result: 'NEW_PASSWORD_REQUIRED',
          completeNewPasswordChallenge: async (
            newPassword,
            attributes = {},
            override,
          ) =>
            continueExchange(
              (metadata) =>
                confirmSignIn({
                  challengeResponse: newPassword,
                  options: {
                    userAttributes: attributes,
                    ...(metadata ? { clientMetadata: metadata } : {}),
                  },
                }),
              override ?? clientMetadata,
            ),
        };

      case 'CONFIRM_SIGN_IN_WITH_TOTP_CODE':
        return {
          result: 'TOTP_REQUIRED',
          respondToTotpChallenge: async (totpCode) =>
            continueExchange(
              (metadata) =>
                confirmSignIn({
                  challengeResponse: totpCode,
                  options: metadata ? { clientMetadata: metadata } : undefined,
                }),
              clientMetadata,
            ),
        };

      case 'CONTINUE_SIGN_IN_WITH_TOTP_SETUP': {
        const secret = output.nextStep.totpSetupDetails.sharedSecret;
        return {
          result: 'MFA_SETUP',
          beginMfaSetupChallenge: async () => ({ secret }),
          completeMfaSetupChallenge: async (totpCode, friendlyDeviceName) =>
            continueExchange(
              (metadata) =>
                confirmSignIn({
                  challengeResponse: totpCode,
                  options: {
                    friendlyDeviceName,
                    ...(metadata ? { clientMetadata: metadata } : {}),
                  },
                }),
              clientMetadata,
            ),
        };
      }

      case 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE':
        return {
          result: 'CUSTOM_CHALLENGE',
          challengeParameters: output.nextStep.additionalInfo ?? {},
          sendCustomChallengeAnswer: async (answerChallenge, override) =>
            continueExchange(
              (metadata) =>
                confirmSignIn({
                  challengeResponse: answerChallenge,
                  options: metadata ? { clientMetadata: metadata } : undefined,
                }),
              override ?? clientMetadata,
            ),
        };

      // Amplify resolves these into a signInStep instead of throwing (unlike
      // amazon-cognito-identity-js) - re-throw as a catchable error carrying
      // the original exception name so existing err.name checks keep
      // working. See MIGRATION.md. These are dead ends, so the guard (if any)
      // is rolled back first.
      case 'RESET_PASSWORD': {
        await guard?.rollback();
        const err = new Error('Password reset required');
        err.name = 'PasswordResetRequiredException';
        throw err;
      }

      case 'CONFIRM_SIGN_UP': {
        await guard?.rollback();
        const err = new Error('User is not confirmed');
        err.name = 'UserNotConfirmedException';
        throw err;
      }

      default:
        await guard?.rollback();
        throw new Error(`Unhandled signInStep: ${signInStep}`);
    }
  };

  return mapSignInResult;
}
