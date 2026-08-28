import { describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  confirmSignIn: vi.fn(),
}));

import { confirmSignIn } from 'aws-amplify/auth';
import { createMapSignInResult } from './mapSignInResult';

describe('createMapSignInResult', () => {
  it('SUCCESS: loads the user and returns SUCCESS', async () => {
    const loadUserFromSession = vi.fn().mockResolvedValue(undefined);
    const mapSignInResult = createMapSignInResult(loadUserFromSession);

    const result = await mapSignInResult({ isSignedIn: true } as never);

    expect(loadUserFromSession).toHaveBeenCalledOnce();
    expect(result).toEqual({ result: 'SUCCESS' });
  });

  it('NEW_PASSWORD_REQUIRED: completeNewPasswordChallenge continues the chain via confirmSignIn', async () => {
    const mapSignInResult = createMapSignInResult(vi.fn());

    const result = await mapSignInResult({
      isSignedIn: false,
      nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED' },
    } as never);
    if (result.result !== 'NEW_PASSWORD_REQUIRED') throw new Error('unreachable');

    vi.mocked(confirmSignIn).mockResolvedValueOnce({ isSignedIn: true } as never);
    const next = await result.completeNewPasswordChallenge('newPass123', {
      given_name: 'Test',
    });

    expect(confirmSignIn).toHaveBeenCalledWith({
      challengeResponse: 'newPass123',
      options: { userAttributes: { given_name: 'Test' } },
    });
    expect(next).toEqual({ result: 'SUCCESS' });
  });

  it('TOTP_REQUIRED: respondToTotpChallenge continues the chain via confirmSignIn', async () => {
    const mapSignInResult = createMapSignInResult(vi.fn());

    const result = await mapSignInResult({
      isSignedIn: false,
      nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_TOTP_CODE' },
    } as never);
    if (result.result !== 'TOTP_REQUIRED') throw new Error('unreachable');

    vi.mocked(confirmSignIn).mockResolvedValueOnce({ isSignedIn: true } as never);
    const next = await result.respondToTotpChallenge('123456');

    expect(confirmSignIn).toHaveBeenCalledWith({ challengeResponse: '123456' });
    expect(next).toEqual({ result: 'SUCCESS' });
  });

  it('CONTINUE_SIGN_IN_WITH_TOTP_SETUP: returns MFA_SETUP with the shared secret', async () => {
    const mapSignInResult = createMapSignInResult(vi.fn());

    const result = await mapSignInResult({
      isSignedIn: false,
      nextStep: {
        signInStep: 'CONTINUE_SIGN_IN_WITH_TOTP_SETUP',
        totpSetupDetails: { sharedSecret: 'SECRET123' },
      },
    } as never);
    if (result.result !== 'MFA_SETUP') throw new Error('unreachable');

    await expect(result.beginMfaSetupChallenge()).resolves.toEqual({
      secret: 'SECRET123',
    });

    vi.mocked(confirmSignIn).mockResolvedValueOnce({ isSignedIn: true } as never);
    const next = await result.completeMfaSetupChallenge('123456', 'My Phone');

    expect(confirmSignIn).toHaveBeenCalledWith({
      challengeResponse: '123456',
      options: { friendlyDeviceName: 'My Phone' },
    });
    expect(next).toEqual({ result: 'SUCCESS' });
  });

  it('CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE: returns CUSTOM_CHALLENGE with challengeParameters', async () => {
    const mapSignInResult = createMapSignInResult(vi.fn());

    const result = await mapSignInResult({
      isSignedIn: false,
      nextStep: {
        signInStep: 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE',
        additionalInfo: { foo: 'bar' },
      },
    } as never);
    if (result.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');

    expect(result.challengeParameters).toEqual({ foo: 'bar' });

    vi.mocked(confirmSignIn).mockResolvedValueOnce({ isSignedIn: true } as never);
    const next = await result.sendCustomChallengeAnswer('answer', { meta: '1' });

    expect(confirmSignIn).toHaveBeenCalledWith({
      challengeResponse: 'answer',
      options: { clientMetadata: { meta: '1' } },
    });
    expect(next).toEqual({ result: 'SUCCESS' });
  });

  it('RESET_PASSWORD: rethrows as a catchable PasswordResetRequiredException', async () => {
    const mapSignInResult = createMapSignInResult(vi.fn());

    await expect(
      mapSignInResult({
        isSignedIn: false,
        nextStep: { signInStep: 'RESET_PASSWORD' },
      } as never),
    ).rejects.toMatchObject({ name: 'PasswordResetRequiredException' });
  });

  it('CONFIRM_SIGN_UP: rethrows as a catchable UserNotConfirmedException', async () => {
    const mapSignInResult = createMapSignInResult(vi.fn());

    await expect(
      mapSignInResult({
        isSignedIn: false,
        nextStep: { signInStep: 'CONFIRM_SIGN_UP' },
      } as never),
    ).rejects.toMatchObject({ name: 'UserNotConfirmedException' });
  });

  it('throws for a genuinely unhandled signInStep', async () => {
    const mapSignInResult = createMapSignInResult(vi.fn());

    await expect(
      mapSignInResult({
        isSignedIn: false,
        nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_SMS_CODE' },
      } as never),
    ).rejects.toThrow('Unhandled signInStep: CONFIRM_SIGN_IN_WITH_SMS_CODE');
  });
});
