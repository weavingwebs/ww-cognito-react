import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  confirmSignIn: vi.fn(),
}));

import { confirmSignIn } from 'aws-amplify/auth';
import { createMapSignInResult } from './mapSignInResult';

const custom = (info: Record<string, string> = {}) =>
  ({
    isSignedIn: false,
    nextStep: {
      signInStep: 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE',
      additionalInfo: info,
    },
  }) as never;

beforeEach(() => vi.clearAllMocks());

describe('clientMetadata', () => {
  const meta = { mfaAction: 'setup' };

  it('chained VERIFY then SETUP custom challenges reach SUCCESS with the metadata resent each time', async () => {
    const map = createMapSignInResult(vi.fn().mockResolvedValue(undefined));
    const first = await map(custom({ mfaChallenge: 'VERIFY' }), meta);
    if (first.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    expect(first.challengeParameters).toEqual({ mfaChallenge: 'VERIFY' });

    vi.mocked(confirmSignIn)
      .mockResolvedValueOnce(custom({ mfaChallenge: 'SETUP' }))
      .mockResolvedValueOnce({ isSignedIn: true } as never);
    const second = await first.sendCustomChallengeAnswer('{"type":"totp"}');
    if (second.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    expect(second.challengeParameters).toEqual({ mfaChallenge: 'SETUP' });
    const done = await second.sendCustomChallengeAnswer('{"type":"webauthn"}');

    expect(done).toEqual({ result: 'SUCCESS' });
    expect(confirmSignIn).toHaveBeenNthCalledWith(1, {
      challengeResponse: '{"type":"totp"}',
      options: { clientMetadata: meta },
    });
    expect(confirmSignIn).toHaveBeenNthCalledWith(2, {
      challengeResponse: '{"type":"webauthn"}',
      options: { clientMetadata: meta },
    });
  });

  it('an explicit argument overrides the default and carries on through the exchange', async () => {
    const map = createMapSignInResult(vi.fn());
    const first = await map(custom(), meta);
    if (first.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    vi.mocked(confirmSignIn)
      .mockResolvedValueOnce(custom())
      .mockResolvedValueOnce({ isSignedIn: true } as never);
    const override = { mfaAction: 'other' };
    const second = await first.sendCustomChallengeAnswer('a', override);
    if (second.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    await second.sendCustomChallengeAnswer('b');
    expect(vi.mocked(confirmSignIn).mock.calls[0][0]).toEqual({
      challengeResponse: 'a',
      options: { clientMetadata: override },
    });
    expect(vi.mocked(confirmSignIn).mock.calls[1][0]).toEqual({
      challengeResponse: 'b',
      options: { clientMetadata: override },
    });
  });

  it('is resent on the new-password step, with an optional override', async () => {
    const map = createMapSignInResult(vi.fn());
    const r = await map(
      {
        isSignedIn: false,
        nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED' },
      } as never,
      meta,
    );
    if (r.result !== 'NEW_PASSWORD_REQUIRED') throw new Error('unreachable');
    vi.mocked(confirmSignIn).mockResolvedValue({ isSignedIn: true } as never);
    await r.completeNewPasswordChallenge('pw', { given_name: 'T' });
    await r.completeNewPasswordChallenge('pw', {}, { x: 'y' });
    expect(vi.mocked(confirmSignIn).mock.calls[0][0]).toEqual({
      challengeResponse: 'pw',
      options: { userAttributes: { given_name: 'T' }, clientMetadata: meta },
    });
    expect(vi.mocked(confirmSignIn).mock.calls[1][0]).toEqual({
      challengeResponse: 'pw',
      options: { userAttributes: {}, clientMetadata: { x: 'y' } },
    });
  });

  it('is resent on the TOTP and MFA-setup steps; absent metadata adds no key', async () => {
    const map = createMapSignInResult(vi.fn());
    const totp = await map(
      { isSignedIn: false, nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_TOTP_CODE' } } as never,
      meta,
    );
    if (totp.result !== 'TOTP_REQUIRED') throw new Error('unreachable');
    vi.mocked(confirmSignIn).mockResolvedValue({ isSignedIn: true } as never);
    await totp.respondToTotpChallenge('123456');
    expect(vi.mocked(confirmSignIn).mock.calls[0][0]).toEqual({
      challengeResponse: '123456',
      options: { clientMetadata: meta },
    });

    const setup = await map(
      {
        isSignedIn: false,
        nextStep: {
          signInStep: 'CONTINUE_SIGN_IN_WITH_TOTP_SETUP',
          totpSetupDetails: { sharedSecret: 's' },
        },
      } as never,
      undefined,
    );
    if (setup.result !== 'MFA_SETUP') throw new Error('unreachable');
    await setup.completeMfaSetupChallenge('123456', 'phone');
    expect(vi.mocked(confirmSignIn).mock.calls[1][0]).toEqual({
      challengeResponse: '123456',
      options: { friendlyDeviceName: 'phone' },
    });
  });
});
