import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  confirmSignIn: vi.fn(),
}));

import { confirmSignIn } from 'aws-amplify/auth';
import { createMapSignInResult } from './mapSignInResult';
import type { ReauthGuard } from './reauthGuard';

const custom = (info: Record<string, string> = {}) =>
  ({
    isSignedIn: false,
    nextStep: {
      signInStep: 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE',
      additionalInfo: info,
    },
  }) as never;

const makeGuard = () => {
  let settled = false;
  const guard: ReauthGuard & { calls: string[] } = {
    calls: [],
    get settled() {
      return settled;
    },
    track: async (fn) => {
      if (settled) {
        throw Object.assign(new Error('ended'), { name: 'ReauthAttemptEndedException' });
      }
      return fn();
    },
    commit: vi.fn(async () => {
      guard.calls.push('commit');
      settled = true;
    }),
    rollback: vi.fn(async () => {
      guard.calls.push('rollback');
      settled = true;
    }),
  };
  return guard;
};

beforeEach(() => vi.clearAllMocks());

describe('clientMetadata', () => {
  const meta = { mfaAction: 'setup' };

  it('chained VERIFY then SETUP custom challenges reach SUCCESS with the metadata resent each time', async () => {
    const map = createMapSignInResult(vi.fn().mockResolvedValue(undefined));
    const first = await map(custom({ mfaChallenge: 'VERIFY' }), null, meta);
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
    const first = await map(custom(), null, meta);
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
      null,
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
      null,
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
      null,
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

describe('guard threading', () => {
  it('commits strictly before loading the user', async () => {
    const guard = makeGuard();
    const load = vi.fn(async () => {
      guard.calls.push('load');
    });
    const map = createMapSignInResult(load);
    await map({ isSignedIn: true } as never, guard);
    expect(guard.calls).toEqual(['commit', 'load']);
  });

  it('a mismatch thrown by commit propagates and loads nothing', async () => {
    const guard = makeGuard();
    guard.commit = vi.fn().mockRejectedValue(new Error('mismatch'));
    const load = vi.fn();
    await expect(
      createMapSignInResult(load)({ isSignedIn: true } as never, guard),
    ).rejects.toThrow('mismatch');
    expect(load).not.toHaveBeenCalled();
  });

  it('guard + VERIFY then SETUP: metadata resent each round, exactly one commit', async () => {
    const guard = makeGuard();
    const meta = { mfaAction: 'setup' };
    const map = createMapSignInResult(vi.fn());
    const first = await map(custom({ mfaChallenge: 'VERIFY' }), guard, meta);
    if (first.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    vi.mocked(confirmSignIn)
      .mockResolvedValueOnce(custom({ mfaChallenge: 'SETUP' }))
      .mockResolvedValueOnce({ isSignedIn: true } as never);
    const second = await first.sendCustomChallengeAnswer('a');
    if (second.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    expect(await second.sendCustomChallengeAnswer('b')).toEqual({ result: 'SUCCESS' });
    expect(guard.calls).toEqual(['commit']);
    expect(vi.mocked(confirmSignIn).mock.calls.map((c) => c[0].options)).toEqual([
      { clientMetadata: meta },
      { clientMetadata: meta },
    ]);
  });

  it('a challenge chain commits once on success', async () => {
    const guard = makeGuard();
    const map = createMapSignInResult(vi.fn());
    const first = await map(custom(), guard);
    if (first.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    vi.mocked(confirmSignIn).mockResolvedValueOnce({ isSignedIn: true } as never);
    await first.sendCustomChallengeAnswer('a');
    expect(guard.calls).toEqual(['commit']);
  });

  it.each([
    ['sendCustomChallengeAnswer', custom(), (r: any) => r.sendCustomChallengeAnswer('a')],
    [
      'respondToTotpChallenge',
      { isSignedIn: false, nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_TOTP_CODE' } } as never,
      (r: any) => r.respondToTotpChallenge('1'),
    ],
    [
      'completeNewPasswordChallenge',
      { isSignedIn: false, nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED' } } as never,
      (r: any) => r.completeNewPasswordChallenge('p'),
    ],
    [
      'completeMfaSetupChallenge',
      {
        isSignedIn: false,
        nextStep: {
          signInStep: 'CONTINUE_SIGN_IN_WITH_TOTP_SETUP',
          totpSetupDetails: { sharedSecret: 's' },
        },
      } as never,
      (r: any) => r.completeMfaSetupChallenge('1', 'd'),
    ],
  ])('%s: a failed confirmSignIn rolls the guard back and rethrows', async (_n, output, call) => {
    const guard = makeGuard();
    const first = await createMapSignInResult(vi.fn())(output, guard);
    const boom = Object.assign(new Error('bad'), { name: 'NotAuthorizedException' });
    vi.mocked(confirmSignIn).mockRejectedValueOnce(boom);
    await expect(call(first)).rejects.toBe(boom);
    expect(guard.calls).toEqual(['rollback']);
  });

  it('callbacks refuse to run (and never reach Cognito) once the guard is rolled back', async () => {
    const guard = makeGuard();
    const first = await createMapSignInResult(vi.fn())(custom(), guard);
    if (first.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    await guard.rollback();
    await expect(first.sendCustomChallengeAnswer('a')).rejects.toMatchObject({
      name: 'ReauthAttemptEndedException',
    });
    expect(confirmSignIn).not.toHaveBeenCalled();
  });

  it.each([
    ['RESET_PASSWORD', 'PasswordResetRequiredException'],
    ['CONFIRM_SIGN_UP', 'UserNotConfirmedException'],
    ['DONE_WEIRD', 'Error'],
  ])('dead-end step %s rolls the guard back before throwing', async (step, name) => {
    const guard = makeGuard();
    const err = await createMapSignInResult(vi.fn())(
      { isSignedIn: false, nextStep: { signInStep: step } } as never,
      guard,
    ).catch((e) => e);
    expect(err.name).toBe(name);
    expect(guard.calls).toEqual(['rollback']);
  });

  it.each([
    [
      'respondToTotpChallenge',
      'CodeMismatchException',
      { isSignedIn: false, nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_TOTP_CODE' } } as never,
      (r: any, code: string) => r.respondToTotpChallenge(code),
    ],
    [
      'completeMfaSetupChallenge',
      'EnableSoftwareTokenMFAException',
      {
        isSignedIn: false,
        nextStep: {
          signInStep: 'CONTINUE_SIGN_IN_WITH_TOTP_SETUP',
          totpSetupDetails: { sharedSecret: 's' },
        },
      } as never,
      (r: any, code: string) => r.completeMfaSetupChallenge(code, 'phone'),
    ],
    [
      'completeNewPasswordChallenge',
      'InvalidPasswordException',
      { isSignedIn: false, nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED' } } as never,
      (r: any, code: string) => r.completeNewPasswordChallenge(code),
    ],
  ])('%s: a retryable %s keeps the guard live so the same step can be retried, then commits once', async (_n, errName, output, call) => {
    const guard = makeGuard();
    const first = await createMapSignInResult(vi.fn())(output, guard);
    const typo = Object.assign(new Error('mismatch'), { name: errName });
    vi.mocked(confirmSignIn)
      .mockRejectedValueOnce(typo)
      .mockResolvedValueOnce({ isSignedIn: true } as never);
    await expect(call(first, 'wrong')).rejects.toBe(typo);
    expect(guard.settled).toBe(false);
    expect(guard.calls).toEqual([]);
    expect(await call(first, 'right')).toEqual({ result: 'SUCCESS' });
    expect(guard.calls).toEqual(['commit']);
  });

  it('a retryable-named error from mapping the NEXT step still rolls back', async () => {
    const guard = makeGuard();
    const first = await createMapSignInResult(vi.fn())(custom(), guard);
    if (first.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    guard.commit = vi.fn().mockRejectedValue(
      Object.assign(new Error('x'), { name: 'CodeMismatchException' }),
    );
    vi.mocked(confirmSignIn).mockResolvedValueOnce({ isSignedIn: true } as never);
    await expect(first.sendCustomChallengeAnswer('a')).rejects.toBeTruthy();
    expect(guard.calls).toEqual(['rollback']);
  });

  it('a failed custom challenge is terminal even if it throws a retryable-looking name', async () => {
    const guard = makeGuard();
    const first = await createMapSignInResult(vi.fn())(custom(), guard);
    if (first.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    vi.mocked(confirmSignIn).mockRejectedValueOnce(
      Object.assign(new Error('x'), { name: 'NotAuthorizedException' }),
    );
    await expect(first.sendCustomChallengeAnswer('a')).rejects.toBeTruthy();
    expect(guard.calls).toEqual(['rollback']);
  });
});
