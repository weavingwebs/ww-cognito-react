import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  confirmSignIn: vi.fn(),
}));

import { confirmSignIn } from 'aws-amplify/auth';
import { createMapSignInResult } from './mapSignInResult';
import { createSupersessionGuard } from './reauth';

const totp = () =>
  ({
    isSignedIn: false,
    nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_TOTP_CODE' },
  }) as never;
const custom = () =>
  ({
    isSignedIn: false,
    nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE', additionalInfo: {} },
  }) as never;
const done = { isSignedIn: true } as never;

const guard = () => ({
  beforeStep: vi.fn().mockResolvedValue(undefined),
  beforeSuccess: vi.fn().mockResolvedValue(undefined),
});

beforeEach(() => vi.clearAllMocks());

describe('re-auth guard', () => {
  it('is checked before each confirmSignIn, and still on the second step of a chain', async () => {
    const load = vi.fn().mockResolvedValue(undefined);
    const g = guard();
    const order: string[] = [];
    g.beforeStep.mockImplementation(async () => void order.push('step'));
    vi.mocked(confirmSignIn).mockImplementation((async () => {
      order.push('confirm');
      return order.filter((o) => o === 'confirm').length === 1 ? custom() : done;
    }) as never);

    const first = await createMapSignInResult(load)(totp(), undefined, g);
    if (first.result !== 'TOTP_REQUIRED') throw new Error('unreachable');
    const second = await first.respondToTotpChallenge('123456');
    if (second.result !== 'CUSTOM_CHALLENGE') throw new Error('unreachable');
    await second.sendCustomChallengeAnswer('a');

    expect(order).toEqual(['step', 'confirm', 'step', 'confirm']);
    expect(g.beforeSuccess).toHaveBeenCalledOnce();
  });

  it('a refused step never reaches confirmSignIn', async () => {
    const g = guard();
    const boom = new Error('aborted');
    g.beforeStep.mockRejectedValue(boom);
    const first = await createMapSignInResult(vi.fn())(totp(), undefined, g);
    if (first.result !== 'TOTP_REQUIRED') throw new Error('unreachable');
    await expect(first.respondToTotpChallenge('1')).rejects.toBe(boom);
    expect(confirmSignIn).not.toHaveBeenCalled();
  });

  it('beforeSuccess runs before the user is loaded, and a refusal prevents the load', async () => {
    const load = vi.fn().mockResolvedValue(undefined);
    const g = guard();
    await createMapSignInResult(load)(done, undefined, g);
    expect(g.beforeSuccess.mock.invocationCallOrder[0]).toBeLessThan(
      load.mock.invocationCallOrder[0],
    );

    const boom = new Error('not fresh');
    const refusing = guard();
    refusing.beforeSuccess.mockRejectedValue(boom);
    load.mockClear();
    await expect(createMapSignInResult(load)(done, undefined, refusing)).rejects.toBe(boom);
    expect(load).not.toHaveBeenCalled();
  });

  it('without a guard behaves as before', async () => {
    const load = vi.fn().mockResolvedValue(undefined);
    await expect(createMapSignInResult(load)(done)).resolves.toEqual({ result: 'SUCCESS' });
  });
});

describe('plain sign-in supersession', () => {
  it('a superseded attempt that Amplify completed still loads the user (tokens are already stored)', async () => {
    const load = vi.fn().mockResolvedValue(undefined);
    const map = createMapSignInResult(load);
    const first = createSupersessionGuard();
    createSupersessionGuard(); // a double-submit starts a newer attempt
    await expect(map(done, undefined, first)).resolves.toEqual({ result: 'SUCCESS' });
    expect(load).toHaveBeenCalledOnce();
  });
});
