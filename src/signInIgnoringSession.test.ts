// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({
  getTokens: undefined as undefined | ((o?: unknown) => Promise<unknown>),
}));
vi.mock('aws-amplify', () => ({
  Amplify: { getConfig: () => ({}) },
  createAmplifyContext: (_cfg: unknown, opts: { Auth: { tokenProvider: { getTokens: typeof h.getTokens } } }) => {
    h.getTokens = opts.Auth.tokenProvider.getTokens;
    return {};
  },
}));
vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  fetchAuthSession: vi.fn(),
  getCurrentUser: vi.fn(),
}));
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: { getTokens: vi.fn().mockResolvedValue('real') },
}));

import { signIn } from 'aws-amplify/auth';
import {
  isAmplifyInternalsChangedError,
  signInIgnoringSession,
} from './reauth';

const input = { username: 'u', password: 'p' };
const interruption = () =>
  Object.assign(new Error('x'), { name: 'UnexpectedSignInInterruptionException' });

// Fakes Amplify's reads through the context, then fails as Amplify does.
const readsThenFail = (reads: number, err: Error) =>
  vi.mocked(signIn).mockImplementation((async () => {
    for (let i = 0; i < reads; i++) await h.getTokens!();
    throw err;
  }) as never);

describe('signInIgnoringSession', () => {
  it('the hidden null was the only read (consumed by the late read): names an Amplify internals change', async () => {
    const cause = interruption();
    readsThenFail(1, cause);
    const err = await signInIgnoringSession(input).catch((e) => e);
    expect(isAmplifyInternalsChangedError(err)).toBe(true);
    expect(err.cause).toBe(cause);
  });

  it('a later read happened (the order is as expected): rethrows the original error', async () => {
    const cause = interruption();
    readsThenFail(2, cause);
    await expect(signInIgnoringSession(input)).rejects.toBe(cause);
  });

  it('passes any other error through untouched', async () => {
    const other = Object.assign(new Error('bad'), { name: 'NotAuthorizedException' });
    readsThenFail(1, other);
    await expect(signInIgnoringSession(input)).rejects.toBe(other);
  });
});
