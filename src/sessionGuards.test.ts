import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  fetchAuthSession: vi.fn(),
  signIn: vi.fn(),
}));
const clearTokens = vi.hoisted(() => vi.fn());
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: { tokenOrchestrator: { clearTokens } },
}));

import { fetchAuthSession } from 'aws-amplify/auth';
import {
  checkSessionOnMount,
  isAlreadySignedInError,
  isRefreshTokenRejected,
  signInHandlingExistingSession,
} from './sessionGuards';

const existing = () =>
  Object.assign(new Error('x'), { name: 'UserAlreadyAuthenticatedException' });

const doSignInIgnoringSession = vi.fn();
const onReplaced = vi.fn();
const run = (
  doSignIn: unknown,
  onExistingSession?: 'replace' | 'reject',
  adoptSession?: () => Promise<unknown>,
) =>
  signInHandlingExistingSession({
    login: 'a@b.c',
    doSignIn: doSignIn as never,
    doSignInIgnoringSession: doSignInIgnoringSession as never,
    onExistingSession,
    adoptSession,
    onReplaced,
  });
beforeEach(() => vi.clearAllMocks());

describe('signInHandlingExistingSession', () => {
  it("default 'replace': signs in again ignoring the session, no sign-out, no token clearing", async () => {
    const doSignIn = vi.fn().mockRejectedValue(existing());
    doSignInIgnoringSession.mockResolvedValue({ isSignedIn: true });
    await run(doSignIn);
    expect(doSignIn).toHaveBeenCalledOnce();
    expect(doSignInIgnoringSession).toHaveBeenCalledOnce();
    expect(clearTokens).not.toHaveBeenCalled();
  });

  it("'replace': a wrong password leaves the existing session alone (nothing is cleared or revoked)", async () => {
    const bad = Object.assign(new Error('pw'), { name: 'NotAuthorizedException' });
    doSignInIgnoringSession.mockRejectedValue(bad);
    await expect(run(vi.fn().mockRejectedValue(existing()))).rejects.toBe(bad);
    expect(clearTokens).not.toHaveBeenCalled();
    expect(onReplaced).not.toHaveBeenCalled();
  });

  it("'reject' with a valid session adopts it and throws AlreadySignedInException, no signOut", async () => {
    vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: {} } as never);
    const adopt = vi.fn().mockResolvedValue(undefined);
    const doSignIn = vi.fn().mockRejectedValue(existing());
    const err = await run(doSignIn, 'reject', adopt).catch((e) => e);
    expect(isAlreadySignedInError(err)).toBe(true);
    expect(err.name).toBe('AlreadySignedInException');
    expect(adopt).toHaveBeenCalledOnce();
    expect(clearTokens).not.toHaveBeenCalled();
    expect(doSignIn).toHaveBeenCalledOnce();
  });

  it("'reject' still throws (tokens untouched) when adopting fails transiently", async () => {
    vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: {} } as never);
    const adopt = vi.fn().mockRejectedValue(Object.assign(new Error('n'), { name: 'NetworkError' }));
    const doSignIn = vi.fn().mockRejectedValue(existing());
    const err = await run(doSignIn, 'reject', adopt).catch((e) => e);
    expect(isAlreadySignedInError(err)).toBe(true);
    expect(clearTokens).not.toHaveBeenCalled();
    expect(doSignIn).toHaveBeenCalledOnce();
  });

  it("'reject' recovers (no lockout) when adopting fails with a token-clearing error", async () => {
    vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: {} } as never);
    const adopt = vi.fn().mockRejectedValue(
      Object.assign(new Error('revoked'), { name: 'NotAuthorizedException' }),
    );
    const doSignIn = vi
      .fn()
      .mockRejectedValueOnce(existing())
      .mockResolvedValueOnce({ isSignedIn: true });
    await run(doSignIn, 'reject', adopt);
    expect(clearTokens).toHaveBeenCalledOnce();
    expect(doSignIn).toHaveBeenCalledTimes(2);
  });

  it("'reject' with no tokens (race) clears locally, no signOut, retries once", async () => {
    vi.mocked(fetchAuthSession).mockResolvedValue({} as never);
    const doSignIn = vi
      .fn()
      .mockRejectedValueOnce(existing())
      .mockResolvedValueOnce({ isSignedIn: true });
    await run(doSignIn, 'reject');
    expect(clearTokens).toHaveBeenCalledOnce();
    expect(doSignIn).toHaveBeenCalledTimes(2);
  });

  it("'reject' rethrows when fetchAuthSession fails, without clearing tokens", async () => {
    const boom = new Error('network');
    vi.mocked(fetchAuthSession).mockRejectedValue(boom);
    const doSignIn = vi.fn().mockRejectedValue(existing());
    await expect(
      run(doSignIn, 'reject'),
    ).rejects.toBe(boom);
    expect(clearTokens).not.toHaveBeenCalled();
    expect(doSignIn).toHaveBeenCalledOnce();
  });

  it('rethrows other errors without touching the session', async () => {
    const bad = Object.assign(new Error('nope'), { name: 'NotAuthorizedException' });
    const doSignIn = vi.fn().mockRejectedValue(bad);
    await expect(
      run(doSignIn, 'reject'),
    ).rejects.toBe(bad);
    expect(clearTokens).not.toHaveBeenCalled();
  });
});

describe('isRefreshTokenRejected', () => {
  const failure = (name: string) => ({
    event: 'tokenRefresh_failure',
    data: { error: { name } },
  });
  it.each([
    'NotAuthorizedException',
    'TokenRevokedException',
    'UserNotFoundException',
    'PasswordResetRequiredException',
    'UserNotConfirmedException',
    'RefreshTokenReuseException',
  ])('true for %s (Amplify clears tokens)', (name) => {
    expect(isRefreshTokenRejected(failure(name))).toBe(true);
  });
  it('false for network-style errors', () => {
    expect(isRefreshTokenRejected(failure('NetworkError'))).toBe(false);
    expect(isRefreshTokenRejected(failure('TooManyRequestsException'))).toBe(false);
  });
  it('false for missing or odd payloads', () => {
    expect(isRefreshTokenRejected({ event: 'tokenRefresh_failure' })).toBe(false);
    expect(
      isRefreshTokenRejected({ event: 'tokenRefresh_failure', data: {} }),
    ).toBe(false);
    expect(
      isRefreshTokenRejected({ event: 'tokenRefresh_failure', data: { error: { name: 42 } } }),
    ).toBe(false);
    expect(isRefreshTokenRejected({ event: 'tokenRefresh_failure', data: null })).toBe(false);
    expect(isRefreshTokenRejected(undefined as never)).toBe(false);
  });
  it('false for other events', () => {
    expect(
      isRefreshTokenRejected({
        event: 'tokenRefresh',
        data: { error: { name: 'NotAuthorizedException' } },
      }),
    ).toBe(false);
  });
});

describe('checkSessionOnMount', () => {
  const mk = (over: Partial<Parameters<typeof checkSessionOnMount>[0]> = {}) => ({
    fetchSession: vi.fn().mockResolvedValue({ tokens: {} }),
    loadUser: vi.fn().mockResolvedValue(undefined),
    clearCurrentUser: vi.fn(),
    isStale: () => false,
    ...over,
  });

  it('loads the user when tokens exist, no clear', async () => {
    const d = mk();
    await checkSessionOnMount(d);
    expect(d.loadUser).toHaveBeenCalledOnce();
    expect(d.clearCurrentUser).not.toHaveBeenCalled();
  });
  it('clears state when there are no tokens', async () => {
    const d = mk({ fetchSession: vi.fn().mockResolvedValue({}) });
    await checkSessionOnMount(d);
    expect(d.clearCurrentUser).toHaveBeenCalledOnce();
  });
  it('fetch failure clears state only (no signOut / token clearing)', async () => {
    const d = mk({ fetchSession: vi.fn().mockRejectedValue(new Error('net')) });
    await checkSessionOnMount(d);
    expect(d.clearCurrentUser).toHaveBeenCalledOnce();
    expect(clearTokens).not.toHaveBeenCalled();
  });
  it('transient load failure clears state only, tokens kept', async () => {
    const d = mk({ loadUser: vi.fn().mockRejectedValue(new Error('net')) });
    await checkSessionOnMount(d);
    expect(d.clearCurrentUser).toHaveBeenCalledOnce();
    expect(clearTokens).not.toHaveBeenCalled();
  });
  it('load failure with a token-clearing error also clears tokens locally', async () => {
    const d = mk({
      loadUser: vi.fn().mockRejectedValue(
        Object.assign(new Error('revoked'), { name: 'NotAuthorizedException' }),
      ),
    });
    await checkSessionOnMount(d);
    expect(clearTokens).toHaveBeenCalledOnce();
    expect(d.clearCurrentUser).toHaveBeenCalledOnce();
  });
  it('does nothing when stale', async () => {
    const d = mk({
      isStale: () => true,
      fetchSession: vi.fn().mockRejectedValue(new Error('x')),
    });
    await checkSessionOnMount(d);
    expect(d.clearCurrentUser).not.toHaveBeenCalled();
  });
});
