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
  checkSessionAfterReauth,
  checkSessionOnMount,
  isAlreadySignedInError,
  isRefreshTokenRejected,
  refreshAndReload,
  shouldLogOutOnHubEvent,
  signInHandlingExistingSession,
} from './sessionGuards';

const existing = () =>
  Object.assign(new Error('x'), { name: 'UserAlreadyAuthenticatedException' });

const forceSignOut = vi.fn();
beforeEach(() => vi.clearAllMocks());

describe('signInHandlingExistingSession', () => {
  it('default: signs out and retries once', async () => {
    const doSignIn = vi
      .fn()
      .mockRejectedValueOnce(existing())
      .mockResolvedValueOnce({ isSignedIn: true });
    await signInHandlingExistingSession(doSignIn as never, forceSignOut);
    expect(forceSignOut).toHaveBeenCalledOnce();
    expect(doSignIn).toHaveBeenCalledTimes(2);
  });

  it("'reject' with a valid session adopts it and throws AlreadySignedInException, no signOut", async () => {
    vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: {} } as never);
    const adopt = vi.fn().mockResolvedValue(undefined);
    const doSignIn = vi.fn().mockRejectedValue(existing());
    const err = await signInHandlingExistingSession(
      doSignIn as never,
      forceSignOut,
      'reject',
      adopt,
    ).catch((e) => e);
    expect(isAlreadySignedInError(err)).toBe(true);
    expect(err.name).toBe('AlreadySignedInException');
    expect(adopt).toHaveBeenCalledOnce();
    expect(forceSignOut).not.toHaveBeenCalled();
    expect(clearTokens).not.toHaveBeenCalled();
    expect(doSignIn).toHaveBeenCalledOnce();
  });

  it("'reject' still throws (tokens untouched) when adopting fails transiently", async () => {
    vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: {} } as never);
    const adopt = vi.fn().mockRejectedValue(Object.assign(new Error('n'), { name: 'NetworkError' }));
    const doSignIn = vi.fn().mockRejectedValue(existing());
    const err = await signInHandlingExistingSession(
      doSignIn as never, forceSignOut, 'reject', adopt,
    ).catch((e) => e);
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
    await signInHandlingExistingSession(
      doSignIn as never, forceSignOut, 'reject', adopt,
    );
    expect(clearTokens).toHaveBeenCalledOnce();
    expect(forceSignOut).not.toHaveBeenCalled();
    expect(doSignIn).toHaveBeenCalledTimes(2);
  });

  it("'reject' with no tokens (race) clears locally, no signOut, retries once", async () => {
    vi.mocked(fetchAuthSession).mockResolvedValue({} as never);
    const doSignIn = vi
      .fn()
      .mockRejectedValueOnce(existing())
      .mockResolvedValueOnce({ isSignedIn: true });
    await signInHandlingExistingSession(doSignIn as never, forceSignOut, 'reject');
    expect(clearTokens).toHaveBeenCalledOnce();
    expect(forceSignOut).not.toHaveBeenCalled();
    expect(doSignIn).toHaveBeenCalledTimes(2);
  });

  it("'reject' rethrows when fetchAuthSession fails, without clearing tokens", async () => {
    const boom = new Error('network');
    vi.mocked(fetchAuthSession).mockRejectedValue(boom);
    const doSignIn = vi.fn().mockRejectedValue(existing());
    await expect(
      signInHandlingExistingSession(doSignIn as never, forceSignOut, 'reject'),
    ).rejects.toBe(boom);
    expect(clearTokens).not.toHaveBeenCalled();
    expect(forceSignOut).not.toHaveBeenCalled();
    expect(doSignIn).toHaveBeenCalledOnce();
  });

  it('rethrows other errors without touching the session', async () => {
    const bad = Object.assign(new Error('nope'), { name: 'NotAuthorizedException' });
    const doSignIn = vi.fn().mockRejectedValue(bad);
    await expect(
      signInHandlingExistingSession(doSignIn as never, forceSignOut, 'reject'),
    ).rejects.toBe(bad);
    expect(forceSignOut).not.toHaveBeenCalled();
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

describe('shouldLogOutOnHubEvent', () => {
  const failure = (name: string) => ({
    event: 'tokenRefresh_failure',
    data: { error: Object.assign(new Error('x'), { name }) },
  });

  it('logs out on a token-clearing refresh failure when no re-auth is active', () => {
    expect(shouldLogOutOnHubEvent(failure('NotAuthorizedException'), false)).toBe(true);
  });

  it('ignores the same failure while a re-auth attempt is active', () => {
    expect(shouldLogOutOnHubEvent(failure('NotAuthorizedException'), true)).toBe(false);
  });

  it('ignores transient failures', () => {
    expect(shouldLogOutOnHubEvent(failure('NetworkError'), false)).toBe(false);
  });
});

describe('checkSessionAfterReauth', () => {
  const run = (fetchSession: () => Promise<{ tokens?: unknown }>, isStale = () => false) => {
    const clearCurrentUser = vi.fn();
    return checkSessionAfterReauth({ fetchSession, clearCurrentUser, isStale }).then(
      () => clearCurrentUser,
    );
  };

  it('keeps state when the real session is still there', async () => {
    expect(await run(async () => ({ tokens: {} }))).not.toHaveBeenCalled();
  });

  it('clears state when there are no tokens', async () => {
    expect(await run(async () => ({}))).toHaveBeenCalledOnce();
  });

  it('clears on a token-clearing error but keeps state on a transient one', async () => {
    const named = (name: string) => async () => {
      throw Object.assign(new Error('x'), { name });
    };
    expect(await run(named('NotAuthorizedException'))).toHaveBeenCalledOnce();
    expect(await run(named('NetworkError'))).not.toHaveBeenCalled();
  });

  it('does nothing when stale', async () => {
    expect(await run(async () => ({}), () => true)).not.toHaveBeenCalled();
  });
});

describe('refreshAndReload', () => {
  it('forces a refresh then reloads, in that order', async () => {
    const calls: string[] = [];
    await refreshAndReload({
      reauthActive: false,
      refresh: async () => void calls.push('refresh'),
      reload: async () => void calls.push('reload'),
    });
    expect(calls).toEqual(['refresh', 'reload']);
  });

  it('throws during a re-auth attempt without refreshing', async () => {
    const refresh = vi.fn();
    await expect(
      refreshAndReload({ reauthActive: true, refresh, reload: vi.fn() }),
    ).rejects.toThrow('re-auth attempt');
    expect(refresh).not.toHaveBeenCalled();
  });
});
