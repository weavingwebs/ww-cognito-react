import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  fetchAuthSession: vi.fn(),
}));
const h = vi.hoisted(() => ({
  run: vi.fn(),
  clearTokens: vi.fn(),
  active: vi.fn(() => false),
}));
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: { tokenOrchestrator: { clearTokens: h.clearTokens } },
}));
vi.mock('./reauthGuard', () => ({
  runWithReauthGuard: h.run,
  hasActiveReauth: h.active,
}));

import { fetchAuthSession, signIn } from 'aws-amplify/auth';
import { authenticateWith } from './authenticate';

const existing = () =>
  Object.assign(new Error('x'), { name: 'UserAlreadyAuthenticatedException' });

const base = () => ({
  email: ' a@b.c ',
  pass: 'pw',
  authFlowType: 'USER_SRP_AUTH' as const,
  mapSignInResult: vi.fn().mockResolvedValue({ result: 'SUCCESS' }),
  loadUserFromSession: vi.fn().mockResolvedValue(undefined),
  forceSignOut: vi.fn().mockResolvedValue(undefined),
});

beforeEach(() => {
  vi.clearAllMocks();
  h.active.mockReturnValue(false);
});

describe('authenticateWith', () => {
  it('back-compat: no options calls signIn exactly as 3.1.0 did', async () => {
    vi.mocked(signIn).mockResolvedValue({ isSignedIn: true } as never);
    const deps = base();
    await authenticateWith(deps);
    expect(signIn).toHaveBeenCalledWith({
      username: 'a@b.c',
      password: 'pw',
      options: { authFlowType: 'USER_SRP_AUTH' },
    });
    expect(deps.mapSignInResult).toHaveBeenCalledWith({ isSignedIn: true }, null, undefined);
    expect(h.run).not.toHaveBeenCalled();
  });

  it("back-compat: default onExistingSession='replace' still signs out and retries", async () => {
    vi.mocked(signIn)
      .mockRejectedValueOnce(existing())
      .mockResolvedValueOnce({ isSignedIn: true } as never);
    const deps = base();
    await authenticateWith(deps);
    expect(deps.forceSignOut).toHaveBeenCalledOnce();
    expect(signIn).toHaveBeenCalledTimes(2);
  });

  it("back-compat: onExistingSession='reject' still adopts then throws AlreadySignedInException", async () => {
    vi.mocked(signIn).mockRejectedValue(existing());
    vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: {} } as never);
    const deps = base();
    const err = await authenticateWith({
      ...deps,
      opts: { onExistingSession: 'reject' },
    }).catch((e) => e);
    expect(err.name).toBe('AlreadySignedInException');
    expect(deps.loadUserFromSession).toHaveBeenCalledOnce();
    expect(deps.forceSignOut).not.toHaveBeenCalled();
  });

  it('forwards clientMetadata on signIn and to the exchange', async () => {
    vi.mocked(signIn).mockResolvedValue({ isSignedIn: false } as never);
    const deps = base();
    const clientMetadata = { mfaAction: 'setup' };
    await authenticateWith({ ...deps, authFlowType: 'CUSTOM_WITH_SRP', opts: { clientMetadata } });
    expect(signIn).toHaveBeenCalledWith({
      username: 'a@b.c',
      password: 'pw',
      options: { authFlowType: 'CUSTOM_WITH_SRP', clientMetadata },
    });
    expect(deps.mapSignInResult).toHaveBeenCalledWith(
      { isSignedIn: false },
      null,
      clientMetadata,
    );
  });

  it('allowWhileLoggedIn bypasses onExistingSession entirely and runs under the guard', async () => {
    const guard = { settled: false };
    h.run.mockImplementation(async (run: () => Promise<unknown>) => ({
      result: await run(),
      guard,
    }));
    vi.mocked(signIn).mockResolvedValue({ isSignedIn: false } as never);
    const deps = base();
    const signal = new AbortController().signal;
    const clientMetadata = { mfaAction: 'setup' };
    await authenticateWith({
      ...deps,
      opts: { allowWhileLoggedIn: true, onExistingSession: 'replace', clientMetadata, signal },
    });
    expect(h.run).toHaveBeenCalledWith(expect.any(Function), { signal });
    expect(deps.forceSignOut).not.toHaveBeenCalled();
    expect(fetchAuthSession).not.toHaveBeenCalled();
    expect(h.clearTokens).not.toHaveBeenCalled();
    expect(deps.mapSignInResult).toHaveBeenCalledWith({ isSignedIn: false }, guard, clientMetadata);
  });

  it('allowWhileLoggedIn: UserAlreadyAuthenticatedException is not special-cased (guard owns the store)', async () => {
    h.run.mockImplementation(async (run: () => Promise<unknown>) => ({
      result: await run(),
      guard: null,
    }));
    vi.mocked(signIn).mockRejectedValue(existing());
    const deps = base();
    await expect(
      authenticateWith({ ...deps, opts: { allowWhileLoggedIn: true } }),
    ).rejects.toMatchObject({ name: 'UserAlreadyAuthenticatedException' });
    expect(deps.forceSignOut).not.toHaveBeenCalled();
  });

  it('a plain authenticate while a re-auth attempt is active is refused, signing in nothing', async () => {
    h.active.mockReturnValue(true);
    const deps = base();
    await expect(authenticateWith(deps)).rejects.toThrow('re-auth attempt is in progress');
    expect(signIn).not.toHaveBeenCalled();
  });
});
