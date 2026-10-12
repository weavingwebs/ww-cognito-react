import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  fetchAuthSession: vi.fn(),
}));
const h = vi.hoisted(() => ({
  clearTokens: vi.fn(),
  signInIgnoringSession: vi.fn(),
  createReauthGuard: vi.fn(),
  createSupersessionGuard: vi.fn(),
}));
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: { tokenOrchestrator: { clearTokens: h.clearTokens } },
}));
vi.mock('./reauth', () => ({
  signInIgnoringSession: h.signInIgnoringSession,
  createReauthGuard: h.createReauthGuard,
  createSupersessionGuard: h.createSupersessionGuard,
  defaultReauthDeps: {
    liveUsername: vi.fn(),
    liveAuthTime: vi.fn().mockResolvedValue(900),
    signOut: vi.fn(),
  },
}));

import { fetchAuthSession, signIn } from 'aws-amplify/auth';
import { authenticateWith, reauthenticateWith } from './authenticate';

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
  h.createSupersessionGuard.mockReturnValue(undefined);
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
    expect(deps.mapSignInResult).toHaveBeenCalledWith(
      { isSignedIn: true },
      undefined,
      undefined,
    );
    expect(h.signInIgnoringSession).not.toHaveBeenCalled();
  });

  it('a plain sign-in supersedes any pending attempt & its callbacks carry the supersession guard', async () => {
    const supersession = { beforeStep: vi.fn(), beforeSuccess: vi.fn() };
    h.createSupersessionGuard.mockReturnValue(supersession);
    vi.mocked(signIn).mockResolvedValue({ isSignedIn: true } as never);
    const deps = base();
    await authenticateWith(deps);
    expect(h.createSupersessionGuard).toHaveBeenCalledOnce();
    expect(deps.mapSignInResult).toHaveBeenCalledWith(
      { isSignedIn: true },
      undefined,
      supersession,
    );
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
      clientMetadata,
      undefined,
    );
  });
});

describe('reauthenticateWith', () => {
  const deps = () => ({
    username: 'cognito-user',
    pass: 'pw',
    authFlowType: 'CUSTOM_WITH_SRP' as const,
    mapSignInResult: vi.fn().mockResolvedValue({ result: 'SUCCESS' }),
    tabUsername: () => 'cognito-user',
    startAuthTime: 1000,
    clearTabUser: vi.fn(),
  });
  const guard = { beforeStep: vi.fn(), beforeSuccess: vi.fn() };
  beforeEach(() => h.createReauthGuard.mockReturnValue(guard));

  it('signs in as the given username, ignoring the session, & maps the result', async () => {
    h.signInIgnoringSession.mockResolvedValue({ isSignedIn: false });
    const d = deps();
    const clientMetadata = { mfaAction: 'setup' };
    await reauthenticateWith({ ...d, clientMetadata });
    expect(h.signInIgnoringSession).toHaveBeenCalledWith({
      username: 'cognito-user',
      password: 'pw',
      options: { authFlowType: 'CUSTOM_WITH_SRP', clientMetadata },
    });
    expect(signIn).not.toHaveBeenCalled();
    expect(d.mapSignInResult).toHaveBeenCalledWith(
      { isSignedIn: false },
      clientMetadata,
      guard,
    );
  });

  it('builds the guard for this user, tab & start auth_time before signing in', async () => {
    h.signInIgnoringSession.mockResolvedValue({ isSignedIn: false });
    const d = deps();
    await reauthenticateWith(d);
    expect(h.createReauthGuard).toHaveBeenCalledWith(
      expect.objectContaining({
        username: 'cognito-user',
        startAuthTime: 1000,
        tabUsername: d.tabUsername,
        clearTabUser: d.clearTabUser,
      }),
    );
    expect(h.createReauthGuard.mock.invocationCallOrder[0]).toBeLessThan(
      h.signInIgnoringSession.mock.invocationCallOrder[0],
    );
  });

  it('a failed attempt rethrows without mapping, signing out or clearing tokens', async () => {
    const boom = Object.assign(new Error('x'), { name: 'NotAuthorizedException' });
    h.signInIgnoringSession.mockRejectedValue(boom);
    const d = deps();
    await expect(reauthenticateWith(d)).rejects.toBe(boom);
    expect(d.mapSignInResult).not.toHaveBeenCalled();
    expect(h.clearTokens).not.toHaveBeenCalled();
  });
});
