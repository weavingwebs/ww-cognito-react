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
  readStoredSession: vi.fn(),
  cleanUpReplacedSession: vi.fn(),
}));
vi.mock('./storedSession', async (orig) => ({
  ...(await orig<typeof import('./storedSession')>()),
  readStoredSession: h.readStoredSession,
  cleanUpReplacedSession: h.cleanUpReplacedSession,
}));
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: { tokenOrchestrator: { clearTokens: h.clearTokens } },
}));
vi.mock('./reauth', () => ({
  signInIgnoringSession: h.signInIgnoringSession,
  createReauthGuard: h.createReauthGuard,
  createSupersessionGuard: h.createSupersessionGuard,
  isAmplifyInternalsChangedError: (err: unknown) =>
    (err as { name?: unknown } | null)?.name === 'AmplifyInternalsChangedException',
  defaultReauthDeps: {
    liveUsername: vi.fn(),
    liveAuthTime: vi.fn().mockResolvedValue(900),
    discardSession: vi.fn(),
    restoreSession: vi.fn(),
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
});

beforeEach(() => {
  vi.clearAllMocks();
  h.createSupersessionGuard.mockReturnValue(undefined);
  h.readStoredSession.mockResolvedValue(null);
});

const stored = {
  username: 'old-uuid',
  email: 'old@b.c',
  refreshToken: 'r-old',
  revocable: true,
};

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

  it("default 'replace': signs in again WITHOUT signing out first, keeping the existing session until success", async () => {
    vi.mocked(signIn).mockRejectedValueOnce(existing());
    h.signInIgnoringSession.mockResolvedValue({ isSignedIn: true } as never);
    const deps = base();
    await authenticateWith(deps);
    expect(signIn).toHaveBeenCalledOnce();
    expect(h.signInIgnoringSession).toHaveBeenCalledWith({
      username: 'a@b.c',
      password: 'pw',
      options: { authFlowType: 'USER_SRP_AUTH' },
    });
  });

  it("'replace' with a stored session: cleans it up only when the guard reports success", async () => {
    h.readStoredSession.mockResolvedValue(stored);
    let onSuccess: (() => Promise<void>) | undefined;
    h.createSupersessionGuard.mockImplementation((fn) => {
      onSuccess = fn;
      return undefined;
    });
    vi.mocked(signIn).mockRejectedValueOnce(existing());
    h.signInIgnoringSession.mockResolvedValue({ isSignedIn: false } as never);
    await authenticateWith(base());
    expect(h.cleanUpReplacedSession).not.toHaveBeenCalled();
    await onSuccess!();
    expect(h.cleanUpReplacedSession).toHaveBeenCalledWith(stored);
    await onSuccess!(); // once only
    expect(h.cleanUpReplacedSession).toHaveBeenCalledOnce();
  });

  it('a plain login with no existing session never reads storage or cleans up', async () => {
    let onSuccess: (() => Promise<void>) | undefined;
    h.createSupersessionGuard.mockImplementation((fn) => {
      onSuccess = fn;
      return undefined;
    });
    vi.mocked(signIn).mockResolvedValue({ isSignedIn: true } as never);
    await authenticateWith(base());
    await onSuccess!();
    expect(h.readStoredSession).not.toHaveBeenCalled();
    expect(h.cleanUpReplacedSession).not.toHaveBeenCalled();
  });

  it('confirmReplace declined: throws ReplaceCancelledException, nothing signed in or cleaned', async () => {
    h.readStoredSession.mockResolvedValue(stored);
    vi.mocked(signIn).mockRejectedValueOnce(existing());
    const confirmReplace = vi.fn().mockResolvedValue(false);
    const err = await authenticateWith({ ...base(), opts: { confirmReplace } }).catch((e) => e);
    expect(err.name).toBe('ReplaceCancelledException');
    expect(confirmReplace).toHaveBeenCalledWith({ username: 'old-uuid', email: 'old@b.c' });
    expect(h.signInIgnoringSession).not.toHaveBeenCalled();
    expect(h.cleanUpReplacedSession).not.toHaveBeenCalled();
  });

  it('confirmReplace accepted: proceeds', async () => {
    h.readStoredSession.mockResolvedValue(stored);
    vi.mocked(signIn).mockRejectedValueOnce(existing());
    h.signInIgnoringSession.mockResolvedValue({ isSignedIn: true } as never);
    await authenticateWith({ ...base(), opts: { confirmReplace: async () => true } });
    expect(h.signInIgnoringSession).toHaveBeenCalledOnce();
  });

  it.each(['old@b.c', ' OLD@B.C ', 'old-uuid'])(
    'confirmReplace is not asked when the typed login (%s) is the stored user',
    async (typed) => {
      h.readStoredSession.mockResolvedValue(stored);
      vi.mocked(signIn).mockRejectedValueOnce(existing());
      h.signInIgnoringSession.mockResolvedValue({ isSignedIn: true } as never);
      const confirmReplace = vi.fn();
      await authenticateWith({ ...base(), email: typed, opts: { confirmReplace } });
      expect(confirmReplace).not.toHaveBeenCalled();
    },
  );

  it("confirmReplace is ignored for 'reject' and when there is no existing session", async () => {
    const confirmReplace = vi.fn();
    vi.mocked(signIn).mockResolvedValue({ isSignedIn: true } as never);
    await authenticateWith({ ...base(), opts: { confirmReplace } });
    vi.mocked(signIn).mockRejectedValue(existing());
    vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: {} } as never);
    await authenticateWith({
      ...base(),
      opts: { confirmReplace, onExistingSession: 'reject' },
    }).catch(() => undefined);
    expect(confirmReplace).not.toHaveBeenCalled();
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
