import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  fetchAuthSession: vi.fn(),
}));
const h = vi.hoisted(() => ({
  clearTokens: vi.fn(),
  signInIgnoringSession: vi.fn(),
}));
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: { tokenOrchestrator: { clearTokens: h.clearTokens } },
}));
vi.mock('./reauth', () => ({
  signInIgnoringSession: h.signInIgnoringSession,
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

beforeEach(() => vi.clearAllMocks());

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
    expect(deps.mapSignInResult).toHaveBeenCalledWith({ isSignedIn: true }, undefined);
    expect(h.signInIgnoringSession).not.toHaveBeenCalled();
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
    );
  });
});

describe('reauthenticateWith', () => {
  const deps = () => ({
    username: 'cognito-user',
    pass: 'pw',
    authFlowType: 'CUSTOM_WITH_SRP' as const,
    mapSignInResult: vi.fn().mockResolvedValue({ result: 'SUCCESS' }),
  });

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
    expect(d.mapSignInResult).toHaveBeenCalledWith({ isSignedIn: false }, clientMetadata);
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
