// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ signInIgnoringSession: vi.fn() }));
vi.mock('aws-amplify/auth', () => ({
  signIn: vi.fn(),
  confirmSignIn: vi.fn(),
  fetchAuthSession: vi.fn(),
  getCurrentUser: vi.fn(),
  signOut: vi.fn(),
}));
vi.mock('./reauth', async (orig) => ({
  ...(await orig<typeof import('./reauth')>()),
  signInIgnoringSession: h.signInIgnoringSession,
}));

import { confirmSignIn, signIn } from 'aws-amplify/auth';
import { authenticateWith, reauthenticateWith } from './authenticate';
import { createMapSignInResult } from './mapSignInResult';
import {
  isAmplifyInternalsChangedError,
  isReauthAbortedError,
  isReauthNotFreshError,
  reauthError,
  AMPLIFY_INTERNALS_CHANGED_EXCEPTION,
} from './reauth';

// The real guard + the real mapSignInResult, with only Amplify's sign-in and
// the session lookups faked: how the pieces are wired together.
const done = { isSignedIn: true, nextStep: { signInStep: 'DONE' } } as never;
const totp = {
  isSignedIn: false,
  nextStep: { signInStep: 'CONFIRM_SIGN_IN_WITH_TOTP_CODE' },
} as never;

let tab: string | undefined;
let live: string | undefined;
let liveAuth: number | undefined;
const discardFn = vi.fn().mockResolvedValue(undefined);
const restoreFn = vi.fn().mockResolvedValue(false);
const clearTabUser = vi.fn();
const load = vi.fn().mockResolvedValue(undefined);

const reauth = (over: { startAuthTime?: number | undefined } = {}) =>
  reauthenticateWith({
    username: 'user-a',
    pass: 'pw',
    authFlowType: 'USER_SRP_AUTH',
    mapSignInResult: createMapSignInResult(load),
    tabUsername: () => tab,
    startAuthTime: 'startAuthTime' in over ? over.startAuthTime : 1000,
    clearTabUser,
    guardDeps: {
      liveUsername: async () => live,
      liveAuthTime: async () => liveAuth,
      discardSession: discardFn,
      restoreSession: restoreFn,
    },
  });

beforeEach(() => {
  vi.clearAllMocks();
  tab = 'user-a';
  live = 'user-a';
  liveAuth = 2000;
});

describe('reauthenticateWith (real guard, real mapSignInResult)', () => {
  it('no challenge: succeeds & loads the user', async () => {
    h.signInIgnoringSession.mockImplementation(async () => {
      liveAuth = 3000; // Amplify stored the new tokens
      return done;
    });
    await expect(reauth()).resolves.toEqual({ result: 'SUCCESS' });
    expect(load).toHaveBeenCalledOnce();
  });

  it('no challenge: another tab changed the stored user -> refuses BEFORE signing in', async () => {
    live = 'user-b';
    await expect(reauth()).rejects.toSatisfy(isReauthAbortedError);
    expect(h.signInIgnoringSession).not.toHaveBeenCalled();
    expect(load).not.toHaveBeenCalled();
  });

  it('no challenge: logged out in this tab -> refuses before signing in', async () => {
    tab = undefined;
    await expect(reauth()).rejects.toSatisfy(isReauthAbortedError);
    expect(h.signInIgnoringSession).not.toHaveBeenCalled();
  });

  it('the new auth_time must beat the newer of the tab snapshot and the stored session', async () => {
    // Another tab re-authenticated (auth_time 1500) after this tab loaded its
    // snapshot (1000); a racing refresh then restored those tokens.
    liveAuth = 1500;
    h.signInIgnoringSession.mockResolvedValue(done); // stores nothing newer
    // Start and post-success lookups both see 1500, which is not > 1500.
    await expect(reauth()).rejects.toSatisfy(isReauthNotFreshError);
    expect(load).not.toHaveBeenCalled();
    expect(discardFn).not.toHaveBeenCalled();
  });

  it('challenge: logout during the in-flight final answer discards the session', async () => {
    h.signInIgnoringSession.mockResolvedValue(totp);
    const first = await reauth();
    if (first.result !== 'TOTP_REQUIRED') throw new Error('unreachable');
    vi.mocked(confirmSignIn).mockImplementation((async () => {
      tab = undefined; // the tab logs out while the answer is in flight
      return done;
    }) as never);
    await expect(first.respondToTotpChallenge('123456')).rejects.toSatisfy(isReauthAbortedError);
    expect(discardFn).toHaveBeenCalledOnce();
    expect(discardFn).toHaveBeenCalledWith('user-a');
    expect(load).not.toHaveBeenCalled();
  });

  it('challenge: the tab became another user during the in-flight answer -> discarded by name & tab reset', async () => {
    h.signInIgnoringSession.mockResolvedValue(totp);
    const first = await reauth();
    if (first.result !== 'TOTP_REQUIRED') throw new Error('unreachable');
    vi.mocked(confirmSignIn).mockImplementation((async () => {
      tab = 'user-b';
      return done;
    }) as never);
    await expect(first.respondToTotpChallenge('123456')).rejects.toSatisfy(isReauthAbortedError);
    expect(discardFn).toHaveBeenCalledOnce();
    expect(clearTabUser).toHaveBeenCalledOnce();
  });

  it('internals changed, nothing else changed: rethrows it and leaves the session alone', async () => {
    h.signInIgnoringSession.mockImplementation(async () => {
      liveAuth = 3000; // Amplify stored the new tokens before it failed
      throw reauthError(AMPLIFY_INTERNALS_CHANGED_EXCEPTION, 'x');
    });
    await expect(reauth()).rejects.toSatisfy(isAmplifyInternalsChangedError);
    expect(discardFn).not.toHaveBeenCalled();
    expect(load).not.toHaveBeenCalled();
  });

  it('internals changed after the tab logged out: the possibly-stored session is discarded', async () => {
    // The pre-sign-in check passes; the tab logs out while the request runs.
    h.signInIgnoringSession.mockImplementation(async () => {
      tab = undefined;
      throw reauthError(AMPLIFY_INTERNALS_CHANGED_EXCEPTION, 'x');
    });
    await expect(reauth()).rejects.toSatisfy(isReauthAbortedError);
    expect(discardFn).toHaveBeenCalledWith('user-a');
  });

  it('a stale plain-authenticate challenge callback cannot answer a newer re-auth', async () => {
    vi.mocked(signIn).mockResolvedValue(totp);
    const old = await authenticateWith({
      email: 'a@b.c',
      pass: 'pw',
      authFlowType: 'USER_SRP_AUTH',
      mapSignInResult: createMapSignInResult(load),
      loadUserFromSession: load,
      forceSignOut: vi.fn(),
    });
    if (old.result !== 'TOTP_REQUIRED') throw new Error('unreachable');

    h.signInIgnoringSession.mockResolvedValue(totp);
    await reauth(); // starts a newer attempt

    await expect(old.respondToTotpChallenge('123456')).rejects.toSatisfy(isReauthAbortedError);
    expect(confirmSignIn).not.toHaveBeenCalled();
  });

  it('a stale re-auth callback cannot be answered after a plain sign-in starts', async () => {
    h.signInIgnoringSession.mockResolvedValue(totp);
    const first = await reauth();
    if (first.result !== 'TOTP_REQUIRED') throw new Error('unreachable');
    vi.mocked(signIn).mockResolvedValue(totp);
    await authenticateWith({
      email: 'a@b.c',
      pass: 'pw',
      authFlowType: 'USER_SRP_AUTH',
      mapSignInResult: createMapSignInResult(load),
      loadUserFromSession: load,
      forceSignOut: vi.fn(),
    });
    await expect(first.respondToTotpChallenge('1')).rejects.toSatisfy(isReauthAbortedError);
    expect(confirmSignIn).not.toHaveBeenCalled();
  });
});
