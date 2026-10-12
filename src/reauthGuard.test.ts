// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import {
  createReauthGuard,
  createSupersessionGuard,
  isReauthAbortedError,
  isReauthNotFreshError,
  supersedeReauthAttempts,
  type ReauthGuardDeps,
} from './reauth';

const deps = (over: Partial<ReauthGuardDeps> = {}): ReauthGuardDeps => ({
  username: 'auser',
  startAuthTime: 1000,
  tabUsername: () => 'auser',
  liveUsername: async () => 'auser',
  liveAuthTime: async () => 2000,
  signOut: vi.fn().mockResolvedValue(undefined),
  clearTabUser: vi.fn(),
  ...over,
});

describe('beforeStep', () => {
  it('passes for the same user in this tab and in storage', async () => {
    await expect(createReauthGuard(deps()).beforeStep()).resolves.toBeUndefined();
  });

  it('aborts when this tab has logged out', async () => {
    const g = createReauthGuard(deps({ tabUsername: () => undefined }));
    await expect(g.beforeStep()).rejects.toSatisfy(isReauthAbortedError);
  });

  it('aborts when storage has no session (logged out in another tab)', async () => {
    const g = createReauthGuard(deps({ liveUsername: async () => undefined }));
    await expect(g.beforeStep()).rejects.toSatisfy(isReauthAbortedError);
  });

  it('aborts when another user is in storage', async () => {
    const g = createReauthGuard(deps({ liveUsername: async () => 'someone-else' }));
    await expect(g.beforeStep()).rejects.toSatisfy(isReauthAbortedError);
  });

  it('a transient failure reading the session is rethrown as itself, not a logout', async () => {
    const boom = new Error('network');
    const g = createReauthGuard(
      deps({
        liveUsername: async () => {
          throw boom;
        },
      }),
    );
    await expect(g.beforeStep()).rejects.toBe(boom);
  });

  it('a newer attempt supersedes it', async () => {
    const older = createReauthGuard(deps());
    createReauthGuard(deps());
    await expect(older.beforeStep()).rejects.toSatisfy(isReauthAbortedError);
  });

  it('a plain sign-in (supersedeReauthAttempts) supersedes it', async () => {
    const g = createReauthGuard(deps());
    supersedeReauthAttempts();
    await expect(g.beforeStep()).rejects.toSatisfy(isReauthAbortedError);
  });
});

describe('createSupersessionGuard', () => {
  it('a plain sign-in attempt stops working once a newer one starts', async () => {
    const plain = createSupersessionGuard();
    await expect(plain.beforeStep()).resolves.toBeUndefined();
    createReauthGuard(deps());
    await expect(plain.beforeStep()).rejects.toSatisfy(isReauthAbortedError);
    // Success is never refused: Amplify has already stored the tokens.
    await expect(plain.beforeSuccess()).resolves.toBeUndefined();
  });
});

describe('beforeSuccess', () => {
  it('passes with a newer auth_time', async () => {
    const d = deps();
    await expect(createReauthGuard(d).beforeSuccess()).resolves.toBeUndefined();
    expect(d.signOut).not.toHaveBeenCalled();
  });

  it('discards the session when this tab logged out while the last answer was in flight', async () => {
    const d = deps({ tabUsername: () => undefined });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.signOut).toHaveBeenCalledOnce();
    expect(d.clearTabUser).not.toHaveBeenCalled();
  });

  it('when the tab now shows ANOTHER user, signs out the clobbering session and resets the tab', async () => {
    const d = deps({ tabUsername: () => 'user-b' });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.signOut).toHaveBeenCalledOnce();
    expect(d.clearTabUser).toHaveBeenCalledOnce();
  });

  it('does not sign out when merely superseded (the tab is still logged in)', async () => {
    const d = deps();
    const g = createReauthGuard(d);
    supersedeReauthAttempts();
    await expect(g.beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.signOut).not.toHaveBeenCalled();
  });

  it('rejects an unchanged auth_time (a refresh restored the old tokens), keeping the session', async () => {
    const d = deps({ liveAuthTime: async () => 1000 });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthNotFreshError);
    expect(d.signOut).not.toHaveBeenCalled();
  });

  it('rejects a missing auth_time', async () => {
    const d = deps({ liveAuthTime: async () => undefined });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthNotFreshError);
  });

  it('skips the freshness check when the start auth_time is unknown', async () => {
    const liveAuthTime = vi.fn();
    const d = deps({ startAuthTime: undefined, liveAuthTime });
    await expect(createReauthGuard(d).beforeSuccess()).resolves.toBeUndefined();
    expect(liveAuthTime).not.toHaveBeenCalled();
  });
});
