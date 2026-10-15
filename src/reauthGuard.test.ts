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
  discardSession: vi.fn().mockResolvedValue(undefined),
  restoreSession: vi.fn().mockResolvedValue(false),
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

  it('runs onSuccess on success even when superseded (the tokens are stored either way)', async () => {
    const onSuccess = vi.fn().mockResolvedValue(undefined);
    const plain = createSupersessionGuard(onSuccess);
    await plain.beforeStep();
    expect(onSuccess).not.toHaveBeenCalled();
    createReauthGuard(deps());
    await plain.beforeSuccess();
    expect(onSuccess).toHaveBeenCalledOnce();
  });
});

describe('beforeSuccess', () => {
  it('passes with a newer auth_time', async () => {
    const d = deps();
    await expect(createReauthGuard(d).beforeSuccess()).resolves.toBeUndefined();
    expect(d.discardSession).not.toHaveBeenCalled();
  });

  it('discards (by name) the session when this tab logged out while the last answer was in flight', async () => {
    const d = deps({ tabUsername: () => undefined });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.discardSession).toHaveBeenCalledOnce();
    expect(d.discardSession).toHaveBeenCalledWith('auser');
    expect(d.clearTabUser).not.toHaveBeenCalled();
  });

  it('tab shows ANOTHER user whose session is gone: discards this attempt by name and resets the tab', async () => {
    // liveUsername says A (just re-authed); B cannot be made current again.
    const d = deps({ tabUsername: () => 'user-b' });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.discardSession).toHaveBeenCalledOnce();
    expect(d.discardSession).toHaveBeenCalledWith('auser');
    expect(d.restoreSession).toHaveBeenCalledWith('user-b');
    expect(d.clearTabUser).toHaveBeenCalledOnce();
  });

  it('tab shows ANOTHER user whose tokens are intact: makes them current again and keeps the tab', async () => {
    const d = deps({
      tabUsername: () => 'user-b',
      restoreSession: vi.fn().mockResolvedValue(true),
    });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.discardSession).toHaveBeenCalledWith('auser');
    expect(d.clearTabUser).not.toHaveBeenCalled();
  });

  it('tab shows a user who is still current in storage (signed in after this attempt): keeps the tab', async () => {
    const d = deps({
      tabUsername: () => 'user-c',
      liveUsername: async () => 'user-c',
    });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.discardSession).toHaveBeenCalledWith('auser');
    expect(d.restoreSession).not.toHaveBeenCalled();
    expect(d.clearTabUser).not.toHaveBeenCalled();
  });

  it('a third user is current in storage and the tab logged out: discards only this attempt, never touches the tab', async () => {
    const d = deps({ tabUsername: () => undefined, liveUsername: async () => 'user-c' });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.discardSession).toHaveBeenCalledOnce();
    expect(d.discardSession).toHaveBeenCalledWith('auser');
    expect(d.clearTabUser).not.toHaveBeenCalled();
  });

  it('does not clear a tab that changed user while the discard was running', async () => {
    let tab: string | undefined = 'user-b';
    const d = deps({
      tabUsername: () => tab,
      discardSession: vi.fn(async () => {
        tab = 'user-d'; // a fresh sign-in landed during the wait
      }),
    });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.clearTabUser).not.toHaveBeenCalled();
  });

  it('does not discard when merely superseded (the tab is still logged in)', async () => {
    const d = deps();
    const g = createReauthGuard(d);
    supersedeReauthAttempts();
    await expect(g.beforeSuccess()).rejects.toSatisfy(isReauthAbortedError);
    expect(d.discardSession).not.toHaveBeenCalled();
  });

  it('rejects an unchanged auth_time (a refresh restored the old tokens), keeping the session', async () => {
    const d = deps({ liveAuthTime: async () => 1000 });
    await expect(createReauthGuard(d).beforeSuccess()).rejects.toSatisfy(isReauthNotFreshError);
    expect(d.discardSession).not.toHaveBeenCalled();
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
