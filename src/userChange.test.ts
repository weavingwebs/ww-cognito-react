// @vitest-environment node
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  beginOwnSignIn,
  clearReloadFlag,
  createLoadCoordinator,
  duringOwnSignIn,
  readsStraddleUsers,
  runWhenSignInEnds,
  isOwnSignInActive,
  isUserChangedError,
  sessionUsername,
  shouldReloadFor,
  userChangedError,
} from './userChange';

const payload = (p: Record<string, unknown>) => ({ payload: p });
afterEach(() => vi.unstubAllGlobals());

describe('sessionUsername', () => {
  it('prefers the ID token cognito:username, then the access token username', () => {
    expect(
      sessionUsername({
        tokens: { idToken: payload({ 'cognito:username': 'a' }), accessToken: payload({ username: 'b' }) },
      }),
    ).toBe('a');
    expect(sessionUsername({ tokens: { accessToken: payload({ username: 'b' }) } })).toBe('b');
    expect(sessionUsername({ tokens: {} })).toBeUndefined();
    expect(sessionUsername(undefined)).toBeUndefined();
  });
});

describe('UserChangedError', () => {
  it('is recognised by name and leaks no usernames', () => {
    const err = userChangedError();
    expect(isUserChangedError(err)).toBe(true);
    expect(isUserChangedError(new Error('x'))).toBe(false);
    expect(err.message).not.toMatch(/user-/);
  });
});

describe('duringOwnSignIn', () => {
  it('is active only while the work runs, also when it throws, and nests', async () => {
    expect(isOwnSignInActive()).toBe(false);
    await duringOwnSignIn(async () => {
      expect(isOwnSignInActive()).toBe(true);
      await duringOwnSignIn(async () => undefined);
      expect(isOwnSignInActive()).toBe(true);
    });
    expect(isOwnSignInActive()).toBe(false);
    await expect(duringOwnSignIn(async () => Promise.reject(new Error('x')))).rejects.toThrow('x');
    expect(isOwnSignInActive()).toBe(false);
  });
});

describe('shouldReloadFor (reload-loop guard)', () => {
  const fakeSession = () => {
    const store = new Map<string, string>();
    vi.stubGlobal('sessionStorage', {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
  };

  it('allows one reload per target user until cleared', () => {
    fakeSession();
    expect(shouldReloadFor('b')).toBe(true);
    expect(shouldReloadFor('b')).toBe(false);
    expect(shouldReloadFor('c')).toBe(true);
    clearReloadFlag();
    expect(shouldReloadFor('c')).toBe(true);
  });

  it('never reloads without sessionStorage (it could loop forever)', () => {
    vi.stubGlobal('sessionStorage', undefined);
    expect(shouldReloadFor('b')).toBe(false);
  });

  it('never reloads when sessionStorage throws', () => {
    vi.stubGlobal('sessionStorage', {
      getItem: () => {
        throw new Error('blocked');
      },
    });
    expect(shouldReloadFor('b')).toBe(false);
  });
});

describe('beginOwnSignIn / runWhenSignInEnds', () => {
  it('release is idempotent; postponed work runs once when the LAST holder lets go', () => {
    const fn = vi.fn();
    const a = beginOwnSignIn();
    const b = beginOwnSignIn();
    runWhenSignInEnds(fn);
    runWhenSignInEnds(fn); // same function: once
    a();
    a(); // second release of the same holder does nothing
    expect(fn).not.toHaveBeenCalled();
    expect(isOwnSignInActive()).toBe(true);
    b();
    expect(fn).toHaveBeenCalledOnce();
    expect(isOwnSignInActive()).toBe(false);
  });

  it('runs at once when nothing is signing in, and a throwing function does not stop the others', () => {
    const now = vi.fn();
    runWhenSignInEnds(now);
    expect(now).toHaveBeenCalledOnce();
    const ok = vi.fn();
    const release = beginOwnSignIn();
    runWhenSignInEnds(() => {
      throw new Error('boom');
    });
    runWhenSignInEnds(ok);
    release();
    expect(ok).toHaveBeenCalledOnce();
  });
});

describe('readsStraddleUsers', () => {
  const id = (name: string) => ({ tokens: { idToken: { payload: { 'cognito:username': name } } } });
  it('agrees when all three reads are one user', () => {
    expect(readsStraddleUsers(id('a'), { username: 'a', userId: 's1' }, { sub: 's1' })).toBe(false);
  });
  it('detects the session read belonging to another user', () => {
    expect(readsStraddleUsers(id('b'), { username: 'a', userId: 's1' }, { sub: 's1' })).toBe(true);
  });
  it("detects the attributes read belonging to another user (the third read)", () => {
    expect(readsStraddleUsers(id('a'), { username: 'a', userId: 's1' }, { sub: 's2' })).toBe(true);
  });
  it('a missing attribute sub, or a session with no ID token, is not a mismatch', () => {
    expect(readsStraddleUsers(id('a'), { username: 'a', userId: 's1' }, {})).toBe(false);
    expect(readsStraddleUsers({ tokens: {} }, { username: undefined, userId: 's1' }, { sub: 's1' })).toBe(false);
  });
});

describe('createLoadCoordinator', () => {
  it('a caller arriving mid-run gets a follow-up run that started after it asked; the first caller keeps its own result', async () => {
    let state = 'old';
    let release!: () => void;
    const load = vi.fn(async () => {
      const read = state; // what this run saw when it started
      if (load.mock.calls.length === 1) await new Promise<void>((r) => (release = r));
      return read;
    });
    const coordinated = createLoadCoordinator(load);
    const first = coordinated();
    await Promise.resolve();
    state = 'new'; // storage changed while the first load was reading
    const second = coordinated();
    release();
    expect(await first).toBe('old');
    expect(await second).toBe('new'); // not the stale in-flight result
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('runs once for a single request, and again for a later one', async () => {
    const load = vi.fn(async () => 1);
    const coordinated = createLoadCoordinator(load);
    await coordinated();
    expect(load).toHaveBeenCalledTimes(1);
    await coordinated();
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('many joiners share a single follow-up run', async () => {
    let release!: () => void;
    const load = vi.fn(async () => {
      if (load.mock.calls.length === 1) await new Promise<void>((r) => (release = r));
    });
    const coordinated = createLoadCoordinator(load);
    const all = [coordinated(), coordinated(), coordinated(), coordinated()];
    await Promise.resolve();
    release();
    await Promise.all(all);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('a failing follow-up run never rejects the original caller', async () => {
    let release!: () => void;
    const load = vi.fn(async () => {
      if (load.mock.calls.length === 1) {
        await new Promise<void>((r) => (release = r));
        return 'first';
      }
      throw new Error('transient');
    });
    const coordinated = createLoadCoordinator(load);
    const first = coordinated();
    await Promise.resolve();
    const second = coordinated();
    release();
    await expect(first).resolves.toBe('first');
    await expect(second).rejects.toThrow('transient');
  });

  it('a failing first run does not stop a pending joiner getting its own run', async () => {
    let fail!: () => void;
    const load = vi.fn(async () => {
      if (load.mock.calls.length === 1) {
        await new Promise<void>((_, rej) => (fail = () => rej(new Error('boom'))));
      }
      return 'ok';
    });
    const coordinated = createLoadCoordinator(load);
    const first = coordinated();
    await Promise.resolve();
    const second = coordinated();
    fail();
    await expect(first).rejects.toThrow('boom');
    await expect(second).resolves.toBe('ok');
  });

  it('starts fresh after a failure', async () => {
    const load = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValue('ok');
    const coordinated = createLoadCoordinator(load);
    await expect(coordinated()).rejects.toThrow('boom');
    await expect(coordinated()).resolves.toBe('ok');
  });
});
