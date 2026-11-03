// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FOLLOW_RETRY_MS, createSessionSync } from './sessionSync';
import { beginOwnSignIn, duringOwnSignIn, isUserChangedError, type OnUserChange } from './userChange';

// ID token for `idUser`, access token for `accessUser` (as caught mid-write).
const mixed = (idUser: string, accessUser: string) => ({
  tokens: {
    idToken: { payload: { 'cognito:username': idUser, sub: `sub-${idUser}` } },
    accessToken: { payload: { username: accessUser, sub: `sub-${accessUser}` } },
  },
});

const session = (name: string | null) =>
  name === null
    ? {}
    : { tokens: { idToken: { payload: { 'cognito:username': name } } } };

let tab: string | undefined;
let stored: ReturnType<typeof session>;
let how: OnUserChange | undefined;
const loadUser = vi.fn();
const clearTab = vi.fn();
const reload = vi.fn();
let resurrection = false;
const fetchSession = vi.fn();

const sync = () =>
  createSessionSync({
    fetchSession,
    tabUsername: () => tab,
    loadUser,
    clearTab,
    onUserChange: () => how,
    isResurrection: () => resurrection,
    reload,
  });

beforeEach(() => {
  vi.clearAllMocks();
  tab = 'user-a';
  stored = session('user-a');
  how = 'reload';
  resurrection = false;
  fetchSession.mockImplementation(async () => stored);
  loadUser.mockResolvedValue(undefined);
  const store = new Map<string, string>();
  vi.stubGlobal('sessionStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
});
afterEach(() => vi.unstubAllGlobals());

describe('beforeApply (loading a session into the tab)', () => {
  it('same user, or nobody shown yet: nothing happens', () => {
    sync().beforeApply('user-a');
    tab = undefined;
    sync().beforeApply('user-b');
    expect(reload).not.toHaveBeenCalled();
  });

  it("a different user with 'reload': reloads once and throws UserChangedError", () => {
    const s = sync();
    expect(() => s.beforeApply('user-b')).toThrow(expect.objectContaining({ name: 'UserChangedException' }));
    expect(reload).toHaveBeenCalledOnce();
    expect(() => s.beforeApply('user-b')).toThrow(); // still refuses...
    expect(reload).toHaveBeenCalledOnce(); // ...but never reloads twice
  });

  it('a different user with a callback: calls it with from/to and throws', () => {
    const cb = vi.fn();
    how = cb;
    expect(() => sync().beforeApply('user-b')).toThrow();
    expect(cb).toHaveBeenCalledWith({ from: 'user-a', to: 'user-b' });
    expect(reload).not.toHaveBeenCalled();
  });

  it('no reaction configured: the silent switch of 3.2 is preserved', () => {
    how = undefined;
    expect(() => sync().beforeApply('user-b')).not.toThrow();
    expect(reload).not.toHaveBeenCalled();
  });

  it("this tab's own sign-in is not a user change", async () => {
    await duringOwnSignIn(async () => {
      expect(() => sync().beforeApply('user-b')).not.toThrow();
    });
    expect(reload).not.toHaveBeenCalled();
  });

  it('a throwing callback never breaks the auth flow beyond UserChangedError', () => {
    how = () => {
      throw new Error('consumer bug');
    };
    expect(() => sync().beforeApply('user-b')).toThrow(expect.objectContaining({ name: 'UserChangedException' }));
  });
});

describe('assertSameUser (strict token getters)', () => {
  it('passes for the same user and throws UserChangedError for another', () => {
    const s = sync();
    expect(() => s.assertSameUser(session('user-a'))).not.toThrow();
    try {
      s.assertSameUser(session('user-b'));
      throw new Error('expected a throw');
    } catch (err) {
      expect(isUserChangedError(err)).toBe(true);
    }
    expect(reload).toHaveBeenCalledOnce();
  });

  it('still throws (without reacting) when no reaction is configured', () => {
    how = undefined;
    expect(() => sync().assertSameUser(session('user-b'))).toThrow();
    expect(reload).not.toHaveBeenCalled();
  });

  it("while this tab is signing in, a token for a different user throws WITHOUT reacting (no reload mid sign-in)", async () => {
    await duringOwnSignIn(async () => {
      expect(() => sync().assertSameUser(session('user-b'))).toThrow(
        expect.objectContaining({ name: 'UserChangedException' }),
      );
    });
    expect(reload).not.toHaveBeenCalled();
  });

  it('is bound to the user the CALLER was written for, not whoever the tab shows now', () => {
    tab = 'user-b'; // the tab has since switched to B
    expect(() => sync().assertSameUser(session('user-b'), 'user-a')).toThrow(); // old closure
    expect(() => sync().assertSameUser(session('user-b'), 'user-b')).not.toThrow();
  });

  it('a closure for a user the tab has logged out of cannot get any token', () => {
    tab = undefined;
    expect(() => sync().assertSameUser(session('user-a'), 'user-a')).toThrow();
  });

  it('with no expected user and a logged-out tab there is nothing to compare', () => {
    tab = undefined;
    expect(() => sync().assertSameUser(session('user-b'))).not.toThrow();
  });
});

describe('ownsSession (non-strict token getters)', () => {
  it('true for the same user, false for another, never throwing or reacting', () => {
    const s = sync();
    expect(s.ownsSession(session('user-a'))).toBe(true);
    expect(s.ownsSession(session('user-b'))).toBe(false);
    expect(s.ownsSession(session('user-b'), 'user-a')).toBe(false);
    expect(reload).not.toHaveBeenCalled();
    expect(clearTab).not.toHaveBeenCalled();
  });

  it("false during this tab's own sign-in while storage already holds the new user", async () => {
    await duringOwnSignIn(async () => {
      expect(sync().ownsSession(session('user-b'), 'user-a')).toBe(false);
      expect(sync().ownsSession(session('user-b'))).toBe(false);
    });
    expect(reload).not.toHaveBeenCalled();
  });

  it('is bound to the user the CALLER was written for, not whoever the tab shows now', () => {
    tab = 'user-b';
    expect(sync().ownsSession(session('user-b'), 'user-a')).toBe(false); // old closure
    expect(sync().ownsSession(session('user-b'), 'user-b')).toBe(true);
  });

  it('a closure for a user the tab has logged out of gets no token', () => {
    tab = undefined;
    expect(sync().ownsSession(session('user-a'), 'user-a')).toBe(false);
  });

  it('nothing to compare (logged-out tab, or no username claim) passes as before', () => {
    expect(sync().ownsSession({ tokens: {} }, 'user-a')).toBe(true);
    tab = undefined;
    expect(sync().ownsSession(session('user-b'))).toBe(true);
  });

  it('does not depend on syncTabs / onUserChange being configured', () => {
    how = undefined;
    expect(sync().ownsSession(session('user-b'), 'user-a')).toBe(false);
  });
});

describe('followStoredUser (non-strict getter found another user)', () => {
  const flush = () => new Promise((r) => setTimeout(r, 0));
  // A session for `name` whose access token has its own id (a new sign-in or
  // refresh gives a new one).
  const tokens = (name: string, jti: string) => ({
    tokens: {
      idToken: { payload: { 'cognito:username': name, sub: `sub-${name}` } },
      accessToken: { payload: { username: name, sub: `sub-${name}`, jti } },
    },
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('loads the stored user in the background, once per stored session', async () => {
    const s = sync();
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a'); // polled getter
    await flush();
    expect(loadUser).toHaveBeenCalledOnce();
    expect(reload).not.toHaveBeenCalled(); // the load decides how to react, not the getter
  });

  it('follows the same switch again when it is a new sign-in (A->B, back to A, B again)', async () => {
    const s = sync();
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    // The tab went to B and back to A without the key being cleared by a
    // same-user load; another tab now signs in as B again.
    s.followStoredUser(tokens('user-b', 'b2'), 'user-a');
    await flush();
    expect(loadUser).toHaveBeenCalledTimes(2);
  });

  it('after a failed load (e.g. offline) retries only once FOLLOW_RETRY_MS has passed, not per call', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const s = sync();
    loadUser.mockRejectedValue(new Error('A network error has occurred.'));
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    for (let i = 0; i < 20; i++) s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    expect(loadUser).toHaveBeenCalledOnce();
    vi.setSystemTime(Date.now() + FOLLOW_RETRY_MS);
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    expect(loadUser).toHaveBeenCalledTimes(2);
  });

  it('never repeats a load whose configured reaction already ran (UserChangedException)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const s = sync();
    loadUser.mockRejectedValue(Object.assign(new Error('changed'), { name: 'UserChangedException' }));
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    vi.setSystemTime(Date.now() + FOLLOW_RETRY_MS);
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    expect(loadUser).toHaveBeenCalledOnce();
  });

  it('retries a UserChangedException when no reaction is configured (reads straddled another switch)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    how = undefined;
    const s = sync();
    loadUser.mockRejectedValueOnce(Object.assign(new Error('changed'), { name: 'UserChangedException' }));
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    vi.setSystemTime(Date.now() + FOLLOW_RETRY_MS);
    s.followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    expect(loadUser).toHaveBeenCalledTimes(2);
  });

  it("does nothing during this tab's own sign-in (its own load follows)", async () => {
    await duringOwnSignIn(async () => {
      sync().followStoredUser(tokens('user-b', 'b1'), 'user-a');
      await flush();
    });
    expect(loadUser).not.toHaveBeenCalled();
  });

  it('never adopts a session this tab explicitly logged out of', async () => {
    resurrection = true;
    sync().followStoredUser(tokens('user-b', 'b1'), 'user-a');
    await flush();
    expect(loadUser).not.toHaveBeenCalled();
  });

  it('does nothing for a stale closure, a logged-out tab, no username claim, or a half-written session', async () => {
    tab = 'user-b';
    sync().followStoredUser(session('user-c'), 'user-a'); // closure for A, tab already on B
    tab = undefined;
    sync().followStoredUser(session('user-b'), 'user-a');
    tab = 'user-a';
    sync().followStoredUser({ tokens: {} }, 'user-a');
    sync().followStoredUser(mixed('user-a', 'user-b'), 'user-a');
    await flush();
    expect(loadUser).not.toHaveBeenCalled();
  });
});

describe('mixed sessions (ID token of one user, access token of another)', () => {
  it('never pass: non-strict gets no token, strict throws without reacting', () => {
    expect(sync().ownsSession(mixed('user-a', 'user-b'), 'user-a')).toBe(false);
    expect(() => sync().assertSameUser(mixed('user-a', 'user-b'), 'user-a')).toThrow(
      expect.objectContaining({ name: 'UserChangedException' }),
    );
    expect(reload).not.toHaveBeenCalled();
  });

  it('a consistent session with both tokens passes', () => {
    expect(sync().ownsSession(mixed('user-a', 'user-a'), 'user-a')).toBe(true);
  });
});

describe('reactions', () => {
  it('a refused reload (loop guard) logs the tab out of the old user instead of leaving it', () => {
    const s = sync();
    s.react({ from: 'user-a', to: 'user-b' });
    expect(reload).toHaveBeenCalledOnce();
    s.react({ from: 'user-a', to: 'user-b' });
    expect(reload).toHaveBeenCalledOnce();
    expect(clearTab).toHaveBeenCalledOnce();
  });

  it('the callback form is called once per from->to change, however often it is detected', () => {
    const cb = vi.fn();
    how = cb;
    const s = sync();
    s.react({ from: 'user-a', to: 'user-b' });
    s.react({ from: 'user-a', to: 'user-b' });
    s.react({ from: 'user-a', to: 'user-c' });
    expect(cb).toHaveBeenCalledTimes(2);
  });
});

describe('check (cross-tab events re-read storage)', () => {
  it('signed out elsewhere: logs this tab out (state only)', async () => {
    stored = session(null);
    await sync().check();
    expect(clearTab).toHaveBeenCalledOnce();
  });

  it('a signedOut event while ANOTHER user is current does not log this tab out: it reacts to the switch', async () => {
    // Removing A's refresh key fires signedOut everywhere even though B is current.
    stored = session('user-b');
    await sync().check();
    expect(clearTab).not.toHaveBeenCalled();
    expect(reload).toHaveBeenCalledOnce();
  });

  it('a different user is now stored: reacts', async () => {
    stored = session('user-b');
    await sync().check();
    expect(reload).toHaveBeenCalledOnce();
    expect(loadUser).not.toHaveBeenCalled();
  });

  it('same user (e.g. re-authenticated elsewhere): reloads the claims', async () => {
    await sync().check();
    expect(loadUser).toHaveBeenCalledOnce();
  });

  it('this tab was logged out and someone signed in elsewhere: adopts them', async () => {
    tab = undefined;
    stored = session('user-b');
    await sync().check();
    expect(loadUser).toHaveBeenCalledOnce();
  });

  it('a transient read failure changes nothing', async () => {
    fetchSession.mockRejectedValue(Object.assign(new Error('net'), { name: 'NetworkError' }));
    await sync().check();
    expect(clearTab).not.toHaveBeenCalled();
    expect(loadUser).not.toHaveBeenCalled();
  });

  it('a token-clearing failure means the session is gone: logs the tab out', async () => {
    fetchSession.mockRejectedValue(Object.assign(new Error('x'), { name: 'NotAuthorizedException' }));
    await sync().check();
    expect(clearTab).toHaveBeenCalledOnce();
  });

  it("postpones (does not drop) a check requested during this tab's own sign-in", async () => {
    stored = session(null);
    const s = sync();
    const release = beginOwnSignIn();
    await s.check();
    await s.check(); // twice: still one postponed run
    expect(clearTab).not.toHaveBeenCalled();
    expect(fetchSession).not.toHaveBeenCalled();
    release();
    await vi.waitFor(() => expect(clearTab).toHaveBeenCalledOnce());
    expect(fetchSession).toHaveBeenCalledOnce();
  });

  it('a sign-in that starts while the check is reading discards its stale answer', async () => {
    let release!: () => void;
    fetchSession.mockImplementation(async () => {
      await new Promise<void>((r) => (release = r));
      return session(null);
    });
    const pending = sync().check();
    await Promise.resolve();
    const end = beginOwnSignIn();
    release();
    await pending;
    end();
    expect(clearTab).not.toHaveBeenCalled();
  });

  it('concurrent events (signedOut + signedIn of one switch) share runs', async () => {
    stored = session('user-a');
    const s = sync();
    await Promise.all([s.check(), s.check(), s.check()]);
    expect(fetchSession.mock.calls.length).toBeLessThanOrEqual(2);
  });

  it('never re-adopts the session this tab explicitly logged out of (a refresh in flight elsewhere wrote it back)', async () => {
    tab = undefined;
    stored = session('user-a');
    resurrection = true;
    await sync().check();
    expect(loadUser).not.toHaveBeenCalled();
    resurrection = false; // a genuinely new sign-in
    await sync().check();
    expect(loadUser).toHaveBeenCalledOnce();
  });

  it('the resurrection guard only applies to a logged-out tab', async () => {
    resurrection = true;
    await sync().check(); // tab shows user-a and storage has user-a: refresh claims
    expect(loadUser).toHaveBeenCalledOnce();
  });

  it('a loadUser failure is swallowed (the next event retries)', async () => {
    loadUser.mockRejectedValue(new Error('net'));
    await expect(sync().check()).resolves.toBeUndefined();
  });
});

describe('callback form under strictTokens + syncTabs (wheels saw it fire twice once)', () => {
  it('check(), a strict getter and a load for the same from->to change call it once', async () => {
    const cb = vi.fn();
    how = cb;
    stored = session('user-b');
    const s = sync();
    await s.check(); // cross-tab event
    expect(() => s.assertSameUser(session('user-b'), 'user-a')).toThrow(); // strict getter
    expect(() => s.beforeApply('user-b')).toThrow(); // a load
    await s.check(); // second event of the same switch
    expect(() => s.assertSameUser(session('user-b'), 'user-a')).toThrow();
    expect(cb).toHaveBeenCalledTimes(1);
  });

  it('but a load that finds the tab and storage in agreement re-arms it, so a later change fires again', async () => {
    const cb = vi.fn();
    how = cb;
    const s = sync();
    expect(() => s.beforeApply('user-b')).toThrow();
    s.beforeApply('user-a'); // same user: re-arms
    expect(() => s.beforeApply('user-b')).toThrow();
    expect(cb).toHaveBeenCalledTimes(2);
  });
});
