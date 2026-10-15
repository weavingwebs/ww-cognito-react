// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createSessionSync } from './sessionSync';
import { beginOwnSignIn, duringOwnSignIn, isUserChangedError, type OnUserChange } from './userChange';

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
