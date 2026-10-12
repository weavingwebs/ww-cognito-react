import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// A fake token provider whose store reads/writes whatever storage is current,
// like Amplify's DefaultTokenStore.
const h = vi.hoisted(() => {
  type Storage = {
    data: Map<string, unknown>;
    writes: number;
    setItem: (k: string, v: unknown) => Promise<void>;
    getItem: (k: string) => Promise<unknown>;
    removeItem: (k: string) => Promise<void>;
    clear: () => Promise<void>;
  };
  const makeStorage = (): Storage => {
    const s: Storage = {
      data: new Map(),
      writes: 0,
      setItem: async (k, v) => {
        s.writes += 1;
        s.data.set(k, v);
      },
      getItem: async (k) => (s.data.has(k) ? s.data.get(k) : null),
      removeItem: async (k) => {
        s.writes += 1;
        s.data.delete(k);
      },
      clear: async () => {
        s.writes += 1;
        s.data.clear();
      },
    };
    return s;
  };
  const state = { current: makeStorage() as Storage };
  const provider = {
    authTokenStore: {
      getKeyValueStorage: () => state.current,
      loadTokens: async () => state.current.getItem('tokens'),
      storeTokens: async (t: unknown) => state.current.setItem('tokens', t),
      clearTokens: async () => state.current.removeItem('tokens'),
    },
    setKeyValueStorage: (s: Storage) => {
      state.current = s;
    },
  };
  return { makeStorage, state, provider };
});

vi.mock('aws-amplify/auth', () => ({ fetchAuthSession: vi.fn() }));
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: h.provider,
}));

import { fetchAuthSession } from 'aws-amplify/auth';
import {
  REAUTH_IDLE_TIMEOUT_MS,
  assertReauthLive,
  isReauthAttemptEndedError,
  clearPersistedSignInState,
  getGuardedJwt,
  hasActiveReauth,
  isReauthUserMismatchError,
  onReauthSettled,
  reapplyReauthStorage,
  rollbackPendingReauth,
  runWithReauthGuard,
} from './reauthGuard';

const future = () => Math.floor(Date.now() / 1000) + 3600;
const past = () => Math.floor(Date.now() / 1000) - 10;

const tokens = (username: string, exp = future(), label = username) => ({
  idToken: {
    payload: { 'cognito:username': username, sub: username, exp },
    toString: () => `id-${label}`,
  },
  accessToken: {
    payload: { username, sub: username, exp },
    toString: () => `access-${label}`,
  },
});

let real: ReturnType<typeof h.makeStorage>;
const withSession = (t = tokens('u1', future(), 'live')) => {
  real.data.set('tokens', t);
  real.writes = 0;
  vi.mocked(fetchAuthSession).mockResolvedValue({ tokens: t } as never);
};

// What a successful Amplify signIn does: write tokens via the provider.
const signInAs = (t: ReturnType<typeof tokens>, isSignedIn = true) => async () => {
  await h.provider.authTokenStore.storeTokens(t);
  return { isSignedIn };
};

beforeEach(() => {
  vi.clearAllMocks();
  real = h.makeStorage();
  h.state.current = real;
  vi.mocked(fetchAuthSession).mockResolvedValue({} as never);
});

afterEach(async () => {
  await rollbackPendingReauth();
  vi.unstubAllGlobals();
});

describe('runWithReauthGuard', () => {
  it('no session: behaves like a plain login (commits to real storage, no user check)', async () => {
    const t = tokens('u2');
    const { result, guard } = await runWithReauthGuard(signInAs(t));
    expect(result.isSignedIn).toBe(true);
    expect(guard).toBeNull();
    expect(real.data.get('tokens')).toBe(t);
    expect(h.state.current).toBe(real);
    expect(hasActiveReauth()).toBe(false);
  });

  it('with a session: real storage is not touched mid-attempt, then receives the new tokens on success', async () => {
    withSession();
    const fresh = tokens('u1', future(), 'fresh');
    let midAttempt: { writes: number; usingReal: boolean } | undefined;
    const { result, guard } = await runWithReauthGuard(async () => {
      const out = await signInAs(fresh)();
      midAttempt = { writes: real.writes, usingReal: h.state.current === real };
      return out;
    });
    expect(midAttempt).toEqual({ writes: 0, usingReal: false });
    expect(result.isSignedIn).toBe(true);
    expect(guard).toBeNull();
    expect(real.data.get('tokens')).toBe(fresh);
    expect(h.state.current).toBe(real);
  });

  it('a challenge returns a live guard; commit() then copies the tokens across', async () => {
    withSession();
    const fresh = tokens('u1', future(), 'fresh');
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    expect(guard).not.toBeNull();
    expect(hasActiveReauth()).toBe(true);
    expect(real.writes).toBe(0);
    await h.provider.authTokenStore.storeTokens(fresh); // confirmSignIn success
    await guard!.commit();
    expect(real.data.get('tokens')).toBe(fresh);
    expect(h.state.current).toBe(real);
    expect(hasActiveReauth()).toBe(false);
  });

  it('rollback() leaves the real session untouched and clears CognitoSignInState', async () => {
    const store = new Map<string, string>([
      ['CognitoSignInState.username', 'a'],
      ['other', 'b'],
    ]);
    vi.stubGlobal('sessionStorage', fakeSessionStorage(store));
    const live = tokens('u1', future(), 'live');
    withSession(live);
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    await guard!.rollback();
    expect(real.writes).toBe(0);
    expect(real.data.get('tokens')).toBe(live);
    expect(h.state.current).toBe(real);
    expect(hasActiveReauth()).toBe(false);
    expect(Array.from(store.keys())).toEqual(['other']);
  });

  it('a throw from run() rolls back and rethrows', async () => {
    withSession();
    const boom = new Error('NotAuthorizedException');
    await expect(
      runWithReauthGuard(async () => {
        throw boom;
      }),
    ).rejects.toBe(boom);
    expect(h.state.current).toBe(real);
    expect(real.writes).toBe(0);
    expect(hasActiveReauth()).toBe(false);
  });

  it('a concurrent second attempt throws and does not disturb the first', async () => {
    withSession();
    const first = runWithReauthGuard(async () => ({ isSignedIn: false }));
    await expect(
      runWithReauthGuard(async () => ({ isSignedIn: true })),
    ).rejects.toThrow('already in progress');
    const { guard } = await first;
    expect(guard).not.toBeNull();
    expect(hasActiveReauth()).toBe(true);
  });

  it('an already-aborted signal installs no guard', async () => {
    withSession();
    const ctrl = new AbortController();
    ctrl.abort();
    const run = vi.fn();
    await expect(runWithReauthGuard(run, { signal: ctrl.signal })).rejects.toBeTruthy();
    expect(run).not.toHaveBeenCalled();
    expect(hasActiveReauth()).toBe(false);
    expect(h.state.current).toBe(real);
  });

  it('aborting mid-attempt rolls the guard back', async () => {
    withSession();
    const ctrl = new AbortController();
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }), {
      signal: ctrl.signal,
    });
    ctrl.abort();
    await Promise.resolve();
    expect(guard!.settled).toBe(true);
    expect(hasActiveReauth()).toBe(false);
    expect(h.state.current).toBe(real);
  });

  it('aborting during the session snapshot installs no guard', async () => {
    const ctrl = new AbortController();
    vi.mocked(fetchAuthSession).mockImplementation(async () => {
      ctrl.abort();
      return {} as never;
    });
    const run = vi.fn();
    await expect(runWithReauthGuard(run, { signal: ctrl.signal })).rejects.toBeTruthy();
    expect(run).not.toHaveBeenCalled();
    expect(hasActiveReauth()).toBe(false);
    expect(h.state.current).toBe(real);
  });

  it('releases the slot if the session snapshot fails', async () => {
    const boom = new Error('network');
    vi.mocked(fetchAuthSession).mockRejectedValueOnce(boom);
    await expect(runWithReauthGuard(async () => ({ isSignedIn: true }))).rejects.toBe(boom);
    expect(hasActiveReauth()).toBe(false);
    expect(h.state.current).toBe(real);
  });

  it('commit() and rollback() are idempotent and settled guards refuse challenge callbacks', async () => {
    withSession();
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    expect(() => assertReauthLive(guard)).not.toThrow();
    await guard!.rollback();
    await guard!.rollback();
    // commit() on a rolled-back guard must fail loudly, not look like success
    expect(isReauthAttemptEndedError(await guard!.commit().catch((e) => e))).toBe(true);
    expect(real.writes).toBe(0);
    expect(() => assertReauthLive(guard)).toThrow('re-auth attempt has ended');
    expect(() => assertReauthLive(null)).not.toThrow();
  });

  it('notifies settle listeners with the outcome', async () => {
    withSession();
    const seen: string[] = [];
    const stop = onReauthSettled((o) => seen.push(o));
    await runWithReauthGuard(signInAs(tokens('u1')));
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    await guard!.rollback();
    stop();
    expect(seen).toEqual(['commit', 'rollback']);
  });

  it('reapplyReauthStorage() puts the attempt store back after a reconfigure', async () => {
    withSession();
    await runWithReauthGuard(async () => ({ isSignedIn: false }));
    const attempt = h.state.current;
    h.provider.setKeyValueStorage(real); // what Amplify.configure does
    reapplyReauthStorage();
    expect(h.state.current).toBe(attempt);
    expect(h.state.current).not.toBe(real);
  });
});

describe('same-user rule', () => {
  it('rolls back and throws ReauthUserMismatchException for a different user, before anything is written', async () => {
    const live = tokens('u1', future(), 'live');
    withSession(live);
    const err = await runWithReauthGuard(signInAs(tokens('u2'))).catch((e) => e);
    expect(isReauthUserMismatchError(err)).toBe(true);
    expect(real.writes).toBe(0);
    expect(real.data.get('tokens')).toBe(live);
    expect(h.state.current).toBe(real);
    expect(hasActiveReauth()).toBe(false);
  });

  it('also enforces it when the mismatch is found on a later challenge step', async () => {
    const live = tokens('u1', future(), 'live');
    withSession(live);
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    await h.provider.authTokenStore.storeTokens(tokens('u2'));
    const err = await guard!.commit().catch((e) => e);
    expect(isReauthUserMismatchError(err)).toBe(true);
    expect(real.data.get('tokens')).toBe(live);
    expect(guard!.settled).toBe(true);
  });

  it('compares the username, not the email: same user with a changed email passes', async () => {
    withSession(tokens('u1', future(), 'live'));
    const fresh = tokens('u1', future(), 'fresh');
    (fresh.idToken.payload as Record<string, unknown>).email = 'new@example.com';
    await runWithReauthGuard(signInAs(fresh));
    expect(real.data.get('tokens')).toBe(fresh);
  });

  it('fails closed if the attempt has no identifiable user', async () => {
    withSession();
    const anonymous = { idToken: { payload: {}, toString: () => 'x' } };
    const err = await runWithReauthGuard(signInAs(anonymous as never)).catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(real.writes).toBe(0);
    expect(h.state.current).toBe(real);
  });
});

describe('getGuardedJwt', () => {
  it('is undefined with no guard', () => {
    expect(getGuardedJwt('idToken')).toBeUndefined();
  });

  it('serves the live session snapshot during the guard, then the real store again', async () => {
    withSession(tokens('u1', future(), 'live'));
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    expect(getGuardedJwt('idToken')).toBe('id-live');
    expect(getGuardedJwt('accessToken')).toBe('access-live');
    await guard!.rollback();
    expect(getGuardedJwt('idToken')).toBeUndefined();
  });

  it('returns null once the snapshot has expired (never refreshed)', async () => {
    withSession(tokens('u1', past(), 'old'));
    await runWithReauthGuard(async () => ({ isSignedIn: false }));
    expect(getGuardedJwt('idToken')).toBeNull();
    expect(getGuardedJwt('accessToken')).toBeNull();
  });

  it('returns null during a guard that started with no session', async () => {
    await runWithReauthGuard(async () => ({ isSignedIn: false }));
    expect(getGuardedJwt('idToken')).toBeNull();
  });

  it('serves the new tokens (via undefined -> real store) immediately after commit', async () => {
    withSession(tokens('u1', future(), 'live'));
    await runWithReauthGuard(signInAs(tokens('u1', future(), 'fresh')));
    expect(getGuardedJwt('idToken')).toBeUndefined();
    expect(real.data.get('tokens')).toMatchObject({
      idToken: { payload: { 'cognito:username': 'u1' } },
    });
  });
});

describe('clearPersistedSignInState', () => {
  it('removes only CognitoSignInState* keys', () => {
    const store = new Map<string, string>([
      ['CognitoSignInState.username', 'a'],
      ['CognitoSignInState.signInSession', 'b'],
      ['CognitoIdentityServiceProvider.x.LastAuthUser', 'c'],
      ['unrelated', 'd'],
    ]);
    vi.stubGlobal('sessionStorage', fakeSessionStorage(store));
    clearPersistedSignInState();
    expect(Array.from(store.keys()).sort()).toEqual([
      'CognitoIdentityServiceProvider.x.LastAuthUser',
      'unrelated',
    ]);
  });

  it('does not throw when sessionStorage is unavailable', () => {
    vi.stubGlobal('sessionStorage', undefined);
    expect(() => clearPersistedSignInState()).not.toThrow();
  });
});

// Object.keys(sessionStorage) lists stored keys; methods are non-enumerable.
function fakeSessionStorage(store: Map<string, string>) {
  const obj: Record<string, string> = {};
  store.forEach((v, k) => {
    obj[k] = v;
  });
  Object.defineProperty(obj, 'removeItem', {
    enumerable: false,
    value: (k: string) => {
      delete obj[k];
      store.delete(k);
    },
  });
  return obj;
}

// A deferred promise, to hold an Amplify call "in flight".
const deferred = <T>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};
const tick = () => new Promise((r) => setTimeout(r, 0));

describe('rollback while an Amplify call is in flight', () => {
  it('abort mid-signIn: the late response lands in the discarded store, never the real one', async () => {
    withSession(tokens('u1', future(), 'live'));
    const ctrl = new AbortController();
    const reply = deferred<{ isSignedIn: boolean }>();
    const attempt = runWithReauthGuard(async () => {
      const out = await reply.promise;
      // Amplify writes at resolve time, to whichever store is current.
      await h.provider.authTokenStore.storeTokens(tokens('mallory'));
      return out;
    }, { signal: ctrl.signal });
    const settled = attempt.catch((e) => e);
    await tick();
    ctrl.abort();
    await tick();
    // Deferred: the private store must still be installed while the call is out.
    expect(h.state.current).not.toBe(real);
    expect(hasActiveReauth()).toBe(true);
    reply.resolve({ isSignedIn: true });
    const err = await settled;
    expect(isReauthAttemptEndedError(err)).toBe(true);
    expect(real.writes).toBe(0);
    expect(real.data.get('tokens')).toMatchObject({ idToken: { payload: { sub: 'u1' } } });
    expect(h.state.current).toBe(real);
    expect(hasActiveReauth()).toBe(false);
  });

  it('abort mid-confirmSignIn: result discarded, callbacks throw, real untouched', async () => {
    withSession(tokens('u1', future(), 'live'));
    const ctrl = new AbortController();
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }), {
      signal: ctrl.signal,
    });
    const reply = deferred<{ isSignedIn: boolean }>();
    const step = guard!
      .track(async () => {
        const out = await reply.promise;
        await h.provider.authTokenStore.storeTokens(tokens('mallory'));
        return out;
      })
      .catch((e) => e);
    await tick();
    ctrl.abort();
    await tick();
    expect(guard!.settled).toBe(true);
    expect(h.state.current).not.toBe(real);
    reply.resolve({ isSignedIn: true });
    expect(isReauthAttemptEndedError(await step)).toBe(true);
    expect(real.writes).toBe(0);
    expect(h.state.current).toBe(real);
    expect(isReauthAttemptEndedError(await guard!.commit().catch((e) => e))).toBe(true);
  });

  it('rollback() resolves only once the in-flight call has settled (logout waits for it)', async () => {
    withSession();
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    const reply = deferred<{ isSignedIn: boolean }>();
    const step = guard!.track(() => reply.promise).catch((e) => e);
    await tick();
    let done = false;
    const rolling = rollbackPendingReauth().then(() => {
      done = true;
    });
    await tick();
    expect(done).toBe(false);
    reply.reject(Object.assign(new Error('boom'), { name: 'NetworkError' }));
    await rolling;
    expect((await step).name).toBe('NetworkError');
    expect(done).toBe(true);
    expect(h.state.current).toBe(real);
  });

  it('clears persisted sign-in state again after a late challenge response re-persists it', async () => {
    const store = new Map<string, string>();
    vi.stubGlobal('sessionStorage', fakeSessionStorage(store));
    withSession();
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    const reply = deferred<void>();
    const step = guard!.track(() => reply.promise).catch((e) => e);
    await tick();
    const rolling = guard!.rollback();
    store.set('CognitoSignInState.signInSession', 'late'); // Amplify re-persists
    const live = sessionStorage as unknown as Record<string, string>;
    live['CognitoSignInState.signInSession'] = 'late';
    reply.resolve();
    await step;
    await rolling;
    expect(Object.keys(sessionStorage as object)).not.toContain('CognitoSignInState.signInSession');
  });
});

describe('commit re-verifies the real store', () => {
  it('another tab switched the session mid-attempt: rolls back with a mismatch, leaves the other session alone', async () => {
    withSession(tokens('u1', future(), 'live'));
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    await h.provider.authTokenStore.storeTokens(tokens('u1', future(), 'fresh'));
    const other = tokens('u3', future(), 'other-tab');
    real.data.set('tokens', other); // tab 2 signed in as someone else
    real.writes = 0;
    const err = await guard!.commit().catch((e) => e);
    expect(isReauthUserMismatchError(err)).toBe(true);
    expect(real.data.get('tokens')).toBe(other);
    expect(real.writes).toBe(0);
  });

  it('another tab logged out mid-attempt: the logout is not undone', async () => {
    withSession(tokens('u1', future(), 'live'));
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    await h.provider.authTokenStore.storeTokens(tokens('u1', future(), 'fresh'));
    real.data.delete('tokens');
    real.writes = 0;
    const err = await guard!.commit().catch((e) => e);
    expect(isReauthUserMismatchError(err)).toBe(true);
    expect(real.data.has('tokens')).toBe(false);
    expect(real.writes).toBe(0);
  });

  it('no session at the start but another tab signed in meanwhile: that user is cleared, not orphaned', async () => {
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    const fresh = tokens('u2');
    await h.provider.authTokenStore.storeTokens(fresh);
    real.data.set('tokens', tokens('u3', future(), 'other-tab'));
    await guard!.commit();
    expect(real.data.get('tokens')).toBe(fresh);
  });

  it('Amplify.configure mid-attempt is detected and the live session is not left as someone else', async () => {
    withSession(tokens('u1', future(), 'live'));
    const err = await runWithReauthGuard(async () => {
      h.provider.setKeyValueStorage(real); // app called Amplify.configure
      await h.provider.authTokenStore.storeTokens(tokens('mallory'));
      return { isSignedIn: false };
    }).catch((e) => e);
    expect(isReauthAttemptEndedError(err)).toBe(true);
    expect(real.data.has('tokens')).toBe(false); // mallory's session is not left in place
    expect(hasActiveReauth()).toBe(false);
  });
});

describe('lifecycle', () => {
  it('rolls back by itself after the idle timeout', async () => {
    vi.useFakeTimers();
    try {
      withSession();
      const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
      vi.advanceTimersByTime(REAUTH_IDLE_TIMEOUT_MS + 1);
      await Promise.resolve();
      expect(guard!.settled).toBe(true);
      expect(hasActiveReauth()).toBe(false);
      expect(h.state.current).toBe(real);
    } finally {
      vi.useRealTimers();
    }
  });

  it('serves nothing from the guard until the swap has happened', async () => {
    withSession();
    const gate = deferred<unknown>();
    vi.mocked(fetchAuthSession).mockReturnValueOnce(gate.promise as never);
    const attempt = runWithReauthGuard(async () => ({ isSignedIn: false }));
    expect(hasActiveReauth()).toBe(true);
    expect(getGuardedJwt('idToken')).toBeUndefined();
    gate.resolve({ tokens: tokens('u1', future(), 'live') });
    await attempt;
    expect(getGuardedJwt('idToken')).toBe('id-live');
  });

  it('drops token material from the attempt store when it settles', async () => {
    withSession();
    const { guard } = await runWithReauthGuard(async () => ({ isSignedIn: false }));
    const attemptStore = h.state.current;
    await h.provider.authTokenStore.storeTokens(tokens('u1', future(), 'fresh'));
    expect(await attemptStore.getItem('tokens')).not.toBeNull();
    await guard!.rollback();
    expect(await attemptStore.getItem('tokens')).toBeNull();
  });
});
