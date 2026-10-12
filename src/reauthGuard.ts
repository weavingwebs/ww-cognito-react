import { fetchAuthSession } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';

// Re-auth guard (`allowWhileLoggedIn`).
//
// Amplify's `signIn` throws UserAlreadyAuthenticatedException whenever usable
// tokens exist, so a signed-in user cannot re-authenticate (e.g. to reset the
// ID token's `auth_time`) without first signing out, which revokes the
// session. Instead, for the duration of the attempt the token provider is
// pointed at a private in-memory store: `signIn` sees no session, and the real
// (shared, localStorage-backed) storage is never read, cleared or written
// unless the attempt succeeds, when `commit()` copies the new tokens across.
// So a failed or abandoned attempt cannot affect the live session in this tab
// or any other, and other tabs have nothing to misread mid-attempt (hence no
// cross-tab marker).
//
// Verified against aws-amplify 6.20.0: TokenOrchestrator.getTokens reads the
// store on every call (no in-memory token cache) and
// `cognitoUserPoolsTokenProvider.setKeyValueStorage` swaps it. Caveats:
//  - `Amplify.configure` resets the provider's storage to localStorage, so the
//    provider calls reapplyReauthStorage() after configuring.
//  - A refresh of the REAL session already in flight when the guard starts
//    writes its result into whichever store is current when it completes.
//    startGuard() awaits fetchAuthSession() first (settling any refresh this
//    tab needs) but cannot see one started concurrently by other code: a
//    narrow race, documented in the README.
//  - Amplify dispatches its Hub `signedIn` event before commit().
//  - Amplify writes tokens to whichever store is current WHEN A CALL
//    RESOLVES, not when it starts. A rollback (abort, logout, modal closed)
//    that landed mid-call and restored the real storage at once would let the
//    late response write the attempt's tokens into the real session, with no
//    same-user check. So every Amplify call made under the guard is tracked
//    (guard.track) and a rollback requested while one is in flight is
//    DEFERRED: the guard is marked ended (callbacks refuse, commit() throws)
//    but the private store stays installed until the call settles, so its
//    result lands in the store that is then discarded.
//  - An app calling Amplify.configure itself mid-attempt resets the provider
//    to the real storage behind our back. That is detected (the provider no
//    longer points at the attempt store) when a tracked call resolves and at
//    commit, and treated as a failed attempt; apps must not do it.
//  - Amplify's in-memory sign-in challenge state cannot be reset through the
//    public API, so a rolled-back guard makes its challenge callbacks throw
//    (see assertReauthLive) rather than letting them reach Cognito.
//  - commit() re-reads the REAL store after switching back, so a session
//    changed by another tab during the attempt is detected (the live user
//    must still be the one who started it) rather than overwritten, and
//    another user's tokens are cleared, not orphaned, if there was no session
//    at the start.

export const REAUTH_USER_MISMATCH_EXCEPTION = 'ReauthUserMismatchException';
export const REAUTH_ATTEMPT_ENDED_EXCEPTION = 'ReauthAttemptEndedException';

// A guard that nobody settles (no signal, no rollbackPendingReauth) would pin
// this tab to the private store until reload. Cognito's challenge session
// lasts ~3 minutes, so give up after this long without progress.
export const REAUTH_IDLE_TIMEOUT_MS = 5 * 60 * 1000;

export function isReauthUserMismatchError(err: unknown): err is Error {
  return err instanceof Error && err.name === REAUTH_USER_MISMATCH_EXCEPTION;
}

// Thrown by a challenge callback / commit() of an attempt that has been rolled
// back (or whose storage was tampered with).
export function isReauthAttemptEndedError(err: unknown): err is Error {
  return err instanceof Error && err.name === REAUTH_ATTEMPT_ENDED_EXCEPTION;
}

export type ReauthGuard = {
  // Copies the attempt's tokens into the real storage. Rolls back and throws
  // ReauthUserMismatchException if the signed-in user is not the one who
  // started the attempt (or the session changed meanwhile); throws
  // ReauthAttemptEndedException if the attempt was already rolled back. No-op
  // once committed.
  commit: () => Promise<void>;
  // Discards the attempt. The real storage is not written. If an Amplify call
  // is in flight the discard completes (and this resolves) when it settles.
  rollback: () => Promise<void>;
  // Runs one Amplify call (signIn / confirmSignIn) under the guard. If the
  // attempt was rolled back meanwhile, the call's result is discarded and
  // ReauthAttemptEndedException is thrown.
  track: <T>(fn: () => Promise<T>) => Promise<T>;
  // True once committed, committing or rolled back (including a rollback that
  // is waiting for an in-flight call).
  readonly settled: boolean;
};

type KeyValueStorage = ReturnType<
  typeof cognitoUserPoolsTokenProvider.authTokenStore.getKeyValueStorage
>;

type TokenLike = { toString: () => string; payload: Record<string, unknown> };
type TokensLike = { idToken?: TokenLike; accessToken?: TokenLike };

type Snapshot = {
  identity: string | undefined;
  idToken: TokenLike | undefined;
  accessToken: TokenLike | undefined;
};

type ActiveReauth = {
  guard: ReauthGuard;
  // The live session's tokens, captured before the swap. Null when no session
  // existed. Cleared when the attempt settles.
  snapshot: Snapshot | null;
  attemptStorage: KeyValueStorage | null;
  // True once the provider has actually been pointed at the attempt store.
  swapped: boolean;
};

type Phase = 'live' | 'committing' | 'ending' | 'committed' | 'rolledBack';

let active: ActiveReauth | null = null;
const settledListeners = new Set<(outcome: 'commit' | 'rollback') => void>();

export const hasActiveReauth = (): boolean => active !== null;

// Notified after a guard settles (commit or rollback), however that came
// about. Used by the provider to re-check the real session once it is
// visible again.
export function onReauthSettled(
  listener: (outcome: 'commit' | 'rollback') => void,
): () => void {
  settledListeners.add(listener);
  return () => {
    settledListeners.delete(listener);
  };
}

// Same derivation as Amplify's getCurrentUser (`cognito:username` from the ID
// token), falling back to the access token claims. Cognito USERNAME is the
// stable identifier; the email can change mid-session.
function identityOf(tokens: TokensLike | null | undefined): string | undefined {
  const fromId = tokens?.idToken?.payload['cognito:username'];
  if (typeof fromId === 'string' && fromId) return fromId;
  const fromAccess = tokens?.accessToken?.payload.username;
  if (typeof fromAccess === 'string' && fromAccess) return fromAccess;
  const sub = tokens?.idToken?.payload.sub ?? tokens?.accessToken?.payload.sub;
  return typeof sub === 'string' && sub ? sub : undefined;
}

function isUnexpired(token: TokenLike | undefined): boolean {
  const exp = token?.payload.exp;
  return typeof exp === 'number' && exp * 1000 > Date.now();
}

// While a guard is active this tab's provider reads the empty private store,
// so fetchAuthSession() would report no session and every API call made by the
// live page would go out unauthenticated. The JWT getters therefore serve the
// real session's tokens as they were when the guard started, only until they
// expire (never refreshed: refreshing would run against the private store).
// Returns undefined when the real store is in use (no guard, or the swap has
// not happened yet: use fetchAuthSession as usual); null when the snapshot has
// expired or there was no session. Not invalidated by a logout in ANOTHER tab:
// bounded by the token's own expiry and REAUTH_IDLE_TIMEOUT_MS.
export function getGuardedJwt(
  kind: 'idToken' | 'accessToken',
): string | null | undefined {
  if (!active || !active.swapped) return undefined;
  const token = active.snapshot?.[kind];
  return token && isUnexpired(token) ? token.toString() : null;
}

// Amplify.configure resets the provider's storage to localStorage; put the
// attempt store back if a guard is mid-attempt.
export function reapplyReauthStorage(): void {
  if (active?.attemptStorage) {
    cognitoUserPoolsTokenProvider.setKeyValueStorage(active.attemptStorage);
  }
}

// Rolls back any pending re-auth attempt for this tab: abandonment (modal
// closed mid-challenge) or a terminal failure state that will never call
// Cognito again. Safe to call redundantly. Resolves once the real storage is
// back in use (after any in-flight Amplify call has settled).
export async function rollbackPendingReauth(): Promise<void> {
  await active?.guard.rollback();
}

// Amplify persists a pending sign-in challenge (username, challenge name and
// session token) in sessionStorage and only clears it when sign-in completes.
// An abandoned challenge must not leave that behind, where anyone with access
// to the tab could finish signing in as the user. Removes only
// `CognitoSignInState*` keys (the 6.20.0 signInStore prefix). sessionStorage is
// per-tab, so this never affects other tabs.
export function clearPersistedSignInState(): void {
  try {
    Object.keys(sessionStorage)
      .filter((key) => key.indexOf('CognitoSignInState') === 0)
      .forEach((key) => sessionStorage.removeItem(key));
  } catch {
    // Storage unavailable: nothing was persisted.
  }
}

function attemptEnded(message = 'The re-auth attempt has ended'): Error {
  const err = new Error(message);
  err.name = REAUTH_ATTEMPT_ENDED_EXCEPTION;
  return err;
}

function userMismatch(message: string): Error {
  const err = new Error(message);
  err.name = REAUTH_USER_MISMATCH_EXCEPTION;
  return err;
}

// Throws if the guard has been rolled back. Challenge callbacks call this
// first so a stale callback cannot continue an attempt that has been
// discarded (Amplify's in-memory challenge state would still accept it).
export function assertReauthLive(guard: ReauthGuard | null): void {
  if (guard?.settled) throw attemptEnded();
}

// Private in-memory storage for one attempt. Never reused.
function createAttemptStorage(): KeyValueStorage {
  const data = new Map<string, string>();
  return {
    setItem: async (key: string, value: string) => {
      data.set(key, value);
    },
    getItem: async (key: string) => (data.has(key) ? (data.get(key) as string) : null),
    removeItem: async (key: string) => {
      data.delete(key);
    },
    clear: async () => {
      data.clear();
    },
  };
}

function abortError(signal: AbortSignal): Error {
  const reason = (signal as { reason?: unknown }).reason;
  if (reason instanceof Error) return reason;
  const err = new Error('The operation was aborted');
  err.name = 'AbortError';
  return err;
}

function notifySettled(outcome: 'commit' | 'rollback'): void {
  settledListeners.forEach((listener) => {
    try {
      listener(outcome);
    } catch {
      // A listener must not break the settle path.
    }
  });
}

// Runs `run` (a signIn call) against a private store and returns its result.
// If the result is signed in the attempt is committed (see commit()); if it is
// a challenge the live guard is returned and the caller must thread it
// through every confirmSignIn (via guard.track), committing on success and
// rolling back on any failure. Throws if another attempt is in progress or
// the signal is aborted; an abort while the attempt is live rolls it back.
export async function runWithReauthGuard<T extends { isSignedIn: boolean }>(
  run: () => Promise<T>,
  opts?: { signal?: AbortSignal },
): Promise<{ result: T; guard: ReauthGuard | null }> {
  const signal = opts?.signal;
  if (signal?.aborted) throw abortError(signal);

  // Claim the slot SYNCHRONOUSLY, before any await, so two concurrent callers
  // cannot both pass this check.
  if (active) throw new Error('A re-auth attempt is already in progress');

  let phase: Phase = 'live';
  // TypeScript narrows `phase` within a function body; closures mutate it.
  const phaseNow = (): Phase => phase;
  let inflight = 0;
  let onAbort: (() => void) | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let originalStorage: KeyValueStorage | undefined;
  let resolveFinalized: () => void = () => undefined;
  const finalized = new Promise<void>((resolve) => {
    resolveFinalized = resolve;
  });

  const attempt: ActiveReauth = {
    guard: {
      commit: async () => commit(),
      rollback: async () => rollback(),
      track: <R>(fn: () => Promise<R>) => track(fn),
      get settled() {
        return phase !== 'live';
      },
    },
    snapshot: null,
    attemptStorage: null,
    swapped: false,
  };
  active = attempt;

  const { authTokenStore } = cognitoUserPoolsTokenProvider;

  const restoreStorage = () => {
    if (originalStorage) {
      cognitoUserPoolsTokenProvider.setKeyValueStorage(originalStorage);
    }
  };

  const storageIntact = () =>
    authTokenStore.getKeyValueStorage() === attempt.attemptStorage;

  // Releases everything the attempt holds. Token material (the snapshot and
  // the attempt store, which holds the new refresh token) is dropped here.
  const finish = (outcome: 'commit' | 'rollback') => {
    if (timer) clearTimeout(timer);
    if (signal && onAbort) signal.removeEventListener('abort', onAbort);
    attempt.snapshot = null;
    void attempt.attemptStorage?.clear();
    if (active === attempt) active = null;
    notifySettled(outcome);
  };

  // The real storage is back in use and nothing was written to it.
  const finalizeRollback = () => {
    if (phase === 'rolledBack' || phase === 'committed') return;
    restoreStorage();
    clearPersistedSignInState();
    phase = 'rolledBack';
    finish('rollback');
    resolveFinalized();
  };

  const armTimer = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      rollback().catch(() => undefined);
    }, REAUTH_IDLE_TIMEOUT_MS);
  };

  const rollback = async (): Promise<void> => {
    // A commit in progress decides its own fate; it is local-storage fast.
    if (phase === 'committed' || phase === 'committing') return;
    if (phase === 'rolledBack') return;
    if (phase === 'live') phase = 'ending';
    if (inflight === 0) finalizeRollback();
    await finalized;
  };

  // The provider was reset to the real storage while the attempt was live
  // (an Amplify.configure from the app). Anything the attempt wrote may have
  // gone to the real session. If the live user's session is no longer what it
  // was, clear it rather than leave someone else's session in place.
  const compromised = async (): Promise<never> => {
    const liveIdentity = attempt.snapshot?.identity;
    finalizeRollback();
    if (liveIdentity) {
      try {
        const current = await authTokenStore.loadTokens();
        if (identityOf(current as TokensLike | null) !== liveIdentity) {
          await authTokenStore.clearTokens();
        }
      } catch {
        // Best effort.
      }
    }
    throw attemptEnded(
      'The token storage was reconfigured during the re-auth attempt',
    );
  };

  const track = async <R>(fn: () => Promise<R>): Promise<R> => {
    if (phase !== 'live') throw attemptEnded();
    inflight += 1;
    let value: R;
    try {
      value = await fn();
    } catch (err) {
      inflight -= 1;
      if (phaseNow() === 'ending' && inflight === 0) finalizeRollback();
      throw err;
    }
    inflight -= 1;
    if (phaseNow() === 'ending') {
      // Rolled back mid-call: whatever the call produced went to the attempt
      // store (still installed) and is discarded with it.
      if (inflight === 0) finalizeRollback();
      throw attemptEnded();
    }
    if (!storageIntact()) await compromised();
    armTimer();
    return value;
  };

  const commit = async (): Promise<void> => {
    if (phase === 'committed') return;
    if (phase !== 'live') throw attemptEnded();
    phase = 'committing';
    if (!storageIntact()) await compromised();

    let tokens: Awaited<ReturnType<typeof authTokenStore.loadTokens>>;
    try {
      // Read from the attempt store BEFORE switching back.
      tokens = await authTokenStore.loadTokens();
    } catch (err) {
      finalizeRollback();
      throw err;
    }
    const attempted = identityOf(tokens as TokensLike | null);
    if (!tokens || !attempted) {
      finalizeRollback();
      throw new Error('Re-authentication produced no usable tokens');
    }
    const live = attempt.snapshot?.identity;
    if (attempt.snapshot && (!live || live !== attempted)) {
      finalizeRollback();
      throw userMismatch('Re-authentication must be for the signed-in user');
    }

    restoreStorage();
    try {
      // Re-check the REAL store now that it is back: another tab may have
      // changed the session while the attempt was running.
      const current = (await authTokenStore.loadTokens()) as TokensLike | null;
      const currentId = identityOf(current);
      if (attempt.snapshot) {
        if (currentId !== live) {
          throw userMismatch(
            'The signed-in session changed during re-authentication',
          );
        }
      } else if (current && currentId !== attempted) {
        // Someone else signed in (another tab) while we had no session:
        // replace, but do not leave their tokens orphaned.
        await authTokenStore.clearTokens();
      }
      // The only write to the real session.
      await authTokenStore.storeTokens(tokens);
    } catch (err) {
      finalizeRollback();
      throw err;
    }
    phase = 'committed';
    finish('commit');
  };

  try {
    // Snapshot the live session (this also settles any refresh it needs).
    // A throw here (e.g. offline) means we cannot tell a dead session from a
    // live one, so propagate rather than guess; the slot is released below.
    const session = await fetchAuthSession();
    if (signal?.aborted) throw abortError(signal);
    if (session.tokens) {
      attempt.snapshot = {
        identity: identityOf(session.tokens as TokensLike),
        idToken: session.tokens.idToken as TokenLike | undefined,
        accessToken: session.tokens.accessToken as TokenLike | undefined,
      };
    }

    // From here to the swap there must be no await.
    originalStorage = authTokenStore.getKeyValueStorage();
    attempt.attemptStorage = createAttemptStorage();
    cognitoUserPoolsTokenProvider.setKeyValueStorage(attempt.attemptStorage);
    attempt.swapped = true;
    if (signal) {
      onAbort = () => {
        rollback().catch(() => undefined);
      };
      signal.addEventListener('abort', onAbort);
    }
    armTimer();
  } catch (err) {
    finalizeRollback();
    throw err;
  }

  try {
    const result = await attempt.guard.track(run);
    if (result.isSignedIn) {
      await attempt.guard.commit();
      return { result, guard: null };
    }
    return { result, guard: attempt.guard };
  } catch (err) {
    await attempt.guard.rollback();
    throw err;
  }
}
