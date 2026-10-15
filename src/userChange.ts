// Detecting that the user stored in this browser is no longer the one this tab
// shows (another tab signed in as someone else), and reacting to it safely.

export const USER_CHANGED_EXCEPTION = 'UserChangedException';

export const isUserChangedError = (err: unknown): err is Error =>
  (err as { name?: unknown } | null | undefined)?.name ===
  USER_CHANGED_EXCEPTION;

export function userChangedError(): Error {
  const err = new Error('The signed-in user changed since this tab loaded');
  err.name = USER_CHANGED_EXCEPTION;
  return err;
}

// The username a session's tokens belong to. ID token first, as that is what
// the tab's user is built from; the access token's `username` claim otherwise.
export function sessionUsername(
  session:
    | {
        tokens?: {
          idToken?: { payload: Record<string, unknown> };
          accessToken?: { payload: Record<string, unknown> };
        };
      }
    | undefined,
): string | undefined {
  const fromId = session?.tokens?.idToken?.payload['cognito:username'];
  if (typeof fromId === 'string') return fromId;
  const fromAccess = session?.tokens?.accessToken?.payload.username;
  return typeof fromAccess === 'string' ? fromAccess : undefined;
}

export type UserChange = {
  // undefined: nobody was signed in (from) / nobody is now (to).
  from: string | undefined;
  to: string | undefined;
};
export type OnUserChange = 'reload' | ((change: UserChange) => void);

// While this tab's own sign-in is running, storage legitimately flips to the
// new user before the tab has loaded them: that must not look like a change.
// It is held only around Amplify's calls and the load that follows, never
// across a user-paced prompt (a long marker would switch the protections off
// while another tab changes user). Work that was skipped meanwhile is run when
// the last holder lets go.
let ownSignIns = 0;
const deferred = new Set<() => void>();

export function beginOwnSignIn(): () => void {
  ownSignIns++;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (--ownSignIns === 0) {
      const run = Array.from(deferred);
      deferred.clear();
      for (const fn of run) {
        try {
          fn();
        } catch {
          // Best-effort.
        }
      }
    }
  };
}

export async function duringOwnSignIn<T>(fn: () => Promise<T>): Promise<T> {
  const release = beginOwnSignIn();
  try {
    return await fn();
  } finally {
    release();
  }
}
export const isOwnSignInActive = (): boolean => ownSignIns > 0;

// Runs `fn` now, or once this tab's sign-in has finished (once per function).
export function runWhenSignInEnds(fn: () => void): void {
  if (ownSignIns === 0) fn();
  else deferred.add(fn);
}

// Reload-loop guard: reload at most once for a given target user until a load
// has settled without a change.
const RELOAD_FLAG = 'ww-cognito-react:user-change-reload';
const flagStorage = (): Storage | null => {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
};

export function shouldReloadFor(to: string | undefined): boolean {
  try {
    const storage = flagStorage();
    // Without storage a reload could loop forever: do not.
    if (!storage) return false;
    const key = to ?? '';
    if (storage.getItem(RELOAD_FLAG) === key) return false;
    storage.setItem(RELOAD_FLAG, key);
    return true;
  } catch {
    return false;
  }
}

export function clearReloadFlag(): void {
  try {
    flagStorage()?.removeItem(RELOAD_FLAG);
  } catch {
    // Best-effort.
  }
}

// Runs `load`, merging concurrent requests. A caller that arrives while a run
// is in progress gets ONE shared follow-up run that starts after it asked, so it
// sees storage at or after that moment (returning the in-flight promise would
// hand a sign-in success the previous user). Each caller only sees the run it
// asked for: a failing follow-up never rejects the original caller.
export function createLoadCoordinator<T>(load: () => Promise<T>) {
  let running: Promise<T> | null = null;
  let next: Promise<T> | null = null;
  const start = (): Promise<T> => {
    const done = () => {
      if (running === run) running = null;
    };
    const run: Promise<T> = load().then(
      (value) => {
        done();
        return value;
      },
      (err: unknown) => {
        done();
        throw err;
      },
    );
    running = run;
    return run;
  };
  return (): Promise<T> => {
    if (!running) return start();
    if (!next) {
      next = running
        .then(
          () => undefined,
          () => undefined,
        )
        .then(() => {
          next = null;
          return start();
        });
    }
    return next;
  };
}

// True when the three reads behind loading a user (session, current user,
// attributes) belong to different people, i.e. another tab switched user
// between them. Compares ID token claims only: getCurrentUser reads the same
// claim, so these cannot differ in steady state.
export function readsStraddleUsers(
  session: { tokens?: { idToken?: { payload: Record<string, unknown> } } },
  authUser: { username?: string; userId?: string },
  attributes: { sub?: string },
): boolean {
  const idUser = session.tokens?.idToken?.payload['cognito:username'];
  if (typeof idUser === 'string' && idUser !== authUser.username) return true;
  return attributes.sub !== undefined && attributes.sub !== authUser.userId;
}
