import { isTokenClearingError } from './sessionGuards';
import {
  clearReloadFlag,
  createLoadCoordinator,
  isOwnSignInActive,
  isUserChangedError,
  runWhenSignInEnds,
  sessionUsername,
  shouldReloadFor,
  userChangedError,
  type OnUserChange,
  type UserChange,
} from './userChange';

type Session = Parameters<typeof sessionUsername>[0] & { tokens?: unknown };

// After a follow-up load fails (offline, a revoked session, ...), how long a
// non-strict getter waits before it may start another one.
export const FOLLOW_RETRY_MS = 30_000;

// The two tokens of one session are written separately, so a reader can catch
// another user's access token next to the previous ID token (the storage
// prefix is the login name with USER_PASSWORD_AUTH, which two people can share
// over time). `sub` is in both tokens.
const tokensDisagree = (session: Session | undefined): boolean => {
  const idSub = session?.tokens?.idToken?.payload.sub;
  const accessSub = session?.tokens?.accessToken?.payload.sub;
  return (
    typeof idSub === 'string' && typeof accessSub === 'string' && idSub !== accessSub
  );
};

const tokenId = (session: Session | undefined): string => {
  const payload = session?.tokens?.accessToken?.payload;
  return String(payload?.jti ?? payload?.iat ?? '');
};

// Keeps one tab in step with the session in storage. All the logic lives here
// (not in the provider) so it can be tested without a React tree.
export function createSessionSync(deps: {
  fetchSession: () => Promise<Session>;
  // The user this tab shows; undefined when logged out.
  tabUsername: () => string | undefined;
  // Loads the stored session into this tab (already coalesced).
  loadUser: () => Promise<unknown>;
  // Marks this tab logged out (state only, never signOut).
  clearTab: () => void;
  // undefined: detect but do not react (getters may still throw).
  onUserChange: () => OnUserChange | undefined;
  // True for a session this tab explicitly logged out of (a refresh that was
  // in flight in another tab can write it back): never adopt it again.
  isResurrection?: (session: Session) => boolean;
  reload?: () => void;
}) {
  const reload =
    deps.reload ??
    (() => {
      if (typeof window !== 'undefined') window.location.reload();
    });

  // One reaction per from->to change: a strict getter polled in a loop, or the
  // signedOut + signedIn pair one switch produces, must not call a consumer's
  // callback over and over.
  let lastReacted: string | undefined;
  // Likewise one follow-up load per stored session a non-strict getter finds
  // to be another user's (keyed on its token, so a new sign-in is followed
  // again), and after a failed load at most one retry per FOLLOW_RETRY_MS: a
  // polled getter must never turn into a Cognito call per request.
  let followed: { key: string; retryAt?: number } | undefined;

  // Never throws: a consumer callback must not break the auth flow.
  const react = (change: UserChange): void => {
    const how = deps.onUserChange();
    const key = `${change.from}→${change.to}`;
    try {
      if (how === 'reload') {
        if (shouldReloadFor(change.to)) {
          reload();
        } else {
          // Reload refused (already tried for this user, or no sessionStorage
          // to guard against a loop): at least stop presenting the old user.
          deps.clearTab();
        }
      } else if (typeof how === 'function' && lastReacted !== key) {
        lastReacted = key;
        how(change);
      }
    } catch {
      // Ignore.
    }
  };

  // Called by loadUserFromSession before it applies a session. Throws
  // UserChangedError (after reacting) when the tab would silently switch user
  // and a reaction is configured; with no reaction configured the switch goes
  // ahead, as it always did.
  const beforeApply = (to: string | undefined): void => {
    const from = deps.tabUsername();
    if (isOwnSignInActive() || !from || !to || from === to) {
      if (from === to || !from) {
        clearReloadFlag();
        lastReacted = undefined;
      }
      return;
    }
    if (deps.onUserChange() === undefined) return;
    react({ from, to });
    throw userChangedError();
  };

  // The one rule for every token getter: the session about to be handed out
  // must belong to the user the CALLER was written for (`expected`, bound when
  // its state object was built) and this tab must still show that user.
  // undefined: it does (or there is nothing to compare). 'stale': the tab has
  // moved on from `expected` (a closure holding an old state). 'mixed': the
  // two tokens belong to different users (caught mid-write). Otherwise the
  // stored session is another user's.
  const tokenMismatch = (
    session: Session | undefined,
    expected: string | undefined,
  ): UserChange | 'stale' | 'mixed' | undefined => {
    if (expected && deps.tabUsername() !== expected) return 'stale';
    if (expected && tokensDisagree(session)) return 'mixed';
    const to = sessionUsername(session);
    if (!expected || !to || expected === to) return undefined;
    return { from: expected, to };
  };

  // Strict getters: throw on any mismatch. While this tab's own sign-in is
  // running it throws without reacting: the new user's token must never reach
  // code written for the old one.
  const assertSameUser = (
    session: Session | undefined,
    expected: string | undefined = deps.tabUsername(),
  ): void => {
    const mismatch = tokenMismatch(session, expected);
    if (!mismatch) return;
    if (typeof mismatch === 'object' && !isOwnSignInActive()) react(mismatch);
    throw userChangedError();
  };

  // Non-strict getters: the same rule, but it never throws or reacts, so the
  // getter can return null (fail closed) while keeping its "null for any
  // failure" contract.
  const ownsSession = (
    session: Session | undefined,
    expected: string | undefined = deps.tabUsername(),
  ): boolean => tokenMismatch(session, expected) === undefined;

  // For the non-strict getters after ownsSession said no: bring the tab in step
  // with storage in the background, so it does not sit on the old user handing
  // out nulls. The load runs beforeApply, so the configured reaction happens,
  // or with none the tab switches user (as its next load always did). Skipped
  // during this tab's own sign-in (its own load follows), for a closure whose
  // tab has already moved on, for a half-written session, and for a session
  // this tab explicitly logged out of.
  const followStoredUser = (
    session: Session | undefined,
    expected: string | undefined = deps.tabUsername(),
  ): void => {
    const mismatch = tokenMismatch(session, expected);
    if (typeof mismatch !== 'object' || isOwnSignInActive()) return;
    if (session && deps.isResurrection?.(session)) return;
    const key = `${mismatch.from}→${mismatch.to}:${tokenId(session)}`;
    if (
      followed?.key === key &&
      (followed.retryAt === undefined || Date.now() < followed.retryAt)
    ) {
      return;
    }
    const entry: { key: string; retryAt?: number } = { key };
    followed = entry;
    Promise.resolve()
      .then(deps.loadUser)
      .catch((err) => {
        // A configured reaction already ran: never repeat it. Anything else
        // (offline, revoked, reads straddling another switch) may be retried.
        if (isUserChangedError(err) && deps.onUserChange() !== undefined) return;
        entry.retryAt = Date.now() + FOLLOW_RETRY_MS;
      });
  };

  // Re-reads storage rather than trusting an event: removing one user's refresh
  // key fires `signedOut` in every tab even when another user is now current.
  const checkRaw = async (): Promise<void> => {
    let session: Session | undefined;
    try {
      session = await deps.fetchSession();
    } catch (err) {
      // Dead tokens are cleared by Amplify; anything else is transient.
      if (!isTokenClearingError(err)) return;
    }
    if (isOwnSignInActive()) return;
    if (!session?.tokens) {
      if (deps.tabUsername() !== undefined) deps.clearTab();
      return;
    }
    const from = deps.tabUsername();
    const to = sessionUsername(session);
    if (from && to && from !== to) {
      react({ from, to });
      return;
    }
    // Same user (fresh claims after a re-auth/refresh elsewhere) or someone
    // signed in elsewhere while this tab was logged out: adopt it, unless it is
    // the session this tab just logged out of coming back.
    if (!from && deps.isResurrection?.(session)) return;
    try {
      await deps.loadUser();
    } catch {
      // A UserChanged was already reacted to; transient errors retry later.
    }
  };
  const coalesced = createLoadCoordinator(checkRaw);

  // Concurrent events (one switch fires signedOut and signedIn) share runs.
  // While this tab is signing in the check is postponed, not dropped.
  const runPostponed = () => void coalesced(); // one identity: postponed once
  const check = (): Promise<void> => {
    if (isOwnSignInActive()) {
      runWhenSignInEnds(runPostponed);
      return Promise.resolve();
    }
    return coalesced();
  };

  return {
    beforeApply,
    assertSameUser,
    ownsSession,
    followStoredUser,
    check,
    react,
  };
}
