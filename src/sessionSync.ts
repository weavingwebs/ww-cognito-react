import { isTokenClearingError } from './sessionGuards';
import {
  clearReloadFlag,
  createLoadCoordinator,
  isOwnSignInActive,
  runWhenSignInEnds,
  sessionUsername,
  shouldReloadFor,
  userChangedError,
  type OnUserChange,
  type UserChange,
} from './userChange';

type Session = Parameters<typeof sessionUsername>[0] & { tokens?: unknown };

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

  // For the token getters in strict mode: the session about to be handed out
  // must belong to the user the CALLER was written for (`expected`, bound when
  // its state object was built) and this tab must still show that user. While
  // this tab's own sign-in is running a mismatch throws without reacting: the
  // new user's token must never reach code written for the old one.
  const assertSameUser = (
    session: Session | undefined,
    expected: string | undefined = deps.tabUsername(),
  ): void => {
    const to = sessionUsername(session);
    const tab = deps.tabUsername();
    if (expected && tab !== expected) throw userChangedError();
    if (!expected || !to || expected === to) return;
    if (!isOwnSignInActive()) react({ from: expected, to });
    throw userChangedError();
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

  return { beforeApply, assertSameUser, check, react };
}
