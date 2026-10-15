## Example usage

```tsx
import { createCognitoAuth, forceSignOut } from '@weavingwebs/ww-cognito-react';
import type { AuthUser, FetchUserAttributesOutput } from 'aws-amplify/auth';

type User = { id: string; email: string };

function buildUser(authUser: AuthUser, attributes: FetchUserAttributesOutput): User {
  const email = attributes.email;
  if (!email) {
    throw new Error('Email not found in attributes');
  }
  return { id: authUser.userId, email };
}

const { useAuthContext, useAuthContextOrDie, AuthContext, AuthProvider } =
  createCognitoAuth(buildUser);
export { useAuthContext, useAuthContextOrDie, AuthContext, AuthProvider, forceSignOut };
```

```tsx
<AuthProvider userPool={{ userPoolId: 'eu-west-2_xxx', userPoolClientId: 'xxx' }}>
  <App />
</AuthProvider>
```

`buildUser` must be pure: fully reconstruct the returned object from `attributes` on every call, never
conditionally omit a field, and never mutate/reuse a previous return value - see "Stable user identity"
below for why.

Do not use `authUser.signInDetails.loginId` in `buildUser`. It is not a user attribute, just the string that was
passed to Amplify's `signIn` last time: the email as typed at login (stale after `updateEmail`), or the Cognito
username after `reauthenticate`. Use `attributes.email` and `authUser.userId` / `authUser.username` instead.

## MFA preference and existing sessions (3.1.0)

```ts
import {
  fetchMfaPreference,
  setTotpPreference,
  isAlreadySignedInError,
} from '@weavingwebs/ww-cognito-react';

// Both need a signed-in user (they also work straight after an MFA_SETUP sign in).
await setTotpPreference('PREFERRED'); // or 'DISABLED'
const { enabled, preferred } = await fetchMfaPreference();

// Inside a component: const auth = useAuthContext(); (auth.authenticate exists once isLoggedIn !== null)
// Don't replace an existing valid session:
try {
  await auth.authenticate(email, pass, { onExistingSession: 'reject' });
} catch (err) {
  if (isAlreadySignedInError(err)) {
    /* a session already exists (possibly another user); redirect based on context state */
  }
}
```

`onExistingSession` defaults to `'replace'`: the new login replaces whatever session is stored. Since 3.3.0 it signs in
again *without* signing out first, so a wrong password or an abandoned challenge leaves the existing session alone;
only once Amplify reports success is the replaced session cleaned up (a different user's keys are removed and
their refresh token revoked best-effort, and only if it is revocable, i.e. its access token has `origin_jti`; for the
same user the old refresh token is revoked on the same terms if it changed). It uses the same
Amplify-internals trick as `reauthenticate` (see below). With `'reject'` an existing valid session is never signed out or revoked. `authenticate` throws
`AlreadySignedInException` and normally the session has been loaded into this tab (`isLoggedIn` becomes `true`);
if loading it hit a transient error the exception is still thrown but `isLoggedIn` stays `false`, so redirect
based on context state, not on the exception alone. The loaded session may belong to a different user than the
email entered (the password is not checked), so check `user` if that matters. If the session check itself fails
(e.g. offline) that original error is thrown instead.

**`confirmReplace` (optional, 3.3.0).** With `'replace'`, a stale login form in a second tab can silently replace
another user's session. Pass `confirmReplace` to warn first; without it nothing changes and the session is replaced
silently:

```ts
await auth.authenticate(email, pass, {
  confirmReplace: ({ username, email }) =>
    showModal(`${email ?? username} is still signed in. Replace them?`), // boolean | Promise<boolean>
});
// resolving false throws ReplaceCancelledException (isReplaceCancelledError); nothing is touched.
```

It is called only when the stored session belongs to a *different* login, matched on the typed email or username
against the stored username and ID-token email (case-insensitively). That match is advisory and best-effort: alias
logins (phone, `preferred_username`) or an email changed since the token was issued can prompt for the same user, and
a case-sensitive pool can fail to prompt for a different one; what is discarded afterwards never depends on it. It is
never called for `'reject'`, the same user, an empty submit, or when there is no session. It runs before the password
is checked, so it shows the signed-in user's identity to whoever is at the form (they could already read it from
storage). It is re-checked afterwards: if the stored user changed while the prompt was open, `authenticate` throws
`ReplaceCancelledException` rather than replace someone who was never asked about; if a newer `authenticate` started
meanwhile, this one throws `ReauthAbortedException`. Starting `authenticate` always ends any pending challenge of an
older attempt, even if the prompt is then declined. A hook that throws propagates unchanged with nothing touched.

Leftovers that cannot be fully closed (the replaced user's refresh token then stays stored and valid until it
expires, with nothing sweeping it later): a revoke that fails or is blocked (offline), a tab closed between Amplify
storing the new tokens and the cleanup, two tabs replacing at once (including a third user stored by another tab
while the sign-in was in flight), and a double submit. The cleanup names the new
user from Amplify's own `signedIn` event rather than from `LastAuthUser`, so a token refresh of the old user landing
in that instant does not misdirect it, but a refresh that lands *after* the cleanup can restore the old user. The old
user's device keys are kept (as Amplify's own sign-out does), so on a shared machine a remembered device can still
skip MFA for the old user.

## Provider options (3.3.0, all opt-in)

```tsx
<AuthProvider
  userPool={pool}
  options={{ syncTabs: true, strictTokens: true, retrySessionCheck: true }}
>
```

(`CognitoAuthProvider` in `/legacy` takes the same `options` prop.) With no `options` the provider adds no new
*reactions*, but note two always-on changes: concurrent user loads are coalesced (a caller that arrives mid-load gets
one follow-up run), and the three reads behind a load (session, current user, attributes) are repeated if another tab
switched user between them. If they still disagree after three tries the load rejects with `UserChangedException`
(also from `authenticate`, `refreshSession`, `verifyEmail` and the mount check, which then logs the tab out).

- **`syncTabs`** keeps a tab in step with the session in browser storage (one session per origin + client id, shared
  by every tab). It listens for Amplify's cross-tab `signedIn` / `signedOut` / `tokenRefresh` events but re-reads
  storage rather than trusting them (removing one user's refresh token fires `signedOut` in every tab even when
  another user is now current): a logout elsewhere logs this tab out (state only, never `signOut`), a login elsewhere
  is adopted by a tab that was logged out, and a refresh or re-authentication elsewhere reloads the user so claims
  (`emailVerified`, `mfaEnrolled`, ...) do not go stale. A tab never re-adopts the session it explicitly logged out of
  (a refresh already in flight in another tab can write it back). While this tab is itself signing in, storage
  legitimately flips to the new user first, so checks are postponed until that finishes (the marker covers Amplify's
  calls and the load after them, never a `confirmReplace` prompt).
- **`onUserChange`** is what happens when storage holds a *different* user than the tab shows (another tab signed in as
  someone else). `'reload'` (the default with `syncTabs`) reloads the page, at most once per target user. If the
  reload is refused (already tried for that user, or no `sessionStorage` to guard against a loop) the tab is logged
  out of the old user instead. A function `({ from, to }) => void` is called once per change instead; it receives raw
  usernames (possibly emails), must not throw (ignored if it does) and **must itself stop presenting the old
  user**: nothing else changes in this tab. In both forms the load that found the change rejects with
  `UserChangedException` (`isUserChangedError`, `USER_CHANGED_EXCEPTION`). Without this option and without
  `syncTabs` the tab silently switches user, as in 3.2 (the non-strict getters then return the new user's token to
  code written for the old one). A refresh landing at the wrong instant can restore the old user and cause one extra
  reload. If your app already has its own token/user mismatch reload (wheels does), do not enable the reload form too.
- **`strictTokens`** changes `getIdJwt` / `getAccessJwt`. By default they return `null` for any failure, which is
  indistinguishable from being logged out. Strict mode: a transient failure (network, throttling) throws; a session
  Amplify has dropped locally logs this tab out (after a short re-check); and tokens that belong to a different user
  than the state object the getter came from throw `UserChangedException` instead of reaching code written for the
  old user (poll loops should rethrow it at once, not retry). This holds during this tab's own sign-in too, and for a
  closure that still holds an old state object. It does not detect server-side revocation: the access token stays
  usable until it expires. Callers must catch; the default is unchanged because existing consumers treat `null` as
  "send without a token" or "retry". The getters only *throw*: unless `syncTabs` or `onUserChange` is also set, nothing
  else happens in this tab after a `UserChangedException`, which keeps showing the old user until something reloads
  or logs it out, so the caller must do that. A transient failure is rethrown as Amplify's own error (e.g. "A network
  error has occurred."), so a caller that used `null` to tell "offline" from "expired" must catch it and decide for
  itself (wheels' `useGraphql` needs changes before it can adopt this).
- **`retrySessionCheck`**: the mount-time check normally logs the tab out on any failure (documented trade-off). With
  this it retries (3 tries) and then stays at `isLoggedIn: null` with `sessionCheckFailed: true` and
  `retrySessionCheck()` on the state, instead of reporting a logout. **Never treat `null` as "allowed"**: a gate
  written `isLoggedIn === false ? redirect : <Protected/>` would stay open in that state, and anything that treats
  `null` as "loading" must handle `sessionCheckFailed` or it will wait forever.

The signed-in state also has `sendEmailVerificationCode()` and `confirmEmailVerificationCode(code)` to re-verify the
current address (the latter refreshes the claims).

## Re-authentication, `clientMetadata` and claims (3.2.0)

```ts
// Sign the current user in again (e.g. for a fresh `auth_time`) without signing out.
const res = await auth.reauthenticate(password, {
  clientMetadata: { mfaAction: 'setup' }, // re-sent on every step
});
// ...walk the challenge chain exactly as for authenticate().
```

**`reauthenticate`.** Amplify refuses to sign in while a session exists; this skips that one check. The live session
is untouched and fully usable (API calls, `getIdJwt`) until the attempt succeeds, when Amplify stores the new tokens
over it. A wrong password, a failed or mistyped step (retry the same callback) or an abandoned challenge leaves the
live session as it was. This is the same as a plain login: Amplify keeps the pending challenge (username and Cognito
session token, about 3 minutes) in `sessionStorage`, and a failed attempt can clear this device's stored device key.
An abandoned challenge therefore leaves that pending state (including the Cognito session token) in `sessionStorage`
until the tab closes; Amplify has no public way to clear it, so the library does not (3.2.0-pre.1's clear helper is gone).
Cognito expires the session server-side and the library's callbacks stop working once a newer attempt starts.

- Always the signed-in user: the username is taken from the session, not the caller.
- A fresh sign-in resets `auth_time`; `refreshSession()` does not (`iat`/`exp` move, `auth_time` stays).
- The previous refresh token is not revoked, it just stops being used (unlike a same-user `authenticate` replace
  since 3.3.0, which revokes the one it replaced).
- Amplify's Hub `signedIn` event fires, after the new tokens are stored.
- Only the latest sign-in attempt can be answered (Amplify keeps one global sign-in state): starting another
  `reauthenticate` or `authenticate` makes the older attempt's callbacks throw `ReauthAbortedException`
  (`isReauthAbortedError`).
- The tab and the stored session are checked to still be the same user before the sign-in request and before each
  step; if not, the call throws `ReauthAbortedException`. Amplify stores the new tokens the moment it succeeds, so a
  change made in another tab between the last check and that write cannot be detected there. If the tab logged out
  while the final answer was in flight, or now shows a different user, the session that answer created is discarded
  *by username* (never `signOut()`, which would revoke whoever is current): that user's keys are removed and their
  refresh token revoked on a best-effort basis (the revoke can fail, e.g. offline, leaving the token valid
  server-side until it expires). `LastAuthUser` is removed only if it still names that user. If the attempt had
  taken `LastAuthUser` from the user the tab shows, that user is made current again when their tokens are intact;
  otherwise the tab is reset. If another user signed in *before* the attempt's tokens were stored, the attempt had
  already taken `LastAuthUser` from them, so they are logged out (tokens left stored, not revoked), as before.
  A logout or sign-in as another user in another tab inside the check-to-write window is not detected.
- On success the session's `auth_time` must be newer than before. A token refresh landing at the same moment can put
  the old tokens back; that throws `ReauthNotFreshException` (`isReauthNotFreshError`) and the caller should retry.
- If this device is remembered (Cognito device tracking), Cognito may skip the MFA challenge for it. `auth_time` is
  then fresh although no second factor was re-proved. If you gate sensitive actions on a re-proved factor, do not use
  a pool with remembered devices, or enforce it server-side.
- It relies on Amplify internals: the already-signed-in check must be the first token read in `signIn`, before any
  request. `reauth.test.ts` pins this against real Amplify, so run the tests when bumping `aws-amplify`. If a later
  Amplify changes it, the sign-in can store the new tokens and then fail; `reauthenticate` then throws
  `AmplifyInternalsChangedException` (`isAmplifyInternalsChangedError`) when the hidden read was the only read made
  (`authenticate`'s replace path does the same, after cleaning up the replaced session and reloading the tab).
  The new tokens may be stored with the user not loaded, so reload the page. (The same underlying Amplify error from
  any other cause, e.g. storage that drops writes or another tab clearing the session in that instant, is rethrown
  as it was.) The checks above still run first, so a session the tab logged out of meanwhile is discarded.

**`clientMetadata`.** Cognito does not carry `ClientMetadata` between calls, so it is re-sent on every
`confirmSignIn` of the exchange. Overrides: `completeNewPasswordChallenge(pw, attrs, metadata)` and
`sendCustomChallengeAnswer(answer, metadata)`. It is client-controlled: Cognito triggers must never relax a factor
check or derive claims from it.

**Claims.** The signed-in state exposes `emailVerified`, `mfaEnrolled` and `mfaRequired`, parsed from the ID
token (`'true'`/`true` and `'false'`/`false`). They are UI hints only: a backend failure can yield
`mfaEnrolled: false`, so never gate anything on them. `refreshSession()` forces a refresh and reloads them.

## Migrating from v2

v3 is a breaking rewrite (`amazon-cognito-identity-js` -> `aws-amplify`). See `MIGRATION.md` for both
migration paths, and `CHANGELOG.md` for the full list of breaking changes. If you just want existing v2
code to keep working with minimal changes, see the `@weavingwebs/ww-cognito-react/legacy` entry point.

## Stable user identity

The `user` object returned by `useAuthContext()`/`useAuthContextOrDie()` keeps a stable object reference
across session refreshes when nothing about it has actually changed - so it's safe to use as a
`useEffect`/`useMemo` dependency, or store in state management (e.g. a jotai atom), without extra
re-renders when the session merely refreshes its tokens.

This works by shallow-comparing each freshly-built `user` against the previous one and reusing the old
reference only when every field is unchanged, rather than mutating the previous object in place (which is
what v2 did, and which had a real bug: mutating an object and passing the same reference back into
`useState`'s setter makes React bail out of re-rendering entirely, silently dropping legitimate updates).
It depends on `buildUser` staying pure - see the note above.

## A note on `Amplify.configure`

`AuthProvider` calls `Amplify.configure({ Auth: { Cognito: ... } })`, which replaces Amplify's *entire*
config object, not just the `Auth` slice. This is safe as long as your app doesn't use Amplify for
anything else (Storage, Analytics, etc.) - if it does, you'll need to merge configs yourself rather than
relying on this package's default behaviour.
