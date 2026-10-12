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
// Don't sign out (and revoke) an existing valid session:
try {
  await auth.authenticate(email, pass, { onExistingSession: 'reject' });
} catch (err) {
  if (isAlreadySignedInError(err)) {
    /* a session already exists (possibly another user); redirect based on context state */
  }
}
```

`onExistingSession` defaults to `'replace'` (sign out, which revokes the refresh token, then retry). With
`'reject'` an existing valid session is never signed out or revoked. `authenticate` throws
`AlreadySignedInException` and normally the session has been loaded into this tab (`isLoggedIn` becomes `true`);
if loading it hit a transient error the exception is still thrown but `isLoggedIn` stays `false`, so redirect
based on context state, not on the exception alone. The loaded session may belong to a different user than the
email entered (the password is not checked), so check `user` if that matters. If the session check itself fails
(e.g. offline) that original error is thrown instead.

## Re-authentication, `clientMetadata` and claims (3.2.0)

```ts
// Re-authenticate the signed-in user (e.g. to add an MFA factor) without touching the live session
// unless it succeeds.
const ac = new AbortController(); // abort on unmount
const res = await auth.authenticate(user.email, password, {
  allowWhileLoggedIn: true,
  clientMetadata: { mfaAction: 'setup' }, // re-sent on every step
  signal: ac.signal,
});
// ...walk the challenge chain as usual; call rollbackPendingReauth() if the user abandons it.
```

**`allowWhileLoggedIn`.** Amplify refuses to sign in while usable tokens exist. With this flag the attempt runs
against a private in-memory token store, and only a successful attempt copies its tokens into the real
(shared `localStorage`) storage. Consequences:

- A wrong answer, a failed step or an abandoned challenge rolls back; nothing is written to or cleared from the
  live session in any tab. (The one read of the real store is a `fetchAuthSession()` at the start, which may
  refresh the live tokens as it normally would.) A failed challenge step ends the attempt (the user
  restarts from the password), except `CodeMismatchException`, `InvalidPasswordException` and
  `EnableSoftwareTokenMFAException` (a mistyped code / weak new password): Cognito keeps the session, so the
  same callback can be called again. A custom-challenge failure is always terminal.
- A rollback that lands while a Cognito call is in flight (modal closed, abort, logout) is deferred until that
  call settles, and the call's result is discarded: the late response can never write into the real session.
  `rollbackPendingReauth()` and `logout()` therefore resolve only once the real storage is back in use.
- An attempt with no activity for 5 minutes (`REAUTH_IDLE_TIMEOUT_MS`) rolls itself back.
- It replaces `onExistingSession`: no sign-out, no revoke, no `AlreadySignedInException`. With no existing
  session it is just a normal login.
- It must be the signed-in user. The new tokens' Cognito username is compared with the live session's before
  anything is written, and the real store is re-read at commit so a session changed by another tab meanwhile
  (different user, or logged out) is not overwritten; either rolls back and throws
  `ReauthUserMismatchException` (`isReauthUserMismatchError(err)`). A rolled-back attempt's callbacks and
  `commit()` throw `ReauthAttemptEndedException` (`isReauthAttemptEndedError(err)`).
- Do not call `Amplify.configure` yourself while an attempt can be active: it resets the token storage to the
  real one. The library detects this and fails the attempt, but anything Amplify wrote in between has already
  gone to the real storage (the live user's session is cleared if it no longer matches).
- A plain `authenticate()` (without `allowWhileLoggedIn`) while an attempt is active throws.
- Only one attempt at a time; a second throws. Call `rollbackPendingReauth()` when a login modal closes
  mid-challenge or reaches a terminal failure. `logout()` and `forceSignOut()` do this for you.
- While active, `getIdJwt()` / `getAccessJwt()` return the live session's tokens until they expire and never
  refresh them; after commit they return the new ones. `refreshSession()` throws. The snapshot is not
  invalidated by a logout in another tab (bounded by token expiry and the idle timeout).
- With Cognito device tracking enabled, each re-auth looks like a new device (the private store has no device
  keys). Wheels does not use it.
- Amplify's Hub `signedIn` event fires before the commit, so a listener of your own sees it before the real
  storage has the new tokens.
- Known narrow race: a refresh of the real session that another part of the app starts at the same instant the
  attempt begins writes its result into the private store. Don't kick off re-auth in the middle of a token
  refresh storm.
- `auth_time` (which a backend may use to judge freshness) is set at authentication. A fresh sign-in like this
  one resets it; a token refresh does not (measured against a Cognito pool: `iat` and `exp` move, `auth_time` stays).
- `clientMetadata` is client-controlled. Your Cognito triggers must never relax a factor check or derive claims
  from it.

**`clientMetadata`.** Cognito does not carry `ClientMetadata` between calls, so it is re-sent on every
`confirmSignIn` of the exchange. Overrides: `completeNewPasswordChallenge(pw, attrs, metadata)` and
`sendCustomChallengeAnswer(answer, metadata)`.

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
