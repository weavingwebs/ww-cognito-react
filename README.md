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
- The previous refresh token is not revoked, it just stops being used.
- Amplify's Hub `signedIn` event fires, after the new tokens are stored.
- Only the latest sign-in attempt can be answered (Amplify keeps one global sign-in state): starting another
  `reauthenticate` or `authenticate` makes the older attempt's callbacks throw `ReauthAbortedException`
  (`isReauthAbortedError`).
- The tab and the stored session are checked to still be the same user before the sign-in request and before each
  step; if not, the call throws `ReauthAbortedException`. Amplify stores the new tokens the moment it succeeds, so a
  change made in another tab between the last check and that write cannot be detected there: if the tab logged out
  while the final answer was in flight, or now shows a different user, the session that answer created is signed out
  again (and the tab reset in the different-user case, since the other user's tokens were overwritten). This only
  reacts to this tab's view and the stored session at the check; a logout or sign-in as another user in another tab
  inside that window is not detected.
- On success the session's `auth_time` must be newer than before. A token refresh landing at the same moment can put
  the old tokens back; that throws `ReauthNotFreshException` (`isReauthNotFreshError`) and the caller should retry.
- If this device is remembered (Cognito device tracking), Cognito may skip the MFA challenge for it. `auth_time` is
  then fresh although no second factor was re-proved. If you gate sensitive actions on a re-proved factor, do not use
  a pool with remembered devices, or enforce it server-side.
- It relies on Amplify internals: the already-signed-in check must be the first token read in `signIn`, before any
  request. `reauth.test.ts` pins this against real Amplify. If a later Amplify changes it, a failure may not be a
  clean refusal (the sign-in could store tokens and then throw), so run the tests when bumping `aws-amplify`.

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
