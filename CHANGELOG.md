# Changelog

## 3.3.0

### Behaviour changes

- **User loads are coalesced and cross-checked, with no option needed.** Concurrent `loadUserFromSession` calls are
  merged (a caller arriving mid-load gets one shared follow-up run, so a sign-in never gets the previous user), and
  the three reads in a load are repeated if another tab switched user between them. If they still disagree the load
  rejects with `UserChangedException`, which can now come out of `authenticate`, `refreshSession`, `verifyEmail` and
  the mount check (which then logs the tab out).

- **`authenticate` with `onExistingSession: 'replace'` (the default) no longer signs out first.** In 3.1/3.2 it
  revoked the existing session *before* the password was checked, so a wrong password logged the old user out. It now
  signs in again ignoring the stored session (the `signInIgnoringSession` mechanism `reauthenticate` uses; only after
  Amplify has refused with `UserAlreadyAuthenticatedException`, so a normal login is unchanged) and cleans up the
  replaced session only once Amplify reports success. The cleanup names the new user from Amplify's own `signedIn`
  event (falling back to `LastAuthUser`), never from the typed login: a different user's keys are removed and their
  refresh token revoked best-effort (only if revocable, i.e. `origin_jti`); for the same user the old refresh token is
  revoked on the same terms if it changed. If neither the new user nor `LastAuthUser` can be determined, nothing is
  touched. As `reauthenticate`, this depends on Amplify's read order; if that changes, or Amplify fails after
  storing the tokens, `authenticate` still cleans up the replaced session but does NOT load whoever is stored (it
  cannot tell that they are the user this attempt signed in), then throws `AmplifyInternalsChangedException` / the
  original error: reload the page. Leftovers that cannot be closed (a failed revoke, a tab
  closed mid-way, two tabs replacing at once) are listed in the README. `forceSignOut` is still exported but no longer
  used by `authenticate`. Also: a same-user replace now revokes the refresh token it replaced, which `reauthenticate`
  still does not.

### Added

- **`<AuthProvider options={...}>`**, all opt-in (no options = 3.2 behaviour): `syncTabs` (follow other tabs'
  login/logout, refresh claims on token refresh), `onUserChange` (`'reload'` | callback, when another tab signed in as
  a different user; the load rejects with `UserChangedException`), `strictTokens` (`getIdJwt`/`getAccessJwt`
  throw on transient failures and on a user change instead of returning `null`), `retrySessionCheck` (retry the
  mount check, then stay at `isLoggedIn: null` with `sessionCheckFailed` / `retrySessionCheck()`). `AuthProviderOptions`,
  `OnUserChange`, `UserChange`, `isUserChangedError` and `USER_CHANGED_EXCEPTION` are exported (the error is an `Error`
  named `UserChangedException`, not a class); `/legacy`'s `CognitoAuthProvider` forwards `options`. See the README. Defaults are unchanged because s4a/hermes/wheels depend
  on the getters returning `null` and on `isLoggedIn` only ever being `true`/`false` after loading.
- **`sendEmailVerificationCode()` / `confirmEmailVerificationCode(code)`** on the signed-in state (additive; the
  state type gains required fields, so hand-written mocks typed as it need them).
- **`authenticate(..., { confirmReplace })`** (optional, default unchanged: silent replace). Called before the
  sign-in when the stored session is a different login (advisory match), with `{ username, email? }`; resolving
  `false` throws `ReplaceCancelledException` (`isReplaceCancelledError`, `REPLACE_CANCELLED_EXCEPTION`,
  `ConfirmReplace` type) with nothing touched. Not called for an empty submit. Re-checked after it resolves (the stored
  user changing meanwhile cancels; a newer attempt aborts). See the README.
- **`AmplifyInternalsChangedException`** (`isAmplifyInternalsChangedError`, `AMPLIFY_INTERNALS_CHANGED_EXCEPTION`):
  `reauthenticate` (and, since the replace change below, `authenticate`'s replace path) throws it when Amplify's late "who is signed in" read fails after the sign-in and the hidden read
  was the only read made, i.e. a newer Amplify no longer reads the session in the order `signInIgnoringSession`
  relies on. The new tokens may be stored with the user not loaded, so reload the page. The session checks still run
  first (a tab that logged out meanwhile has the session discarded). The same Amplify error from any other cause is
  rethrown unchanged. Normally unreachable: `yarn test` pins the order for the supported Amplify version.

### Fixed

- `reauthenticate`: when the tab logged out (or changed user) while the final answer was in flight, the session the
  attempt had just stored is now discarded by username (its keys removed, its refresh token revoked best-effort,
  `LastAuthUser` removed only if it still names that user). It used to call `signOut()`, which revokes whichever user
  is current and so could revoke a third user another tab had signed in afterwards. If that third user signed in
  *before* the attempt's tokens were stored they are logged out as before (tokens left stored, not revoked). If the
  attempt had taken `LastAuthUser` from the user the tab shows, that user is made current again when their tokens are
  intact instead of the tab being reset. The revoke is not awaited, so the tab is never held up by the network.
- `updateEmail(...).verifyEmail(code)` now forces a token refresh before reloading the user, so `emailVerified` and
  the `email` claim are current straight away (before, they stayed stale until the next refresh). A transient refresh
  failure is ignored (the address is already confirmed); a definitive one logs the tab out as usual and the call
  rejects.

## 3.2.0

All additive. `authenticate(email, pass)` makes the same Amplify calls as in 3.1.0 and its existing option
(`onExistingSession`) is unchanged, so s4a and hermes need no code changes. Things to be aware of:
- Requires `aws-amplify` `~6.22.1` (was `^6.20.0`): `reauthenticate` uses its `createAmplifyContext` and depends on
  Amplify internals, so only the tested minor is allowed; bump deliberately, with `yarn test` as the gate.
- A per-call `clientMetadata` override passed to `sendCustomChallengeAnswer` / `completeNewPasswordChallenge` now
  carries on to the later steps of the exchange (in 3.1.0 later steps without the argument sent nothing). No
  current consumer passes one.
- Amplify keeps one global sign-in state, so a challenge callback from an older `authenticate`/`reauthenticate`
  now throws `ReauthAbortedException` once a newer attempt has started (before, it would have answered the newer
  attempt's challenge). Only the steps are refused: a plain sign-in that Amplify completes is always loaded.
- `reauthenticate` on a logged-out tab throws `ReauthNotLoggedInException` (`isReauthNotLoggedInError`).
- `AuthStateLoggedIn` gains required fields (`emailVerified`, `mfaEnrolled`, `mfaRequired`, `refreshSession`,
  `reauthenticate`), so a hand-written object typed as it (e.g. a test mock) needs them.

### Added

- **`reauthenticate(pass, opts?: { clientMetadata })`** on the signed-in state: signs the current user in again
  without signing out (e.g. to reset the ID token's `auth_time`, or to add an MFA factor). Returns the same
  challenge chain as `authenticate`. The live session is untouched unless the attempt succeeds. See the README
  ("Re-authentication"). Throws `ReauthAbortedException` (`isReauthAbortedError`, `REAUTH_ABORTED_EXCEPTION`) if the
  tab logged out, the user changed or a newer attempt started, and `ReauthNotFreshException`
  (`isReauthNotFreshError`, `REAUTH_NOT_FRESH_EXCEPTION`) if the new session's `auth_time` did not advance.
- **`authenticate(email, pass, opts?: AuthenticateOptions)`** (`AuthenticateOptions` is exported):
  - `clientMetadata?: Record<string, string>` - sent with the sign-in and re-sent on every `confirmSignIn` of the
    exchange (new password, TOTP, MFA setup, custom challenge), because Cognito does not carry it between
    calls. `completeNewPasswordChallenge(newPassword, attributes?, clientMetadata?)` and
    `sendCustomChallengeAnswer(answer, clientMetadata?)` take an optional override, which replaces the metadata
    for that call and the rest of the exchange.
- **ID token claims on the signed-in state**, beside `user` (not inside it, so `user` identity is unchanged):
  `emailVerified: boolean | undefined`, `mfaEnrolled: boolean`, `mfaRequired: boolean`. `'true'`/`true` and
  `'false'`/`false` are parsed; anything else is `false` (`undefined` for `emailVerified`). UI hints only: never
  gate anything on them.
- **`refreshSession()`** on the signed-in state: forces a token refresh then reloads the user and claims. A refresh
  is not a re-authentication: the ID token keeps its original `auth_time` (measured against a Cognito pool: `iat`/`exp`
  move, `auth_time` does not).

## 3.1.0

### Added (additive)

- `fetchMfaPreference()` and `setTotpPreference('PREFERRED' | 'DISABLED')` free functions, wrapping Amplify's
  `fetchMFAPreference` / `updateMFAPreference`, so apps never need to import `aws-amplify` directly.
- `authenticate(email, pass, { onExistingSession: 'replace' | 'reject' })`. Default `'replace'` is the existing
  behaviour (sign out, which revokes the refresh token, then retry). With `'reject'` a valid existing session is
  never signed out or revoked, and `authenticate` throws an error named `AlreadySignedInException`
  (`ALREADY_SIGNED_IN_EXCEPTION`, `isAlreadySignedInError()` and the `OnExistingSession` type are exported).
  Normally the existing session has been loaded into this tab (`isLoggedIn` becomes `true`); if loading it hit a
  transient error the exception is still thrown but `isLoggedIn` stays `false`, so redirect on context state, not
  on the exception alone. If the session check itself fails (e.g. offline) that original error is thrown instead.
  If the existing tokens turn out to be dead (e.g. the access token was revoked server-side) they are cleared
  locally (no revoke) and sign-in is retried, so the user is not locked out.
  Note: tokens live in shared storage (one session per origin + client id). With `'replace'`, signing in in any
  tab replaces the session for every tab. With `'reject'`, a second user cannot sign in while a valid session
  exists: they get `AlreadySignedInException` and this tab is loaded as the *existing* user, who may differ from
  the email entered. The password is not verified, so check `user` after catching it if that matters.

### Behaviour changes (affects s4a, hermes - smoke test before upgrading)

- A failed session check at mount no longer calls `signOut()` (which revoked the refresh token on a transient
  error). App state is cleared only, and the tokens are kept so a transient failure does not end the session. If
  the failure has one of the token-clearing error names listed in the next bullet (e.g. the access token was
  revoked server-side) the library clears the stored tokens locally, without a revoke. On a shared device a
  transient failure can therefore show the login screen while valid tokens remain in storage; with
  `onExistingSession: 'reject'` the next person to log in is then given the previous user's session.
- A Hub `tokenRefresh_failure` now sets `isLoggedIn` to `false` (app state only, no `signOut`) when the error is
  one for which Amplify clears the stored tokens (`NotAuthorizedException`, `TokenRevokedException`,
  `UserNotFoundException`, `PasswordResetRequiredException`, `UserNotConfirmedException`,
  `RefreshTokenReuseException`; prefix match, as Amplify does). Transient failures (e.g. network) are ignored, so
  offline does not log the user out.
  Consumers: `isLoggedIn` can now become `false` while a logged-in page is mounted, so components calling
  `useAuthContextOrDie()` will throw unless a parent guard reacts to `isLoggedIn === false` first. Check this in
  s4a and hermes. This only updates the tab that ran the refresh: other open tabs stay `isLoggedIn: true` with
  null JWTs until they reload or fail a refresh themselves (cross-tab sync is not part of 3.1.0).

### Build / tooling (no consumer impact)

- `tsconfig.json` now includes the test files, so editors and `yarn typecheck` (`tsc --noEmit`) type-check them
  with the real compiler options. The published build uses the new `tsconfig.build.json`, which excludes
  `src/**/*.test.ts`; `yarn build` / `yarn watch` use it. `dist` output is unchanged.
- `yarn typecheck` added and run in `Release.yml` before the tests.

### Upgrading from 3.0.x

No code changes are required: `authenticate(email, pass)` keeps its 3.0 default (`'replace'`). The new exports
are not re-exported from `/legacy`; import them from the main entry. See the behaviour changes above.

## 3.0.0

Underlying SDK swapped from `amazon-cognito-identity-js` to `aws-amplify`. See `MIGRATION.md` for how to
upgrade - either a near-zero-touch swap via `@weavingwebs/ww-cognito-react/legacy`, or onto the real v3
API directly.

### Breaking

- `BuildUserFn<User>` shape changed: `(user: CognitoUser, attr: {Name,Value}[]) => User` is now
  `(authUser: AuthUser, attributes: Record<string, string | undefined>) => User`.
- `UserPoolConfig` fields renamed to camelCase (`userPoolId`, `userPoolClientId`, `authFlowType`), and
  `authFlowType: 'CUSTOM_AUTH'` is now `'CUSTOM_WITH_SRP'` (the value space changed, not just the casing).
- `AuthenticateResult`'s `NEW_PASSWORD_REQUIRED` branch no longer carries `userAttributes`/
  `requiredAttributes`. No branch carries a `cognitoUser` field any more.
- `completeMfaSetupChallenge` takes positional args (`totpCode, friendlyDeviceName`), not an object arg -
  normalized to match its sibling challenge-response callbacks.
- `resetPassword(email)` returns `Promise<void>` instead of a curried confirm function - call
  `confirmResetPassword(email, code, newPassword)` separately.
- `verifyTotp(totpCode, friendlyDeviceName)` returns `Promise<void>` instead of a `CognitoUserSession`.
- `buildTotpUri` now encodes spaces as `%20` (via `qs`), not `+` - unchanged from v2, but called out since
  s4a's independent fork used `URLSearchParams` (`+`) and that fork is what's being replaced here.
- Dropped, no replacement: the `temporary` in-memory-storage option on the provider, the sync `getUser()`
  accessor, and the free `verifyAttribute`/`associateTotp`/`verifyTotp` functions that took a raw
  `CognitoUser`. None had a live consumer.
- `rateLimit()` (the client-side request throttle) is removed entirely. It read a `localStorage` key that
  the code populating it never actually wrote to, so it never fired in practice - this is a dead-code
  removal, not a behaviour change.
- Dependencies: `amazon-cognito-identity-js` and `encoding` replaced with `aws-amplify`. `qs` unchanged.
- `peerDependencies.react` widened from `^16.9.0` to `^16.9.0 || ^17.0.0 || ^18.0.0` - the old range was
  already unmet by every real consumer (all on React 18).

### Behaviour changes worth knowing about even though the type signature didn't change

- A user Cognito has forced into a password reset, or an unconfirmed user, used to throw a catchable
  `PasswordResetRequiredException`/`UserNotConfirmedException` during sign-in. Amplify instead resolves
  these into sign-in steps rather than throwing - v3 re-throws them as errors with the original exception
  names so existing `err.name === '...'` checks keep working, but this is new logic, not a straight port.
- The `user` object's stable-reference-across-refresh behaviour is reimplemented without mutation (shallow
  compare and reuse-or-replace, rather than `Object.assign`-ing the previous object in place). Still
  present, still gives the same referential-stability benefit - the old implementation had a real bug
  (mutating an object and passing the same reference into `useState`'s setter makes React bail out of
  re-rendering entirely on any session refresh after the first login) that this reimplementation fixes.
  See the README's "Stable user identity" section.

### Added

- `useAuthContextOrDie()` - throws unless logged in, folded into the factory (previously duplicated by
  hand in every consumer that needed it).
- `forceSignOut()` - a top-level export, calls Amplify `signOut()` (revokes the refresh token where applicable, then clears local tokens) regardless of app state. Does not update `AuthProvider` state.
- `@weavingwebs/ww-cognito-react/legacy` - a deprecated compat entry point that adapts v3 back onto v2's
  exact API shape, for apps that want to upgrade with minimal code changes. See `MIGRATION.md`.
