# Changelog

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
