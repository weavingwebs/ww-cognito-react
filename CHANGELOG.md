# Changelog

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
- `forceSignOut()` - a top-level export, clears any local Amplify session regardless of app state.
- `@weavingwebs/ww-cognito-react/legacy` - a deprecated compat entry point that adapts v3 back onto v2's
  exact API shape, for apps that want to upgrade with minimal code changes. See `MIGRATION.md`.
