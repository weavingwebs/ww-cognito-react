# Migrating from v2 to v3

v3 replaces the underlying SDK (`amazon-cognito-identity-js` -> `aws-amplify`). There are two migration
paths - pick whichever fits your app.

## Fast path: `@weavingwebs/ww-cognito-react/legacy`

Swap the import path only, no other code changes:

```diff
-import { createCognitoAuth } from '@weavingwebs/ww-cognito-react';
+import { createCognitoAuth } from '@weavingwebs/ww-cognito-react/legacy';
```

This re-exports `createCognitoAuth`, `defaultBuildUser`, `AuthenticateResult`,
`CompleteNewPasswordChallengeFn`, `RespondToTotpChallengeFn`, `SendCustomChallengeAnswerFn`, and
`buildTotpUri` in v2's exact shapes, adapted onto the real v3 API underneath. Your existing `buildUser`
callback (`(user, attr) => ...`, `attr.forEach(a => switch (a.Name) {...})`, `user.getUsername()`) keeps
working unchanged.

**What the shim does not reproduce** - despite the "no other code changes" claim above, the shim doesn't
adapt everything back to v2's exact shape. Check these before relying on the fast path:

- `resetPassword()`'s old curried return (`(code, newPassword) => Promise<void>`) and `verifyTotp()`'s old
  resolved `CognitoUserSession` - the shim exposes v3's flatter shapes (`Promise<void>` for both) instead.
  If you use either return value, you'll need to update that call site even on the fast path. (No current
  consumer does, but this isn't exhaustively swept for every app.)
- `getUsername()` on the fast path returns `authUser.username` (Cognito's `cognito:username` attribute),
  matching v2 exactly - not `authUser.userId` (`sub`). These are usually the same value but can differ
  depending on your user pool's configuration.
- **`completeMfaSetupChallenge`** (the `MFA_SETUP` branch's callback, used by native TOTP setup) is
  re-exported unadapted - it takes v3's positional args (`totpCode, friendlyDeviceName`), not v2's object
  arg (`{totpCode, friendlyDeviceName}`). Unlike the two items above, this one is **not** theoretical:
  every real consumer with a TOTP-setup flow has hit it and needed a one-line fix at that call site, even
  on the fast path.

## Full path: the real v3 API

For apps migrating onto v3's actual public API rather than the compat shim:

- **`buildUser` shape changed**: `(user: CognitoUser, attr: {Name,Value}[]) => User` becomes
  `(authUser: AuthUser, attributes: Record<string, string | undefined>) => User`. Read attributes directly
  off the record (`attributes.email`, `attributes['custom:roles']`) instead of iterating an array.
- **`UserPoolConfig` field casing changed**: `{UserPoolId, ClientId, AuthFlow}` becomes
  `{userPoolId, userPoolClientId, authFlowType}` (camelCase, matching Amplify's own config shape). Note
  `AuthFlow: 'CUSTOM_AUTH'` maps to `authFlowType: 'CUSTOM_WITH_SRP'`, not `'CUSTOM_WITHOUT_SRP'` - the
  value space changed, not just the field name. **If your pool config comes from a backend-sourced JSON
  file you don't control the shape of** (e.g. build-time-generated settings), you likely can't just rename
  the fields at the source - write a small adapter function instead, and call it right before passing
  `userPool` to `AuthProvider`, rather than changing the JSON's casing or spreading it directly (a spread
  can leak extra fields like `Region` into Amplify's config object). See `toV3Pool` in s4a/frontend's
  `shared/lib/authContext.tsx` for a real example of this pattern.
- **`AuthenticateResult` restructured**: still a 5-branch union (`SUCCESS` / `NEW_PASSWORD_REQUIRED` /
  `TOTP_REQUIRED` / `MFA_SETUP` / `CUSTOM_CHALLENGE`), but `NEW_PASSWORD_REQUIRED` no longer carries
  `userAttributes`/`requiredAttributes` (Amplify supplies a differently-shaped `missingAttributes: string[]`
  instead - not currently surfaced by this package; open an issue if you need it), and there's no
  `cognitoUser` field on any branch (no Amplify equivalent).
- **`completeMfaSetupChallenge` is now positional**: `(totpCode, friendlyDeviceName)`, not
  `({totpCode, friendlyDeviceName})` - normalized to match its sibling challenge-response callbacks.
- **`resetPassword`/`verifyTotp` return shapes flattened**: `resetPassword(email)` now returns
  `Promise<void>` (call `confirmResetPassword(email, code, newPassword)` separately), and `verifyTotp`
  returns `Promise<void>` instead of a `CognitoUserSession`.
- **`buildTotpUri`'s space-encoding changed**: it's `qs`-based (space -> `%20`), not `URLSearchParams`-based
  (space -> `+`). Both encodings are valid, but the emitted `otpauth://` URI is byte-different if your
  issuer or account name contains a space.
- **Dropped with no replacement**: `temporary` (in-memory storage option), `getUser()` (sync accessor),
  free `verifyAttribute`/`associateTotp`/`verifyTotp` functions taking a raw `CognitoUser`. None of these
  had a live consumer at the time of the v3 rewrite.

## Applies to both paths: forced password resets and unconfirmed users are now catchable errors

Under v2, a user Cognito had forced into a password reset threw a catchable `PasswordResetRequiredException`
during sign-in, and an unconfirmed user threw `UserNotConfirmedException`. Amplify instead resolves these
into `RESET_PASSWORD`/`CONFIRM_SIGN_UP` sign-in steps rather than throwing - v3 re-throws them as errors
with the original exception names, so existing `err.name === 'PasswordResetRequiredException'`-style
`.catch()` blocks keep working on both the fast and full path without changes.

## Not migrated by either path

`rateLimit()` (v2's client-side throttle) is dropped entirely in v3 - it read a `localStorage` key that
the code populating it never actually wrote to, so it never fired in practice. See `CHANGELOG.md`.
