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
