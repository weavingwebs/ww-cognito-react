// Internal to the legacy shim - not part of any public API surface (the
// /legacy entry point re-exports legacy.tsx's top level with a wildcard, so
// this stays in its own module rather than living there). See
// legacyAdapter.test.ts, and MIGRATION.md for why getUsername() reads
// .username, not .userId.
export function adaptToLegacyBuildUser(
  authUser: { username: string },
  attributes: Record<string, string | undefined>,
): { user: { getUsername: () => string }; attr: { Name: string; Value: string }[] } {
  const attr = Object.entries(attributes)
    .filter((e): e is [string, string] => e[1] !== undefined)
    .map(([Name, Value]) => ({ Name, Value }));
  return { user: { getUsername: () => authUser.username }, attr };
}
