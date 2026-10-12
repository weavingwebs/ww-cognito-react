// Cognito custom claims (and email_verified) arrive as the STRINGS
// 'true'/'false' from some triggers and as JSON booleans from others. Anything
// else is unknown.
export function parseBooleanClaim(value: unknown): boolean | undefined {
  if (value === true || value === 'true') return true;
  if (value === false || value === 'false') return false;
  return undefined;
}

type SessionLike = {
  tokens?: { idToken?: { payload: Record<string, unknown> } };
};

// UI hints only - never gate anything on these.
export function claimsFromSession(session: SessionLike | null | undefined): {
  emailVerified: boolean | undefined;
  mfaEnrolled: boolean;
  mfaRequired: boolean;
} {
  const payload = session?.tokens?.idToken?.payload;
  return {
    emailVerified: parseBooleanClaim(payload?.email_verified),
    mfaEnrolled: parseBooleanClaim(payload?.mfa_enrolled) === true,
    mfaRequired: parseBooleanClaim(payload?.mfa_required) === true,
  };
}
