import { describe, expect, it } from 'vitest';
import { claimsFromSession, parseBooleanClaim } from './claims';

const session = (payload: Record<string, unknown>) =>
  ({ tokens: { idToken: { payload } } }) as never;

describe('parseBooleanClaim', () => {
  it.each([
    ['true', true],
    [true, true],
    ['false', false],
    [false, false],
    [undefined, undefined],
    [null, undefined],
    ['yes', undefined],
    ['TRUE', undefined],
    [1, undefined],
    [{}, undefined],
  ])('%j -> %j', (input, expected) => {
    expect(parseBooleanClaim(input)).toBe(expected);
  });
});

describe('claimsFromSession', () => {
  it('reads all three claims', () => {
    expect(
      claimsFromSession(
        session({ email_verified: true, mfa_enrolled: 'true', mfa_required: 'false' }),
      ),
    ).toEqual({ emailVerified: true, mfaEnrolled: true, mfaRequired: false });
  });

  it('missing or junk: emailVerified undefined, mfa flags false', () => {
    expect(claimsFromSession(session({ mfa_enrolled: 'junk' }))).toEqual({
      emailVerified: undefined,
      mfaEnrolled: false,
      mfaRequired: false,
    });
  });

  it('no session or no ID token', () => {
    const none = { emailVerified: undefined, mfaEnrolled: false, mfaRequired: false };
    expect(claimsFromSession(undefined)).toEqual(none);
    expect(claimsFromSession({} as never)).toEqual(none);
  });
});
