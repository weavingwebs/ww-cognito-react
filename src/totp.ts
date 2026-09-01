import * as qs from 'qs';

/**
 * Create a TOTP Uri for use with authenticator apps.
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
export function buildTotpUri({
  accountName,
  secret,
  issuer,
}: {
  accountName: string;
  secret: string;
  issuer: string;
}): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(
    accountName,
  )}?${qs.stringify({ secret, issuer })}`;
}
