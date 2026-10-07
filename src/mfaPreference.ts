import { fetchMFAPreference, updateMFAPreference } from 'aws-amplify/auth';

// Free functions (not context methods) so they work straight after an
// MFA_SETUP sign in, when the context may not have caught up yet, and so
// consuming apps never need to import `aws-amplify` themselves (a second,
// unconfigured Amplify singleton would result).

export async function fetchMfaPreference(): Promise<{
  enabled: string[];
  preferred?: string;
}> {
  const { enabled, preferred } = await fetchMFAPreference();
  return { enabled: enabled ?? [], preferred };
}

export async function setTotpPreference(
  preference: 'PREFERRED' | 'DISABLED',
): Promise<void> {
  await updateMFAPreference({ totp: preference });
}
