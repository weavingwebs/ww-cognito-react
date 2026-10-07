import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('aws-amplify/auth', () => ({
  fetchMFAPreference: vi.fn(),
  updateMFAPreference: vi.fn(),
}));

import { fetchMFAPreference, updateMFAPreference } from 'aws-amplify/auth';
import { fetchMfaPreference, setTotpPreference } from './mfaPreference';

beforeEach(() => vi.clearAllMocks());

describe('fetchMfaPreference', () => {
  it('maps enabled and preferred', async () => {
    vi.mocked(fetchMFAPreference).mockResolvedValue({
      enabled: ['TOTP'],
      preferred: 'TOTP',
    });
    expect(await fetchMfaPreference()).toEqual({
      enabled: ['TOTP'],
      preferred: 'TOTP',
    });
  });

  it('normalises undefined enabled to []', async () => {
    vi.mocked(fetchMFAPreference).mockResolvedValue({} as never);
    expect(await fetchMfaPreference()).toEqual({
      enabled: [],
      preferred: undefined,
    });
  });
});

describe('setTotpPreference', () => {
  it.each(['PREFERRED', 'DISABLED'] as const)('passes %s through', async (p) => {
    await setTotpPreference(p);
    expect(updateMFAPreference).toHaveBeenCalledWith({ totp: p });
  });
});
