// @vitest-environment node
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Amplify } from 'aws-amplify';
import { fetchAuthSession } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import { discardStoredSession, restoreStoredSession } from './storedSession';

const P = 'CognitoIdentityServiceProvider.client.';
const b64 = (o: object) =>
  btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwt = (claims: object) => `${b64({ alg: 'none' })}.${b64(claims)}.sig`;
const exp = () => Math.floor(Date.now() / 1000) + 3600;
const data = new Map<string, string>();
const storage = {
  setItem: async (k: string, v: string) => void data.set(k, v),
  getItem: async (k: string) => data.get(k) ?? null,
  removeItem: async (k: string) => void data.delete(k),
  clear: async () => data.clear(),
};
const SUFFIXES = ['accessToken', 'idToken', 'refreshToken', 'signInDetails', 'clockDrift', 'oauthMetadata'];
const KEPT = ['deviceKey', 'deviceGroupKey', 'randomPasswordKey'];
const seed = (user: string, { revocable = true } = {}) => {
  const claims = { sub: user, username: user, exp: exp(), iat: 1, ...(revocable ? { origin_jti: 'j' } : {}) };
  for (const s of SUFFIXES) data.set(`${P}${user}.${s}`, `${s}-${user}`);
  data.set(`${P}${user}.clockDrift`, '0');
  data.set(`${P}${user}.signInDetails`, '{}');
  data.set(`${P}${user}.accessToken`, jwt(claims));
  data.set(`${P}${user}.idToken`, jwt({ ...claims, 'cognito:username': user }));
  data.set(`${P}${user}.refreshToken`, `refresh-${user}`);
  for (const s of KEPT) data.set(`${P}${user}.${s}`, `${s}-${user}`);
};
const keysOf = (user: string) =>
  Array.from(data.keys()).filter((k) => k.startsWith(`${P}${user}.`)).map((k) => k.slice(`${P}${user}.`.length));
let fetchMock: ReturnType<typeof vi.fn>;

beforeAll(() => {
  Amplify.configure({
    Auth: { Cognito: { userPoolId: 'eu-west-2_test', userPoolClientId: 'client' } },
  });
  cognitoUserPoolsTokenProvider.setKeyValueStorage(storage);
});

beforeEach(() => {
  data.clear();
  fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
  globalThis.fetch = fetchMock as never;
});

describe('discardStoredSession', () => {
  it('removes every per-user key Amplify writes (not device keys) and Amplify then sees no session', async () => {
    seed('user-a');
    data.set(`${P}LastAuthUser`, 'user-a');
    expect((await fetchAuthSession()).tokens).toBeDefined();
    const { revoked } = await discardStoredSession('user-a');
    expect(await revoked).toBe(true);
    expect(keysOf('user-a').sort()).toEqual([...KEPT].sort());
    expect(data.has(`${P}LastAuthUser`)).toBe(false);
    expect((await fetchAuthSession()).tokens).toBeUndefined();
  });

  it('revokes that refresh token at the Cognito endpoint (body only), keepalive', async () => {
    seed('user-a');
    data.set(`${P}LastAuthUser`, 'user-a');
    await (await discardStoredSession('user-a')).revoked;
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://cognito-idp.eu-west-2.amazonaws.com/');
    expect(new Headers(init.headers).get('x-amz-target')).toContain('RevokeToken');
    expect(init.keepalive).toBe(true);
    expect(JSON.parse(init.body)).toEqual({ Token: 'refresh-user-a', ClientId: 'client' });
    expect(JSON.stringify(init.headers)).not.toContain('refresh-user-a');
  });

  it('local removal is finished before the revoke is awaited', async () => {
    seed('user-a');
    let release!: () => void;
    fetchMock.mockReturnValue(new Promise((r) => (release = () => r(new Response('{}')))));
    const { revoked } = await discardStoredSession('user-a');
    expect(data.has(`${P}user-a.refreshToken`)).toBe(false);
    release();
    expect(await revoked).toBe(true);
  });

  it("leaves another user's session and LastAuthUser alone", async () => {
    seed('user-a');
    seed('user-c');
    data.set(`${P}LastAuthUser`, 'user-c');
    await (await discardStoredSession('user-a')).revoked;
    expect(data.get(`${P}LastAuthUser`)).toBe('user-c');
    expect(keysOf('user-c')).toHaveLength(SUFFIXES.length + KEPT.length);
    expect(JSON.parse(fetchMock.mock.calls[0][1].body).Token).toBe('refresh-user-a');
  });

  it('removes the local keys even when the revoke fails, never throws, never logs the token', async () => {
    seed('user-a');
    data.set(`${P}LastAuthUser`, 'user-a');
    fetchMock.mockRejectedValue(new Error('offline'));
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { revoked } = await discardStoredSession('user-a');
    expect(await revoked).toBe(false);
    expect(data.has(`${P}user-a.refreshToken`)).toBe(false);
    expect(err).toHaveBeenCalledOnce();
    expect(JSON.stringify(err.mock.calls)).not.toContain('refresh-user-a');
    err.mockRestore();
  });

  it('a non-2xx RevokeToken reply is a failed revoke', async () => {
    seed('user-a');
    fetchMock.mockResolvedValue(new Response('{}', { status: 400 }));
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await (await discardStoredSession('user-a')).revoked).toBe(false);
    expect(err.mock.calls[0][1]).toBe('RevokeToken failed with status 400');
    err.mockRestore();
  });

  it('skips the revoke for tokens without origin_jti (not revocable), still removing them', async () => {
    seed('user-a', { revocable: false });
    expect(await (await discardStoredSession('user-a')).revoked).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(data.has(`${P}user-a.refreshToken`)).toBe(false);
  });

  it('makes no request when the user has no refresh token', async () => {
    await discardStoredSession('nobody');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('restoreStoredSession', () => {
  it('makes the user current again when no one is and their refresh token is stored', async () => {
    seed('user-b');
    expect(await restoreStoredSession('user-b')).toBe(true);
    expect(data.get(`${P}LastAuthUser`)).toBe('user-b');
  });

  it('does not overwrite a current user', async () => {
    seed('user-b');
    data.set(`${P}LastAuthUser`, 'user-c');
    expect(await restoreStoredSession('user-b')).toBe(false);
    expect(data.get(`${P}LastAuthUser`)).toBe('user-c');
  });

  it('does nothing for a user with no stored refresh token', async () => {
    expect(await restoreStoredSession('ghost')).toBe(false);
    expect(data.has(`${P}LastAuthUser`)).toBe(false);
  });
});
