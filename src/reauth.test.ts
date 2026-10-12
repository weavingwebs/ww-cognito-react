// @vitest-environment node
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Amplify } from 'aws-amplify';
import { confirmSignIn, fetchAuthSession, signIn } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import { signInIgnoringSession } from './reauth';

// NOTE: runs real Amplify against a faked Cognito endpoint, to pin the
// internals signInIgnoringSession relies on. Expect to revisit on an Amplify
// upgrade if this fails.
const b64 = (o: object) =>
  btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const jwt = (claims: object) => `${b64({ alg: 'none' })}.${b64(claims)}.sig`;
const now = () => Math.floor(Date.now() / 1000);
const tokensFor = (authTime: number) => {
  const claims = { sub: 'auser', exp: now() + 3600, iat: now(), auth_time: authTime };
  return {
    AccessToken: jwt({ ...claims, username: 'auser' }),
    IdToken: jwt({ ...claims, 'cognito:username': 'auser' }),
    RefreshToken: `refresh-${authTime}`,
  };
};

const data = new Map<string, string>();
const storage = {
  setItem: async (k: string, v: string) => void data.set(k, v),
  getItem: async (k: string) => data.get(k) ?? null,
  removeItem: async (k: string) => void data.delete(k),
  clear: async () => data.clear(),
};

let respond: (target: string) => { status: number; body: object };
let calls: string[] = [];

const authTime = async () =>
  (await fetchAuthSession()).tokens?.idToken?.payload.auth_time ?? null;
const input = {
  username: 'auser',
  password: 'pw',
  options: { authFlowType: 'USER_PASSWORD_AUTH' as const },
};
const wrongPassword = () => ({
  status: 400,
  body: { __type: 'NotAuthorizedException', message: 'Incorrect username or password.' },
});

beforeAll(() => {
  Amplify.configure({
    Auth: { Cognito: { userPoolId: 'eu-west-2_test', userPoolClientId: 'client' } },
  });
  cognitoUserPoolsTokenProvider.setKeyValueStorage(storage);
  globalThis.fetch = (async (_url: unknown, init: { headers: Record<string, string> }) => {
    const target = new Headers(init.headers).get('x-amz-target') ?? '';
    calls.push(target.split('.')[1]);
    const { status, body } = respond(target);
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/x-amz-json-1.1' },
    });
  }) as never;
});

beforeEach(async () => {
  calls = [];
  data.clear();
  // Seed a live session with an old auth_time.
  respond = () => ({ status: 200, body: { AuthenticationResult: tokensFor(1000) } });
  await signIn(input);
  calls = [];
  expect(await authTime()).toBe(1000);
});

describe('signInIgnoringSession', () => {
  it('control: a plain signIn is refused without reaching Cognito', async () => {
    await expect(signIn(input)).rejects.toMatchObject({
      name: 'UserAlreadyAuthenticatedException',
    });
    expect(calls).toEqual([]);
  });

  it('a wrong password rejects & leaves the live session intact', async () => {
    respond = wrongPassword;
    await expect(signInIgnoringSession(input)).rejects.toMatchObject({
      name: 'NotAuthorizedException',
    });
    expect(calls).toEqual(['InitiateAuth']);
    expect(await authTime()).toBe(1000);
  });

  it('success replaces the session with a fresh auth_time', async () => {
    respond = () => ({ status: 200, body: { AuthenticationResult: tokensFor(2000) } });
    expect((await signInIgnoringSession(input)).isSignedIn).toBe(true);
    expect(await authTime()).toBe(2000);
  });

  it('the live session stays usable through a challenge, then is replaced', async () => {
    respond = (target) =>
      target.indexOf('InitiateAuth') >= 0
        ? { status: 200, body: { ChallengeName: 'SOFTWARE_TOKEN_MFA', Session: 's', ChallengeParameters: {} } }
        : { status: 200, body: { AuthenticationResult: tokensFor(3000) } };
    const step = await signInIgnoringSession(input);
    expect(step.nextStep.signInStep).toBe('CONFIRM_SIGN_IN_WITH_TOTP_CODE');
    expect(await authTime()).toBe(1000);

    const done = await confirmSignIn({ challengeResponse: '123456' });
    expect(done.isSignedIn).toBe(true);
    expect(await authTime()).toBe(3000);
  });

  it('a failed challenge answer leaves the live session intact', async () => {
    respond = (target) =>
      target.indexOf('InitiateAuth') >= 0
        ? { status: 200, body: { ChallengeName: 'SOFTWARE_TOKEN_MFA', Session: 's', ChallengeParameters: {} } }
        : { status: 400, body: { __type: 'CodeMismatchException', message: 'Invalid code' } };
    await signInIgnoringSession(input);
    await expect(confirmSignIn({ challengeResponse: '000000' })).rejects.toMatchObject({
      name: 'CodeMismatchException',
    });
    expect(await authTime()).toBe(1000);
  });

  it('the session is only hidden from the attempt, not from other callers', async () => {
    respond = () => ({ status: 200, body: { AuthenticationResult: tokensFor(4000) } });
    const attempt = signInIgnoringSession(input);
    expect(await authTime()).toBe(1000);
    expect((await attempt).isSignedIn).toBe(true);
    expect(await authTime()).toBe(4000);
  });
});
