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

let respond: (target: string, body: Record<string, unknown>) => { status: number; body: object };
let calls: string[] = [];

const authTime = async () =>
  (await fetchAuthSession()).tokens?.idToken?.payload.auth_time ?? null;
type Flow = 'USER_SRP_AUTH' | 'CUSTOM_WITH_SRP';
const flows: Flow[] = ['USER_SRP_AUTH', 'CUSTOM_WITH_SRP'];
let input = {
  username: 'auser',
  password: 'pw',
  options: { authFlowType: 'USER_SRP_AUTH' as Flow },
};
// The two flows the library can be configured with. The fake Cognito answers
// the SRP handshake with arbitrary (non-zero) SRP values and accepts whatever
// signature comes back; `after` is what it replies to the PASSWORD_VERIFIER.
const srp = (after: () => { status: number; body: object }) =>
  (target: string, body: Record<string, unknown>) =>
    target.indexOf('InitiateAuth') >= 0
      ? {
          status: 200,
          body: {
            ChallengeName: 'PASSWORD_VERIFIER',
            Session: 's0',
            ChallengeParameters: {
              SALT: 'abcdef0123456789',
              SECRET_BLOCK: 'c2VjcmV0',
              SRP_B: '1234567890abcdef1234567890abcdef1234567890abcdef',
              USER_ID_FOR_SRP: 'auser',
            },
          },
        }
      : body.ChallengeName === 'PASSWORD_VERIFIER'
        ? after()
        : { status: 400, body: { __type: 'InternalErrorException', message: target } };
const signedIn = (authTime: number) => () => ({
  status: 200,
  body: { AuthenticationResult: tokensFor(authTime) },
});
const totpChallenge = () => ({
  status: 200,
  body: { ChallengeName: 'SOFTWARE_TOKEN_MFA', Session: 's1', ChallengeParameters: {} },
});
const wrongPassword = () => ({
  status: 400,
  body: { __type: 'NotAuthorizedException', message: 'Incorrect username or password.' },
});

beforeAll(() => {
  Amplify.configure({
    Auth: { Cognito: { userPoolId: 'eu-west-2_test', userPoolClientId: 'client' } },
  });
  cognitoUserPoolsTokenProvider.setKeyValueStorage(storage);
  globalThis.fetch = (async (_url: unknown, init: { headers: Record<string, string>; body?: unknown }) => {
    const target = new Headers(init.headers).get('x-amz-target') ?? '';
    calls.push(target.split('.')[1]);
    const { status, body } = respond(target, JSON.parse(String(init.body ?? '{}')));
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/x-amz-json-1.1' },
    });
  }) as never;
});

const seedSession = async () => {
  calls = [];
  data.clear();
  // Seed a live session with an old auth_time.
  respond = srp(signedIn(1000));
  await signIn(input);
  calls = [];
  expect(await authTime()).toBe(1000);
};

describe.each(flows)('signInIgnoringSession (%s)', (flow) => {
  beforeEach(async () => {
    input = { ...input, options: { authFlowType: flow } };
    await seedSession();
  });

  it('control: a plain signIn is refused without reaching Cognito', async () => {
    await expect(signIn(input)).rejects.toMatchObject({
      name: 'UserAlreadyAuthenticatedException',
    });
    expect(calls).toEqual([]);
  });

  it('reads the (hidden) session exactly once, before any request', async () => {
    const order: string[] = [];
    const inner = respond;
    respond = srp(signedIn(2000));
    const fetchBefore = globalThis.fetch;
    globalThis.fetch = (async (...args: Parameters<typeof fetch>) => {
      order.push('request');
      return fetchBefore(...args);
    }) as never;
    try {
      await signInIgnoringSession(input, { onHiddenRead: () => order.push('hidden') });
    } finally {
      globalThis.fetch = fetchBefore;
      respond = inner;
    }
    expect(order.filter((o) => o === 'hidden')).toHaveLength(1);
    expect(order[0]).toBe('hidden');
  });

  it('a wrong password rejects & leaves the live session intact', async () => {
    respond = srp(wrongPassword);
    await expect(signInIgnoringSession(input)).rejects.toMatchObject({
      name: 'NotAuthorizedException',
    });
    expect(calls).toEqual(['InitiateAuth', 'RespondToAuthChallenge']);
    expect(await authTime()).toBe(1000);
  });

  it('success replaces the session with a fresh auth_time', async () => {
    respond = srp(signedIn(2000));
    expect((await signInIgnoringSession(input)).isSignedIn).toBe(true);
    expect(await authTime()).toBe(2000);
  });

  it('the live session stays usable through a challenge, then is replaced', async () => {
    respond = (target, body) =>
      body.ChallengeName === 'SOFTWARE_TOKEN_MFA'
        ? signedIn(3000)()
        : srp(totpChallenge)(target, body);
    const step = await signInIgnoringSession(input);
    expect(step.nextStep.signInStep).toBe('CONFIRM_SIGN_IN_WITH_TOTP_CODE');
    expect(await authTime()).toBe(1000);

    const done = await confirmSignIn({ challengeResponse: '123456' });
    expect(done.isSignedIn).toBe(true);
    expect(await authTime()).toBe(3000);
  });

  it('a failed challenge answer leaves the live session intact', async () => {
    respond = (target, body) =>
      body.ChallengeName === 'SOFTWARE_TOKEN_MFA'
        ? { status: 400, body: { __type: 'CodeMismatchException', message: 'Invalid code' } }
        : srp(totpChallenge)(target, body);
    await signInIgnoringSession(input);
    await expect(confirmSignIn({ challengeResponse: '000000' })).rejects.toMatchObject({
      name: 'CodeMismatchException',
    });
    expect(await authTime()).toBe(1000);
  });

  it('TOTP set-up (MFA_SETUP) leaves the live session intact until the code is verified', async () => {
    respond = (target, body) => {
      if (target.indexOf('AssociateSoftwareToken') >= 0) {
        return { status: 200, body: { SecretCode: 'SECRET', Session: 's2' } };
      }
      if (target.indexOf('VerifySoftwareToken') >= 0) {
        return { status: 200, body: { Status: 'SUCCESS', Session: 's3' } };
      }
      if (body.ChallengeName === 'MFA_SETUP') return signedIn(5000)();
      return srp(() => ({
        status: 200,
        body: {
          ChallengeName: 'MFA_SETUP',
          Session: 's1',
          ChallengeParameters: { MFAS_CAN_SETUP: '["SOFTWARE_TOKEN_MFA"]' },
        },
      }))(target, body);
    };
    const step = await signInIgnoringSession(input);
    expect(step.nextStep.signInStep).toBe('CONTINUE_SIGN_IN_WITH_TOTP_SETUP');
    expect(await authTime()).toBe(1000);

    expect((await confirmSignIn({ challengeResponse: '123456' })).isSignedIn).toBe(true);
    expect(await authTime()).toBe(5000);
  });

  it('the session is only hidden from the attempt, not from other callers', async () => {
    respond = srp(signedIn(4000));
    const attempt = signInIgnoringSession(input);
    expect(await authTime()).toBe(1000);
    expect((await attempt).isSignedIn).toBe(true);
    expect(await authTime()).toBe(4000);
  });
});
