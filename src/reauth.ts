import { Amplify } from 'aws-amplify';
import { signIn } from 'aws-amplify/auth';
import {
  cognitoCredentialsProvider,
  cognitoUserPoolsTokenProvider,
} from 'aws-amplify/auth/cognito';
import { defaultStorage } from 'aws-amplify/utils';

type GetTokens = typeof cognitoUserPoolsTokenProvider.getTokens;

let hideSession = false;

const tokenProvider: { getTokens: GetTokens } = {
  getTokens: (options) =>
    hideSession
      ? Promise.resolve(null)
      : cognitoUserPoolsTokenProvider.getTokens(options),
};

// Amplify's signIn refuses to run while a session exists, so a signed-in user
// cannot re-authenticate (e.g. to reset `auth_time`) without signing out.
// NOTE: its only check reads the token provider synchronously inside the
// signIn() call, so the session is hidden for exactly that read (verified
// against aws-amplify 6.20.0, pinned by reauth.test.ts).
export function signInIgnoringSession(
  input: Parameters<typeof signIn>[0],
): ReturnType<typeof signIn> {
  hideSession = true;
  try {
    return signIn(input);
  } finally {
    hideSession = false;
  }
}

// NOTE: passing our own token provider skips aws-amplify's default wiring of
// the Cognito provider, so it is repeated here.
export function configureAmplify(cognito: {
  userPoolId: string;
  userPoolClientId: string;
}): void {
  const config = { Auth: { Cognito: cognito } };
  cognitoUserPoolsTokenProvider.setAuthConfig(config.Auth);
  cognitoUserPoolsTokenProvider.setKeyValueStorage(defaultStorage);
  Amplify.configure(config, {
    Auth: { tokenProvider, credentialsProvider: cognitoCredentialsProvider },
  });
}
