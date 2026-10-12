import { Amplify, createAmplifyContext } from 'aws-amplify';
import { signIn, type SignInInput, type SignInOutput } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';

type GetTokens = typeof cognitoUserPoolsTokenProvider.getTokens;

// Amplify's signIn refuses to run while a session exists, so a signed-in user
// cannot re-authenticate (e.g. to reset `auth_time`) without signing out.
// This signs in through a throwaway context whose first token read (that
// check) sees no session; every later read & write uses the real one.
// NOTE: relies on Amplify internals (verified against aws-amplify 6.22.1,
// pinned by reauth.test.ts).
export function signInIgnoringSession(
  input: SignInInput,
): Promise<SignInOutput> {
  let hidden = true;
  const getTokens: GetTokens = (options) => {
    if (hidden) {
      hidden = false;
      return Promise.resolve(null);
    }
    return cognitoUserPoolsTokenProvider.getTokens(options);
  };
  const ctx = createAmplifyContext(Amplify.getConfig(), {
    Auth: { tokenProvider: { getTokens } },
  });
  return signIn(ctx, input);
}
