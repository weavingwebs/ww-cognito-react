import { signIn } from 'aws-amplify/auth';
import { signInIgnoringSession } from './reauth';
import {
  signInHandlingExistingSession,
  type OnExistingSession,
} from './sessionGuards';
import type { AuthenticateOptions, AuthenticateResult } from './types';

type SignInOutput = Awaited<ReturnType<typeof signIn>>;
type AuthFlowType = 'USER_SRP_AUTH' | 'CUSTOM_WITH_SRP';
type MapSignInResult = (
  output: SignInOutput,
  clientMetadata?: Record<string, string>,
) => Promise<AuthenticateResult>;

function signInInput(
  username: string,
  password: string,
  authFlowType: AuthFlowType,
  clientMetadata?: Record<string, string>,
) {
  return {
    username,
    password,
    options: {
      authFlowType,
      ...(clientMetadata ? { clientMetadata } : {}),
    },
  };
}

// The body of AuthState.authenticate, extracted so it is unit-testable without
// a React tree.
export async function authenticateWith(deps: {
  email: string;
  pass: string;
  opts?: AuthenticateOptions;
  authFlowType: AuthFlowType;
  mapSignInResult: MapSignInResult;
  loadUserFromSession: () => Promise<unknown>;
  forceSignOut: () => Promise<void>;
}): Promise<AuthenticateResult> {
  const { email, pass, opts, authFlowType, mapSignInResult } = deps;
  const clientMetadata = opts?.clientMetadata;

  // Amplify refuses to sign in if it thinks a session is already active, even
  // if our app state disagrees (e.g. a stale local session). See
  // signInHandlingExistingSession.
  const onExistingSession: OnExistingSession | undefined =
    opts?.onExistingSession;
  const result = await signInHandlingExistingSession(
    () => signIn(signInInput(email.trim(), pass, authFlowType, clientMetadata)),
    deps.forceSignOut,
    onExistingSession,
    deps.loadUserFromSession,
  );
  return mapSignInResult(result, clientMetadata);
}

// The body of AuthStateLoggedIn.reauthenticate. The live session is left alone
// until Amplify stores the new tokens over it on success.
export async function reauthenticateWith(deps: {
  username: string;
  pass: string;
  clientMetadata?: Record<string, string>;
  authFlowType: AuthFlowType;
  mapSignInResult: MapSignInResult;
}): Promise<AuthenticateResult> {
  const { username, pass, clientMetadata, authFlowType } = deps;
  const result = await signInIgnoringSession(
    signInInput(username, pass, authFlowType, clientMetadata),
  );
  return deps.mapSignInResult(result, clientMetadata);
}
