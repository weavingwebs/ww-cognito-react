import { signIn } from 'aws-amplify/auth';
import {
  createReauthGuard,
  createSupersessionGuard,
  defaultReauthDeps,
  signInIgnoringSession,
} from './reauth';
import {
  signInHandlingExistingSession,
  type OnExistingSession,
} from './sessionGuards';
import type { ReauthGuard, ReauthGuardDeps } from './reauth';
import type { AuthenticateOptions, AuthenticateResult } from './types';

type SignInOutput = Awaited<ReturnType<typeof signIn>>;
type AuthFlowType = 'USER_SRP_AUTH' | 'CUSTOM_WITH_SRP';
type MapSignInResult = (
  output: SignInOutput,
  clientMetadata?: Record<string, string>,
  guard?: ReauthGuard,
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
  // Amplify has one global sign-in state: this starts a new exchange, and ends
  // any older one.
  const guard = createSupersessionGuard();

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
  return mapSignInResult(result, clientMetadata, guard);
}

// The body of AuthStateLoggedIn.reauthenticate. The live session is left alone
// until Amplify stores the new tokens over it on success.
export async function reauthenticateWith(deps: {
  username: string;
  pass: string;
  clientMetadata?: Record<string, string>;
  authFlowType: AuthFlowType;
  mapSignInResult: MapSignInResult;
  // The tab's current user (a logout clears it) and the session's auth_time.
  tabUsername: () => string | undefined;
  startAuthTime: number | undefined;
  clearTabUser: () => void;
  // Overrides for tests.
  guardDeps?: Partial<ReauthGuardDeps>;
}): Promise<AuthenticateResult> {
  const { username, pass, clientMetadata, authFlowType } = deps;
  const guardDeps = { ...defaultReauthDeps, ...deps.guardDeps };
  // The tab's snapshot can be older than the stored session (another tab may
  // have re-authenticated): the new auth_time must beat whichever is newer.
  const stored = await guardDeps.liveAuthTime().catch(() => undefined);
  const guard = createReauthGuard({
    username,
    startAuthTime:
      deps.startAuthTime === undefined || stored === undefined
        ? (deps.startAuthTime ?? stored)
        : Math.max(deps.startAuthTime, stored),
    tabUsername: deps.tabUsername,
    clearTabUser: deps.clearTabUser,
    ...guardDeps,
  });
  // Amplify stores the new tokens as soon as it succeeds, so with no challenge
  // this is the only chance to see that the session changed since this tab
  // loaded it.
  await guard.beforeStep();
  const result = await signInIgnoringSession(
    signInInput(username, pass, authFlowType, clientMetadata),
  );
  return deps.mapSignInResult(result, clientMetadata, guard);
}
