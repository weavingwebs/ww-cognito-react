import { signIn } from 'aws-amplify/auth';
import {
  hasActiveReauth,
  runWithReauthGuard,
  type ReauthGuard,
} from './reauthGuard';
import {
  signInHandlingExistingSession,
  type OnExistingSession,
} from './sessionGuards';
import type { AuthenticateOptions, AuthenticateResult } from './types';

type SignInOutput = Awaited<ReturnType<typeof signIn>>;
type MapSignInResult = (
  output: SignInOutput,
  guard: ReauthGuard | null,
  clientMetadata?: Record<string, string>,
) => Promise<AuthenticateResult>;

// The body of AuthState.authenticate, extracted so it is unit-testable without
// a React tree.
export async function authenticateWith(deps: {
  email: string;
  pass: string;
  opts?: AuthenticateOptions;
  authFlowType: 'USER_SRP_AUTH' | 'CUSTOM_WITH_SRP';
  mapSignInResult: MapSignInResult;
  loadUserFromSession: () => Promise<unknown>;
  forceSignOut: () => Promise<void>;
}): Promise<AuthenticateResult> {
  const { email, pass, opts, authFlowType, mapSignInResult } = deps;
  const clientMetadata = opts?.clientMetadata;
  const doSignIn = () =>
    signIn({
      username: email.trim(),
      password: pass,
      options: {
        authFlowType,
        ...(clientMetadata ? { clientMetadata } : {}),
      },
    });

  if (opts?.allowWhileLoggedIn) {
    // Bypasses onExistingSession entirely: the attempt runs against a private
    // store with no session, so there is nothing to replace, reject or sign
    // out. See reauthGuard.ts.
    const { result, guard } = await runWithReauthGuard(doSignIn, {
      signal: opts.signal,
    });
    return mapSignInResult(result, guard, clientMetadata);
  }

  // A plain sign-in during a re-auth attempt would run against the attempt's
  // private store and load a user the real storage doesn't hold.
  if (hasActiveReauth()) {
    throw new Error('A re-auth attempt is in progress');
  }

  // Amplify refuses to sign in if it thinks a session is already active, even
  // if our app state disagrees (e.g. a stale local session). See
  // signInHandlingExistingSession.
  const onExistingSession: OnExistingSession | undefined =
    opts?.onExistingSession;
  const result = await signInHandlingExistingSession(
    doSignIn,
    deps.forceSignOut,
    onExistingSession,
    deps.loadUserFromSession,
  );
  return mapSignInResult(result, null, clientMetadata);
}
