import * as React from 'react';
import { useMemo, type PropsWithChildren } from 'react';
import {
  createCognitoAuth as createCognitoAuthV3,
  buildTotpUri,
  type AuthenticateResult,
  type CompleteNewPasswordChallengeFn,
  type RespondToTotpChallengeFn,
  type SendCustomChallengeAnswerFn,
} from './index';
import { adaptToLegacyBuildUser } from './legacyAdapter';

/** @deprecated v2-shape config. Use v3's UserPoolConfig instead - see MIGRATION.md. */
export type UserPoolConfig = {
  UserPoolId: string;
  ClientId: string;
  AuthFlow?: 'USER_SRP_AUTH' | 'CUSTOM_AUTH';
};

/** @deprecated v2-shape callback. Use v3's BuildUserFn instead - see MIGRATION.md. */
export type BuildUserFn<User> = (
  user: { getUsername: () => string },
  attr: { Name: string; Value: string }[],
) => User;

/** @deprecated See MIGRATION.md. */
export const defaultBuildUser: BuildUserFn<{ id: string; email: string }> = (
  user,
  attr,
) => {
  const email = attr.find((a) => a.Name === 'email')?.Value;
  if (!email) {
    throw new Error('Email not found in attributes');
  }
  return { id: user.getUsername(), email };
};

/** @deprecated Unchanged from v3's real API - re-exported here for convenience only. */
export type { AuthenticateResult };
/** @deprecated Unchanged from v3's real API - re-exported here for convenience only. */
export type { CompleteNewPasswordChallengeFn };
/** @deprecated Unchanged from v3's real API - re-exported here for convenience only. */
export type { RespondToTotpChallengeFn };
/** @deprecated Unchanged from v3's real API - re-exported here for convenience only. */
export type { SendCustomChallengeAnswerFn };
/** @deprecated Unchanged from v3's real API - re-exported here for convenience only. */
export { buildTotpUri };

/** @deprecated Use v3's real createCognitoAuth instead - see MIGRATION.md. */
export function createCognitoAuth<User extends object>(
  buildUserLegacy: BuildUserFn<User>,
) {
  const buildUserV3 = (
    authUser: { username: string },
    attributes: Record<string, string | undefined>,
  ): User => {
    const { user, attr } = adaptToLegacyBuildUser(authUser, attributes);
    return buildUserLegacy(user, attr);
  };

  const { useAuthContext, AuthContext, AuthProvider } =
    createCognitoAuthV3(buildUserV3);

  const CognitoAuthProvider = ({
    userPool,
    children,
  }: PropsWithChildren<{ userPool: UserPoolConfig }>) => {
    // Memoized so identity is stable across renders even though v3's
    // AuthProvider effect is keyed on the primitive fields, not the object.
    const v3Pool = useMemo(
      () => ({
        userPoolId: userPool.UserPoolId,
        userPoolClientId: userPool.ClientId,
        // CUSTOM_AUTH (SRP-first custom auth in amazon-cognito-identity-js)
        // maps to Amplify's CUSTOM_WITH_SRP, not CUSTOM_WITHOUT_SRP.
        authFlowType:
          userPool.AuthFlow === 'CUSTOM_AUTH'
            ? ('CUSTOM_WITH_SRP' as const)
            : userPool.AuthFlow,
      }),
      [userPool.UserPoolId, userPool.ClientId, userPool.AuthFlow],
    );
    return <AuthProvider userPool={v3Pool}>{children}</AuthProvider>;
  };

  return {
    useCognitoAuthContext: useAuthContext,
    CognitoAuthContext: AuthContext,
    CognitoAuthProvider,
  };
}
