import * as React from 'react';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FC,
  type PropsWithChildren,
} from 'react';
import { Amplify } from 'aws-amplify';
import {
  confirmResetPassword as amplifyConfirmResetPassword,
  confirmUserAttribute,
  fetchAuthSession,
  fetchUserAttributes,
  getCurrentUser,
  resetPassword as amplifyResetPassword,
  setUpTOTP,
  signIn,
  signOut,
  updatePassword,
  updateUserAttributes,
  verifyTOTPSetup,
} from 'aws-amplify/auth';
import { createMapSignInResult } from './mapSignInResult';
import type { AuthState, BuildUserFn, UserPoolConfig } from './types';

function shallowEqual(a: object, b: object): boolean {
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  return (
    aKeys.length === bKeys.length &&
    aKeys.every(
      (k) => (a as Record<string, unknown>)[k] === (b as Record<string, unknown>)[k],
    )
  );
}

// Clears any local Amplify session regardless of app state - safe to call
// even when not logged in, so callers always have a way to recover from a
// stale session.
export async function forceSignOut(): Promise<void> {
  try {
    await signOut();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[ww-cognito-react] forceSignOut failed', err);
  }
}

type CurrentUser<User> = {
  session: Awaited<ReturnType<typeof fetchAuthSession>>;
  authUser: Awaited<ReturnType<typeof getCurrentUser>>;
  user: User;
};

export function createCognitoAuth<User extends object>(
  buildUser: BuildUserFn<User>,
) {
  const AuthContext = createContext<AuthState<User> | null>(null);

  const useAuthContext = (): AuthState<User> => {
    const ctx = useContext(AuthContext);
    if (ctx === null) {
      throw new Error('useAuthContext must be used within an AuthProvider');
    }
    return ctx;
  };

  // Only use within an auth-gated page - throws if not logged in (or still
  // loading).
  const useAuthContextOrDie = () => {
    const ctx = useAuthContext();
    if (ctx.isLoggedIn === null) {
      throw new Error(
        'auth context has died - auth context is loading (isLoggedIn === null)',
      );
    }
    if (!ctx.isLoggedIn) {
      throw new Error('auth context has died - not logged in');
    }
    return ctx;
  };

  const AuthProvider: FC<PropsWithChildren<{ userPool: UserPoolConfig }>> = ({
    userPool,
    children,
  }) => {
    const [isLoggedIn, setIsLoggedIn] = useState<boolean | null>(null);
    const [currentUser, setCurrentUser] = useState<CurrentUser<User> | null>(
      null,
    );
    const currentUserRef = useRef<CurrentUser<User> | null>(null);

    // Protects against a stale async result landing after the pool changed.
    const versionRef = useRef(0);

    const clearCurrentUser = useCallback(() => {
      setIsLoggedIn(false);
      setCurrentUser(null);
      currentUserRef.current = null;
    }, []);

    const loadUserFromSession = useCallback(async () => {
      const [session, authUser, attributes] = await Promise.all([
        fetchAuthSession(),
        getCurrentUser(),
        fetchUserAttributes(),
      ]);
      const freshUser = buildUser(authUser, attributes);
      const user =
        currentUserRef.current &&
        shallowEqual(currentUserRef.current.user, freshUser)
          ? currentUserRef.current.user
          : freshUser;
      // Always a new wrapper object, even when `user` is reused - see the
      // README. Do not replace with Object.assign/mutation, see MIGRATION.md.
      const newCurrentUser: CurrentUser<User> = { session, authUser, user };
      setCurrentUser(newCurrentUser);
      currentUserRef.current = newCurrentUser;
      setIsLoggedIn(true);
      return user;
    }, []);

    // Configure Amplify (a process-wide singleton - see README) and check
    // session whenever the user pool changes.
    useEffect(() => {
      const version = ++versionRef.current;

      Amplify.configure({
        Auth: {
          Cognito: {
            userPoolId: userPool.userPoolId,
            userPoolClientId: userPool.userPoolClientId,
          },
        },
      });

      fetchAuthSession()
        .then((session) => {
          if (version !== versionRef.current) return;
          if (session.tokens) {
            return loadUserFromSession().catch(async () => {
              await forceSignOut();
              if (version !== versionRef.current) return;
              clearCurrentUser();
            });
          }
          clearCurrentUser();
        })
        .catch(async () => {
          await forceSignOut();
          if (version !== versionRef.current) return;
          clearCurrentUser();
        });
    }, [
      userPool.userPoolId,
      userPool.userPoolClientId,
      loadUserFromSession,
      clearCurrentUser,
    ]);

    const mapSignInResult = useMemo(
      () => createMapSignInResult(loadUserFromSession),
      [loadUserFromSession],
    );

    const authenticate = useCallback(
      async (email: string, pass: string) => {
        const authFlowType = userPool.authFlowType ?? 'USER_SRP_AUTH';
        const doSignIn = () =>
          signIn({
            username: email.trim(),
            password: pass,
            options: { authFlowType },
          });

        let result;
        try {
          result = await doSignIn();
        } catch (err) {
          // Amplify refuses to sign in if it thinks a session is already
          // active, even if our app state disagrees (e.g. a stale local
          // session left behind by a failed session check). Force a sign
          // out and retry once rather than surfacing this to the user.
          if (
            err instanceof Error &&
            err.name === 'UserAlreadyAuthenticatedException'
          ) {
            await forceSignOut();
            result = await doSignIn();
          } else {
            throw err;
          }
        }
        return mapSignInResult(result);
      },
      [userPool.authFlowType, mapSignInResult],
    );

    const getIdJwt = useCallback(async (): Promise<string | null> => {
      try {
        const session = await fetchAuthSession();
        return session.tokens?.idToken?.toString() ?? null;
      } catch {
        return null;
      }
    }, []);

    const getAccessJwt = useCallback(async (): Promise<string | null> => {
      try {
        const session = await fetchAuthSession();
        return session.tokens?.accessToken?.toString() ?? null;
      } catch {
        return null;
      }
    }, []);

    const logout = useCallback(async (): Promise<void> => {
      await signOut();
      clearCurrentUser();
    }, [clearCurrentUser]);

    const changePassword = useCallback(
      async (oldPwd: string, newPwd: string): Promise<void> => {
        await updatePassword({ oldPassword: oldPwd, newPassword: newPwd });
      },
      [],
    );

    const resetPassword = useCallback(async (email: string): Promise<void> => {
      await amplifyResetPassword({ username: email });
    }, []);

    const confirmResetPassword = useCallback(
      async (
        email: string,
        verificationCode: string,
        newPassword: string,
      ): Promise<void> => {
        await amplifyConfirmResetPassword({
          username: email,
          confirmationCode: verificationCode,
          newPassword,
        });
      },
      [],
    );

    const updateEmail = useCallback(
      async (email: string) => {
        await updateUserAttributes({ userAttributes: { email } });
        return {
          verifyEmail: async (verificationCode: string): Promise<void> => {
            await confirmUserAttribute({
              userAttributeKey: 'email',
              confirmationCode: verificationCode,
            });
            await loadUserFromSession();
          },
        };
      },
      [loadUserFromSession],
    );

    const associateTotp = useCallback(async (): Promise<string> => {
      const totpSetup = await setUpTOTP();
      return totpSetup.sharedSecret;
    }, []);

    const verifyTotp = useCallback(
      async (totpCode: string, friendlyDeviceName: string): Promise<void> => {
        await verifyTOTPSetup({
          code: totpCode,
          options: { friendlyDeviceName },
        });
      },
      [],
    );

    const authState = useMemo((): AuthState<User> => {
      if (isLoggedIn === null) {
        return { isLoggedIn: null };
      }
      if (!isLoggedIn || !currentUser) {
        return {
          isLoggedIn: false,
          authenticate,
          resetPassword,
          confirmResetPassword,
        };
      }
      return {
        isLoggedIn: true,
        user: currentUser.user,
        getAccessJwt,
        getIdJwt,
        logout,
        changePassword,
        updateEmail,
        associateTotp,
        verifyTotp,
        authenticate,
        resetPassword,
        confirmResetPassword,
      };
    }, [
      isLoggedIn,
      currentUser,
      authenticate,
      resetPassword,
      confirmResetPassword,
      getAccessJwt,
      getIdJwt,
      logout,
      changePassword,
      updateEmail,
      associateTotp,
      verifyTotp,
    ]);

    return (
      <AuthContext.Provider value={authState}>{children}</AuthContext.Provider>
    );
  };

  return { useAuthContext, useAuthContextOrDie, AuthContext, AuthProvider };
}
