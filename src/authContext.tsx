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
import { Hub } from 'aws-amplify/utils';
import {
  confirmResetPassword as amplifyConfirmResetPassword,
  confirmUserAttribute,
  fetchAuthSession,
  fetchUserAttributes,
  getCurrentUser,
  resetPassword as amplifyResetPassword,
  setUpTOTP,
  signOut,
  updatePassword,
  updateUserAttributes,
  verifyTOTPSetup,
} from 'aws-amplify/auth';
import { authenticateWith } from './authenticate';
import { claimsFromSession } from './claims';
import { createMapSignInResult } from './mapSignInResult';
import {
  getGuardedJwt,
  hasActiveReauth,
  onReauthSettled,
  reapplyReauthStorage,
  rollbackPendingReauth,
} from './reauthGuard';
import {
  checkSessionAfterReauth,
  checkSessionOnMount,
  refreshAndReload,
  shouldLogOutOnHubEvent,
} from './sessionGuards';
import type {
  AuthenticateOptions,
  AuthState,
  BuildUserFn,
  UserPoolConfig,
} from './types';

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

// Calls Amplify signOut() (revokes the refresh token where applicable, then
// clears local tokens) regardless of app state - safe to call even when not
// logged in. Does not update AuthProvider state. A pending re-auth attempt is
// rolled back first: signing out must never run against its private store.
export async function forceSignOut(): Promise<void> {
  try {
    await rollbackPendingReauth();
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
      // Configure resets the token provider's storage to localStorage; put a
      // pending re-auth attempt's private store back.
      reapplyReauthStorage();

      // Never signOut on failure: a transient error at page load must not
      // revoke the refresh token. See checkSessionOnMount.
      const runMountCheck = () =>
        checkSessionOnMount({
          fetchSession: fetchAuthSession,
          loadUser: loadUserFromSession,
          clearCurrentUser,
          isStale: () => version !== versionRef.current,
        });
      // A remount / pool change mid re-auth would read the private store and
      // log the app out: defer the check until the attempt settles.
      let mountCheckDeferred = false;
      if (hasActiveReauth()) {
        mountCheckDeferred = true;
      } else {
        runMountCheck();
      }

      // Log the app out (state only, never signOut) when Amplify has cleared
      // the tokens after a failed refresh - otherwise isLoggedIn stays true while getIdJwt() is null.
      const stopListening = Hub.listen('auth', ({ payload }) => {
        if (version !== versionRef.current) return;
        // Re-auth attempts are ignored here, re-checked on rollback below.
        if (shouldLogOutOnHubEvent(payload, hasActiveReauth())) {
          clearCurrentUser();
        }
      });
      const stopReauthListening = onReauthSettled((outcome) => {
        if (mountCheckDeferred) {
          mountCheckDeferred = false;
          runMountCheck();
          return;
        }
        if (outcome !== 'rollback') return;
        void checkSessionAfterReauth({
          fetchSession: fetchAuthSession,
          clearCurrentUser,
          isStale: () => version !== versionRef.current,
        });
      });
      return () => {
        stopListening();
        stopReauthListening();
      };
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
      async (
        email: string,
        pass: string,
        opts?: AuthenticateOptions,
      ) => {
        return authenticateWith({
          email,
          pass,
          opts,
          authFlowType: userPool.authFlowType ?? 'USER_SRP_AUTH',
          mapSignInResult,
          loadUserFromSession,
          forceSignOut,
        });
      },
      [userPool.authFlowType, mapSignInResult, loadUserFromSession],
    );

    const getIdJwt = useCallback(async (): Promise<string | null> => {
      // During a re-auth attempt fetchAuthSession would read the private
      // store: serve the live session's snapshot instead.
      const guarded = getGuardedJwt('idToken');
      if (guarded !== undefined) return guarded;
      try {
        const session = await fetchAuthSession();
        return session.tokens?.idToken?.toString() ?? null;
      } catch {
        return null;
      }
    }, []);

    const getAccessJwt = useCallback(async (): Promise<string | null> => {
      const guarded = getGuardedJwt('accessToken');
      if (guarded !== undefined) return guarded;
      try {
        const session = await fetchAuthSession();
        return session.tokens?.accessToken?.toString() ?? null;
      } catch {
        return null;
      }
    }, []);

    const logout = useCallback(async (): Promise<void> => {
      // Never signOut against a re-auth attempt's private store.
      await rollbackPendingReauth();
      await signOut();
      clearCurrentUser();
    }, [clearCurrentUser]);

    const refreshSession = useCallback(async (): Promise<void> => {
      await refreshAndReload({
        reauthActive: hasActiveReauth(),
        refresh: () => fetchAuthSession({ forceRefresh: true }),
        reload: loadUserFromSession,
      });
    }, [loadUserFromSession]);

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
        ...claimsFromSession(currentUser.session),
        refreshSession,
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
      refreshSession,
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
