import { reauthError, REAUTH_NOT_LOGGED_IN_EXCEPTION } from './reauth';
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
  sendUserAttributeVerificationCode,
  setUpTOTP,
  signOut,
  updatePassword,
  updateUserAttributes,
  verifyTOTPSetup,
} from 'aws-amplify/auth';
import { authenticateWith, reauthenticateWith } from './authenticate';
import { claimsFromSession } from './claims';
import { createMapSignInResult } from './mapSignInResult';
import {
  checkSessionOnMount,
  isRefreshTokenRejected,
  isTokenClearingError,
} from './sessionGuards';
import { createSessionSync } from './sessionSync';
import type {
  AuthenticateOptions,
  AuthProviderOptions,
  AuthState,
  BuildUserFn,
  UserPoolConfig,
} from './types';
import {
  createLoadCoordinator,
  isOwnSignInActive,
  readsStraddleUsers,
  userChangedError,
} from './userChange';

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
// logged in. Does not update AuthProvider state.
export async function forceSignOut(): Promise<void> {
  try {
    await signOut();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[ww-cognito-react] forceSignOut failed', err);
  }
}

function authTimeOf(
  session: Awaited<ReturnType<typeof fetchAuthSession>> | undefined,
): number | undefined {
  const authTime = session?.tokens?.idToken?.payload.auth_time;
  return typeof authTime === 'number' ? authTime : undefined;
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

  const AuthProvider: FC<
    PropsWithChildren<{ userPool: UserPoolConfig; options?: AuthProviderOptions }>
  > = ({ userPool, options, children }) => {
    const [isLoggedIn, setIsLoggedIn] = useState<boolean | null>(null);
    const [currentUser, setCurrentUser] = useState<CurrentUser<User> | null>(
      null,
    );
    const [sessionCheckFailed, setSessionCheckFailed] = useState(false);
    const currentUserRef = useRef<CurrentUser<User> | null>(null);
    // Read at call time so changing an option never re-runs the effects below.
    const optionsRef = useRef<AuthProviderOptions | undefined>(options);
    optionsRef.current = options;
    const syncRef = useRef<ReturnType<typeof createSessionSync> | null>(null);
    const loggedOutJtiRef = useRef<string | undefined>(undefined);
    const rerunCheckRef = useRef<(() => void) | null>(null);
    const syncTabs = !!options?.syncTabs;

    // Protects against a stale async result landing after the pool changed.
    const versionRef = useRef(0);

    const clearCurrentUser = useCallback(() => {
      setIsLoggedIn(false);
      setCurrentUser(null);
      currentUserRef.current = null;
    }, []);

    const loadRaw = useCallback(async () => {
      for (let attempt = 0; ; attempt++) {
        const [session, authUser, attributes] = await Promise.all([
          fetchAuthSession(),
          getCurrentUser(),
          fetchUserAttributes(),
        ]);
        // The three reads are separate: another tab switching user between
        // them would mix two users (e.g. one's claims with the other's name).
        if (readsStraddleUsers(session, authUser, attributes)) {
          if (attempt < 2) continue;
          throw userChangedError();
        }
        syncRef.current?.beforeApply(authUser.username);
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
      }
    }, []);

    // Concurrent requests are merged but force one more run (see
    // createLoadCoordinator), so a sign-in never gets the previous user.
    const loadUserFromSession = useMemo(
      () => createLoadCoordinator(loadRaw),
      [loadRaw],
    );

    const sync = useMemo(
      () =>
        createSessionSync({
          fetchSession: () => fetchAuthSession(),
          tabUsername: () => currentUserRef.current?.authUser.username,
          loadUser: loadUserFromSession,
          clearTab: clearCurrentUser,
          isResurrection: (session) =>
            loggedOutJtiRef.current !== undefined &&
            (session as { tokens?: { accessToken?: { payload: Record<string, unknown> } } })
              .tokens?.accessToken?.payload.origin_jti === loggedOutJtiRef.current,
          onUserChange: () =>
            optionsRef.current?.onUserChange ??
            (optionsRef.current?.syncTabs ? 'reload' : undefined),
        }),
      [loadUserFromSession, clearCurrentUser],
    );
    syncRef.current = sync;

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

      // Never signOut on failure: a transient error at page load must not
      // revoke the refresh token. See checkSessionOnMount.
      let inFlight = false;
      const runCheck = () => {
        if (inFlight) return;
        inFlight = true;
        setSessionCheckFailed(false);
        void checkSessionOnMount({
          fetchSession: fetchAuthSession,
          loadUser: loadUserFromSession,
          clearCurrentUser,
          isStale: () => version !== versionRef.current,
          retry: optionsRef.current?.retrySessionCheck
            ? {
                delaysMs: [500, 1500],
                onTransientFailure: () => {
                  if (version === versionRef.current) setSessionCheckFailed(true);
                },
              }
            : undefined,
        }).then(
          () => {
            inFlight = false;
          },
          () => {
            inFlight = false;
          },
        );
      };
      rerunCheckRef.current = runCheck;
      runCheck();

      // Invalidates anything still pending (a retry sleep, a late result) so it
      // cannot set state after unmount.
      return () => {
        versionRef.current++;
      };
    }, [
      userPool.userPoolId,
      userPool.userPoolClientId,
      loadUserFromSession,
      clearCurrentUser,
    ]);

    // Log the app out (state only, never signOut) when Amplify has cleared the
    // tokens after a failed refresh - otherwise isLoggedIn stays true while
    // getIdJwt() is null. With `syncTabs`, also follow other tabs (their events
    // are only delivered to listeners that opt in) and keep the claims fresh.
    // A separate effect so toggling `syncTabs` never re-runs the mount check.
    useEffect(() => {
      const version = versionRef.current;
      const stopListening = Hub.listen(
        'auth',
        ({
          payload,
          crossTab,
        }: {
          payload: { event: string; data?: unknown };
          crossTab?: boolean;
        }) => {
          if (version !== versionRef.current) return;
          if (isRefreshTokenRejected(payload)) {
            clearCurrentUser();
            return;
          }
          if (!optionsRef.current?.syncTabs) return;
          if (crossTab) {
            // Re-reads storage (coalesced; postponed during this tab's own
            // sign-in). A token refresh elsewhere is how a re-authentication,
            // or a switch to a user whose keys already exist, shows up.
            if (
              payload.event === 'signedIn' ||
              payload.event === 'signedOut' ||
              payload.event === 'tokenRefresh'
            ) {
              void sync.check();
            }
          } else if (
            payload.event === 'tokenRefresh' &&
            currentUserRef.current &&
            !isOwnSignInActive()
          ) {
            void loadUserFromSession().catch(() => undefined);
          }
        },
        { enableCrossTabEvents: syncTabs },
      );
      return stopListening;
    }, [
      userPool.userPoolId,
      userPool.userPoolClientId,
      loadUserFromSession,
      clearCurrentUser,
      sync,
      syncTabs,
    ]);

    const retrySessionCheck = useCallback(() => rerunCheckRef.current?.(), []);

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
        });
      },
      [userPool.authFlowType, mapSignInResult, loadUserFromSession],
    );

    // `strictTokens` (opt-in): a transient failure throws instead of looking
    // like a logout, a session Amplify has dropped logs this tab out, and tokens
    // that belong to a different user than the caller was written for throw
    // UserChangedError. `expected` is the user of the state object the getter
    // belongs to, so a closure holding an old state cannot receive a new
    // user's token after this tab switched.
    const getToken = useCallback(
      async (
        kind: 'idToken' | 'accessToken',
        expected?: string,
      ): Promise<string | null> => {
        const strict = !!optionsRef.current?.strictTokens;
        let session: Awaited<ReturnType<typeof fetchAuthSession>>;
        try {
          session = await fetchAuthSession();
        } catch (err) {
          if (strict && !isTokenClearingError(err)) throw err;
          return null;
        }
        if (!session.tokens) {
          if (strict && currentUserRef.current && !isOwnSignInActive()) {
            // Another tab can be between the two writes of storing tokens
            // (LastAuthUser first): confirm before logging out a live session.
            await new Promise((r) => setTimeout(r, 50));
            const again = await fetchAuthSession().catch(() => undefined);
            if (again && !again.tokens) clearCurrentUser();
          }
          return null;
        }
        if (strict) syncRef.current?.assertSameUser(session, expected);
        return session.tokens[kind]?.toString() ?? null;
      },
      [clearCurrentUser],
    );
    const getIdJwt = useCallback(() => getToken('idToken'), [getToken]);
    const getAccessJwt = useCallback(() => getToken('accessToken'), [getToken]);

    const logout = useCallback(async (): Promise<void> => {
      // A refresh already in flight in another tab can write this session back
      // after sign-out: remember it, so `syncTabs` never adopts it again.
      try {
        const jti = (await fetchAuthSession()).tokens?.accessToken.payload
          .origin_jti;
        if (typeof jti === 'string') loggedOutJtiRef.current = jti;
      } catch {
        // Best-effort.
      }
      await signOut();
      clearCurrentUser();
    }, [clearCurrentUser]);

    const refreshSession = useCallback(async (): Promise<void> => {
      await fetchAuthSession({ forceRefresh: true });
      await loadUserFromSession();
    }, [loadUserFromSession]);

    const reauthenticate = useCallback(
      async (pass: string, opts?: { clientMetadata?: Record<string, string> }) => {
        // NOTE: the session's own username, so it can only ever be this user.
        const username = currentUserRef.current?.authUser.username;
        if (!username) {
          throw reauthError(REAUTH_NOT_LOGGED_IN_EXCEPTION, 'Not logged in');
        }
        return reauthenticateWith({
          username,
          pass,
          clientMetadata: opts?.clientMetadata,
          authFlowType: userPool.authFlowType ?? 'USER_SRP_AUTH',
          mapSignInResult,
          tabUsername: () => currentUserRef.current?.authUser.username,
          startAuthTime: authTimeOf(currentUserRef.current?.session),
          clearTabUser: clearCurrentUser,
        });
      },
      [userPool.authFlowType, mapSignInResult, clearCurrentUser],
    );

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

    // Confirms the code, then forces a refresh: the email / email_verified
    // claims are only in a freshly issued ID token.
    const confirmEmailCode = useCallback(
      async (verificationCode: string): Promise<void> => {
        await confirmUserAttribute({
          userAttributeKey: 'email',
          confirmationCode: verificationCode,
        });
        try {
          await fetchAuthSession({ forceRefresh: true });
        } catch (err) {
          // Tokens Amplify itself clears are dead: the Hub listener logs the
          // tab out, so do not carry on as if the session were fine.
          if (isTokenClearingError(err)) throw err;
          // Transient: the address is confirmed; claims stay stale until the
          // next refresh.
        }
        await loadUserFromSession();
      },
      [loadUserFromSession],
    );

    const updateEmail = useCallback(
      async (email: string) => {
        await updateUserAttributes({ userAttributes: { email } });
        return { verifyEmail: confirmEmailCode };
      },
      [confirmEmailCode],
    );

    const sendEmailVerificationCode = useCallback(async (): Promise<void> => {
      await sendUserAttributeVerificationCode({ userAttributeKey: 'email' });
    }, []);

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
        return sessionCheckFailed
          ? { isLoggedIn: null, sessionCheckFailed: true, retrySessionCheck }
          : { isLoggedIn: null };
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
        reauthenticate,
        getAccessJwt: () => getToken('accessToken', currentUser.authUser.username),
        getIdJwt: () => getToken('idToken', currentUser.authUser.username),
        logout,
        changePassword,
        updateEmail,
        sendEmailVerificationCode,
        confirmEmailVerificationCode: confirmEmailCode,
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
      getToken,
      refreshSession,
      reauthenticate,
      logout,
      changePassword,
      updateEmail,
      sendEmailVerificationCode,
      confirmEmailCode,
      associateTotp,
      verifyTotp,
      sessionCheckFailed,
      retrySessionCheck,
    ]);

    return (
      <AuthContext.Provider value={authState}>{children}</AuthContext.Provider>
    );
  };

  return { useAuthContext, useAuthContextOrDie, AuthContext, AuthProvider };
}
