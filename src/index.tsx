import * as React from 'react';
import {
  createContext,
  FC,
  PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState
} from 'react';
import {
  AuthenticationDetails, ChallengeName, ClientMetadata,
  CognitoUser,
  CognitoUserAttribute,
  CognitoUserPool,
  CognitoUserSession, IAuthenticationCallback,
  ICognitoStorage,
  ICognitoUserAttributeData,
} from 'amazon-cognito-identity-js';
import * as qs from 'qs';

export type UserPoolConfig = { UserPoolId: string; ClientId: string, AuthFlow?: 'USER_SRP_AUTH' | 'CUSTOM_AUTH' };

export type BuildUserFn<User> = (
  user: CognitoUser,
  attr: ICognitoUserAttributeData[],
) => User;

export const defaultBuildUser: BuildUserFn<{ id: string; email: string }> = (
  user,
  attr,
) => {
  let email: string | undefined;
  attr.forEach((a) => {
    switch (a.Name) {
      case 'email': {
        email = a.Value;
        break;
      }
    }
  });
  if (!email) {
    throw new Error('Email not found in attributes');
  }
  return {
    id: user.getUsername(),
    email,
  };
};

type AuthStateUnknown = { isLoggedIn: null };
type AuthStateAnon<User> = {
  isLoggedIn: false;
  // Get the current user object (without using state and waiting for a re-render).
  getUser: () => User | null;
  authenticate: (email: string, pass: string) => Promise<AuthenticateResult>;
  resetPassword: (
    email: string,
  ) => Promise<
    (verificationCode: string, newPassword: string) => Promise<void>
  >;
  confirmResetPassword: ConfirmResetPasswordFn;
};
type AuthStateLoggedIn<User> = Omit<AuthStateAnon<User>, 'isLoggedIn'> & {
  isLoggedIn: true;
  user: User;
  getAccessJwt: () => Promise<string | null>;
  getIdJwt: () => Promise<string | null>;
  logout: () => Promise<void>;
  changePassword: (oldPwd: string, newPwd: string) => Promise<void>;
  updateEmail: (
    email: string,
  ) => Promise<{ verifyEmail: (verificationCode: string) => Promise<void> }>;
  associateTotp: () => Promise<string>;
  verifyTotp: (
    totpCode: string,
    friendlyDeviceName: string,
  ) => Promise<CognitoUserSession>;
};

type AuthState<User> =
  | AuthStateUnknown
  | AuthStateAnon<User>
  | AuthStateLoggedIn<User>;

export type AuthResult =
  | 'SUCCESS'
  | 'NEW_PASSWORD_REQUIRED'
  | 'MFA_REQUIRED'
  | 'TOTP_REQUIRED'
  | 'CUSTOM_CHALLENGE'
  | 'MFA_SETUP'
  | 'SELECT_MFA_TYPE';

export type AuthenticationResultSuccess = {
  result: 'SUCCESS';
  session: CognitoUserSession;
  userConfirmationNecessary?: boolean | undefined;
};
export type AuthenticationResultNewPasswordRequired = {
  result: 'NEW_PASSWORD_REQUIRED';
  userAttributes: Record<string, string>;
  requiredAttributes: Record<string, string>;
};
export type AuthenticationResultTotpRequired = {
  result: 'TOTP_REQUIRED';
  challengeName: ChallengeName;
  challengeParameters: Record<string, string>;
};
export type AuthenticationResultMfaSetup = {
  result: 'MFA_SETUP';
  challengeName: ChallengeName;
  challengeParameters: Record<string, string>;
};
export type AuthenticationResultMfa = {
  result: 'MFA_REQUIRED' | 'SELECT_MFA_TYPE';
  challengeName: ChallengeName;
  challengeParameters: Record<string, string>;
};
export type AuthenticationResultCustomChallenge = {
  result: 'CUSTOM_CHALLENGE';
  challengeParameters: Record<string, string>;
};

export type AuthenticationResult =
  | AuthenticationResultSuccess
  | AuthenticationResultNewPasswordRequired
  | AuthenticationResultTotpRequired
  | AuthenticationResultMfaSetup
  | AuthenticationResultMfa
  | AuthenticationResultCustomChallenge;

export type AuthenticateResult = {
  cognitoUser: CognitoUser;
} & (
  | AuthenticationResultSuccess
  | (AuthenticationResultNewPasswordRequired & {
  completeNewPasswordChallenge: CompleteNewPasswordChallengeFn;
})
  | (AuthenticationResultTotpRequired & {
  respondToTotpChallenge: RespondToTotpChallengeFn;
})
  | (AuthenticationResultMfaSetup & {
  beginMfaSetupChallenge: BeginMfaSetupChallengeFn;
  completeMfaSetupChallenge: CompleteMfaSetupChallengeFn;
})
  // @todo this needs splitting up & giving callbacks to support these properly.
  | AuthenticationResultMfa
  | (AuthenticationResultCustomChallenge & {
  sendCustomChallengeAnswer: SendCustomChallengeAnswerFn;
})
  );

export type CompleteNewPasswordChallengeFn = (
  newPassword: string,
  attributes?: Record<string, string>,
) => Promise<AuthenticateResult>;

export type RespondToTotpChallengeFn = (
  totpCode: string,
) => Promise<AuthenticateResult>;

export type BeginMfaSetupChallengeFn = () => Promise<{
  cognitoUser: CognitoUser;
  secret: string;
}>;

export type CompleteMfaSetupChallengeFn = (input: {
  totpCode: string;
  friendlyDeviceName: string;
}) => Promise<AuthenticateResult>;

export type SendCustomChallengeAnswerFn = (
  answerChallenge: string,
  clientMetaData?: ClientMetadata,
) => Promise<AuthenticateResult>;

export type ConfirmResetPasswordFn = (
  email: string,
  verificationCode: string,
  newPassword: string,
) => Promise<void>;

function authenticateResultCallbacks(
  resolve: (value: AuthenticationResult) => void,
  reject: (reason?: string | Error) => void,
): IAuthenticationCallback {
  return {
    onSuccess: (session, userConfirmationNecessary) =>
      resolve({ result: 'SUCCESS', session, userConfirmationNecessary }),
    onFailure: reject,
    newPasswordRequired: (
      userAttributes: Record<string, string>,
      requiredAttributes: Record<string, string>,
    ) =>
      resolve({
        result: 'NEW_PASSWORD_REQUIRED',
        userAttributes,
        requiredAttributes,
      }),
    mfaRequired: (
      challengeName: ChallengeName,
      challengeParameters: Record<string, string>,
    ) =>
      resolve({ result: 'MFA_REQUIRED', challengeName, challengeParameters }),
    totpRequired: (
      challengeName: ChallengeName,
      challengeParameters: Record<string, string>,
    ) =>
      resolve({ result: 'TOTP_REQUIRED', challengeName, challengeParameters }),
    customChallenge: (challengeParameters: Record<string, string>) =>
      resolve({ result: 'CUSTOM_CHALLENGE', challengeParameters }),
    mfaSetup: (
      challengeName: ChallengeName,
      challengeParameters: Record<string, string>,
    ) => resolve({ result: 'MFA_SETUP', challengeName, challengeParameters }),
    selectMFAType: (
      challengeName: ChallengeName,
      challengeParameters: Record<string, string>,
    ) =>
      resolve({
        result: 'SELECT_MFA_TYPE',
        challengeName,
        challengeParameters,
      }),
  };
}

// Create cognito auth hooks bound to the User type.
export function createCognitoAuth<User extends object>(
  buildUser: BuildUserFn<User>,
) {
  const useCognitoAuth = (config: UserPoolConfig, temporary?: boolean) => {
    const storeRef = useRef<ICognitoStorage>(
      temporary ? new MemoryCognitoStorage() : new StorageHelper().getStorage(),
    );
    const userPool = useMemo(
      () =>
        new CognitoUserPool({
          UserPoolId: config.UserPoolId,
          ClientId: config.ClientId,
          Storage: storeRef.current,
        }),
      [config.UserPoolId, config.ClientId, storeRef],
    );
    const authFlow = config.AuthFlow ?? 'USER_SRP_AUTH';
    const [isLoggedIn, _setIsLoggedIn] = useState<boolean | null>(null);
    const [currentUser, _setCurrentUser] = useState<null | {
      session: CognitoUserSession;
      cognitoUser: CognitoUser;
      user: User;
    }>(null);

    // Keep a copy of the user in a ref so event handlers can access it without
    // needing to wait for the state to update.
    const currentUserRef = useRef(currentUser);

    // Wrap up the getting of attributes & setting of state into one function.
    const setUserSession = useCallback(
      async (
        cognitoUser: CognitoUser | null,
        session: CognitoUserSession | null,
      ) => {
        // eslint-disable-next-line no-console
        console.debug('Cognito Auth:', { cognitoUser, session });
        if (!session) {
          _setIsLoggedIn(false);
          _setCurrentUser(null);
          currentUserRef.current = null;
          return;
        }
        if (!cognitoUser) {
          throw new Error('No cognito user');
        }
        const userAttributes = await getUserAttributes(cognitoUser);
        const user = buildUser(cognitoUser, userAttributes);
        // eslint-disable-next-line no-console
        console.debug('Cognito Auth User:', user);

        // If there was already a current user object, maintain the reference.
        let newCurrentUser = { session, cognitoUser, user };
        if (currentUserRef.current) {
          newCurrentUser = Object.assign(currentUserRef.current, {
            session,
            cognitoUser,
            user: Object.assign(currentUserRef.current.user, user),
          });
        }

        _setIsLoggedIn(true);
        _setCurrentUser(newCurrentUser);
        currentUserRef.current = newCurrentUser;
      },
      [],
    );

    // Check if the user is logged in on mount.
    useEffect(() => {
      const cognitoUser = userPool.getCurrentUser();
      if (!cognitoUser) {
        void setUserSession(null, null);
        return;
      }

      getSession(cognitoUser)
        .then((session) => {
          return setUserSession(cognitoUser, session);
        })
        .catch((err) => {
          // eslint-disable-next-line no-console
          console.error('Error getting cognito auth session:', err);
          void setUserSession(null, null);
        });
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [userPool]);

    // Build the memoized auth context.
    return useMemo((): AuthState<User> => {
      // Return nothing if we are still loading the auth state.
      if (isLoggedIn === null) {
        return {
          isLoggedIn: null,
        };
      }

      // Build the anonymous context.
      const anonCtx: AuthStateAnon<User> = {
        isLoggedIn: false,
        getUser: () => currentUserRef.current?.user ?? null,
        authenticate: async (email, pass) => {
          const cognitoUser = new CognitoUser({
            Username: email,
            Pool: userPool,
            Storage: storeRef.current,
          });

          const handleResult = async (
            authRes: AuthenticationResult,
          ): Promise<AuthenticateResult> => {
            // eslint-disable-next-line no-console
            console.debug('Auth Result', authRes);
            switch (authRes.result) {
              case 'SUCCESS': {
                await setUserSession(cognitoUser, authRes.session);
                break;
              }

              case 'NEW_PASSWORD_REQUIRED': {
                return {
                  ...authRes,
                  cognitoUser,
                  completeNewPasswordChallenge: async (
                    newPassword: string,
                    attributes: Record<string, string> = {},
                  ) => {
                    return handleResult(
                      await completeNewPasswordChallenge(
                        cognitoUser,
                        newPassword,
                        attributes,
                      ),
                    );
                  },
                };
              }

              case 'MFA_SETUP':
                return {
                  ...authRes,
                  cognitoUser,
                  beginMfaSetupChallenge: async () => {
                    const secret = await associateTotp(cognitoUser);
                    return { secret, cognitoUser };
                  },
                  completeMfaSetupChallenge: async (input) => {
                    const session = await verifyTotp(cognitoUser, input);
                    return handleResult({ result: 'SUCCESS', session });
                  },
                };

              case 'TOTP_REQUIRED':
                return {
                  ...authRes,
                  cognitoUser,
                  respondToTotpChallenge: async (totpCode: string) => {
                    return handleResult(
                      await respondToTotpChallenge(cognitoUser, totpCode),
                    );
                  },
                };

              case 'CUSTOM_CHALLENGE':
                return {
                  ...authRes,
                  cognitoUser,
                  sendCustomChallengeAnswer: async (
                    answerChallenge: string,
                    clientMetaData?: ClientMetadata,
                  ) => {
                    return handleResult(
                      await sendCustomChallengeAnswer(
                        cognitoUser,
                        answerChallenge,
                        clientMetaData,
                      ),
                    );
                  },
                };
            }
            return {
              ...authRes,
              cognitoUser,
            };
          };

          return handleResult(
            await authenticate(cognitoUser, email, pass, authFlow),
          );
        },
        resetPassword: async (email: string) => {
          const cognitoUser = new CognitoUser({
            Username: email,
            Pool: userPool,
            Storage: storeRef.current,
          });
          return resetPassword(cognitoUser);
        },
        confirmResetPassword: async (
          email: string,
          verificationCode: string,
          newPassword: string,
        ) => {
          const cognitoUser = new CognitoUser({
            Username: email,
            Pool: userPool,
            Storage: storeRef.current,
          });
          return confirmResetPassword(
            cognitoUser,
            verificationCode,
            newPassword,
          );
        },
      };
      if (!isLoggedIn) {
        return {
          ...anonCtx,
          isLoggedIn: false,
        };
      }
      if (!currentUser) {
        throw new Error('No current user');
      }

      const getOrRefreshSession = async () => {
        if (!currentUserRef.current) {
          return null;
        }
        let session: CognitoUserSession | null;
        try {
          session = await getSession(currentUserRef.current.cognitoUser);
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error('Error getting session', err);
          return null;
        }
        if (!session) {
          // eslint-disable-next-line no-console
          console.debug('Cognito session is no longer valid');
          return null;
        }
        if (session !== currentUserRef.current.session) {
          // If the session was refreshed, update it.
          await setUserSession(currentUserRef.current.cognitoUser, session);
        }
        return session;
      };

      return {
        ...anonCtx,
        isLoggedIn: true,
        user: currentUser.user,
        getAccessJwt: async () => {
          const session = await getOrRefreshSession();
          if (!session) {
            return null;
          }
          return session.getAccessToken().getJwtToken();
        },
        getIdJwt: async () => {
          const session = await getOrRefreshSession();
          if (!session) {
            return null;
          }
          return session.getIdToken().getJwtToken();
        },
        logout: async () => {
          if (!currentUser.cognitoUser) {
            throw new Error('No cognito user');
          }
          await logout(currentUser.cognitoUser);
          await setUserSession(null, null);
        },
        changePassword: async (oldPwd: string, newPwd: string) => {
          if (!currentUser.cognitoUser) {
            throw new Error('No cognito user');
          }
          return changePassword(currentUser.cognitoUser, oldPwd, newPwd);
        },
        updateEmail: async (email: string) => {
          const { cognitoUser } = currentUser;
          if (!cognitoUser) {
            throw new Error('No cognito user');
          }
          await updateAttributes(cognitoUser, { email });
          return {
            verifyEmail: async (verificationCode: string) => {
              if (!cognitoUser) {
                throw new Error('No cognito user');
              }
              await verifyAttribute(cognitoUser, 'email', verificationCode);
              await setUserSession(cognitoUser, currentUser.session);
            },
          };
        },
        associateTotp: async () => {
          return associateTotp(currentUser.cognitoUser);
        },
        verifyTotp: async (totpCode: string, friendlyDeviceName: string) => {
          return verifyTotp(currentUser.cognitoUser, {
            totpCode,
            friendlyDeviceName,
          });
        },
      };
    }, [isLoggedIn, currentUser, userPool, setUserSession]);
  };

  const CognitoAuthContext = createContext<AuthState<User> | null>(null);

  const useCognitoAuthContext = () => {
    const ctx = useContext(CognitoAuthContext);
    if (!ctx) {
      throw new Error('CognitoAuthContext not initialised');
    }
    return ctx;
  };

  const CognitoAuthProvider: FC<
    PropsWithChildren<{ userPool: UserPoolConfig; temporary?: boolean }>
  > = ({ userPool, temporary, children }) => {
    const state = useCognitoAuth(userPool, temporary);
    return (
      <CognitoAuthContext.Provider value={state}>
        {children}
      </CognitoAuthContext.Provider>
    );
  };

  return {
    useCognitoAuthContext,
    CognitoAuthContext,
    CognitoAuthProvider,
  };
}

class MemoryCognitoStorage implements ICognitoStorage {
  private store = new Map<string, string>();

  clear(): void {
    this.store.clear();
  }

  getItem(key: string): string | null {
    const v = this.store.get(key);
    if (typeof v === 'undefined') {
      return null;
    }
    return v;
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }
}

// Copy of amazon-cognito-identity-js/StorageHelper.js (not exported in types).
// Required to allow hot-swapping of the storage implementation (undefined
// doesn't cut it)
class StorageHelper {
  protected storageWindow: ICognitoStorage;

  constructor() {
    try {
      this.storageWindow = window.localStorage;
      this.storageWindow.setItem('aws.cognito.test-ls', '1');
      this.storageWindow.removeItem('aws.cognito.test-ls');
    } catch (exception) {
      this.storageWindow = new MemoryCognitoStorage();
    }
  }

  public getStorage() {
    return this.storageWindow;
  }
}

function rateLimit() {
  const lastCognitoRequest = localStorage.getItem('cognito_auth_last_request');
  if (lastCognitoRequest) {
    const [lastTime, count] = lastCognitoRequest
      .split('|')
      .map((str) => parseInt(str));
    // Limit to 5 requests per second.
    if (Date.now() - lastTime < 1000) {
      if (count > 5) {
        throw new Error(
          'Too many auth requests, please wait a moment and try again.',
        );
      }
      localStorage.setItem(
        'cognito_auth_last_request',
        `${lastTime}|${count + 1}`,
      );
      return;
    }
  }
  localStorage.setItem('ftax-auth_last-cognito-request', `${Date.now()}|1`);
}

async function getSession(
  cognitoUser: CognitoUser,
): Promise<CognitoUserSession | null> {
  rateLimit();
  return new Promise((resolve, reject) => {
    cognitoUser.getSession(
      (err: Error | null, session: CognitoUserSession | null) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(session);
      },
    );
  });
}

async function authenticate(
  cognitoUser: CognitoUser,
  email: string,
  pass: string,
  authFlow: 'USER_SRP_AUTH' | 'CUSTOM_AUTH' = 'USER_SRP_AUTH',
) {
  return new Promise<AuthenticationResult>((resolve, reject) => {
    rateLimit();
    cognitoUser.setAuthenticationFlowType(authFlow);
    cognitoUser.authenticateUser(
      new AuthenticationDetails({
        Username: email.trim(),
        Password: pass,
      }),
      authenticateResultCallbacks(resolve, reject),
    );
  });
}

async function completeNewPasswordChallenge(
  user: CognitoUser,
  newPassword: string,
  attributes: Record<string, string> = {},
): Promise<AuthenticationResult> {
  return new Promise((resolve, reject) => {
    rateLimit();
    user.completeNewPasswordChallenge(
      newPassword,
      attributes,
      authenticateResultCallbacks(resolve, reject),
    );
  });
}

async function sendCustomChallengeAnswer(
  user: CognitoUser,
  answerChallenge: string,
  clientMetaData?: ClientMetadata,
) {
  return new Promise<AuthenticationResult>((resolve, reject) => {
    rateLimit();
    user.sendCustomChallengeAnswer(
      answerChallenge,
      authenticateResultCallbacks(resolve, reject),
      clientMetaData,
    );
  });
}

async function respondToTotpChallenge(user: CognitoUser, totpCode: string) {
  return new Promise<AuthenticationResult>((resolve, reject) => {
    rateLimit();
    user.sendMFACode(
      totpCode,
      authenticateResultCallbacks(resolve, reject),
      'SOFTWARE_TOKEN_MFA',
    );
  });
}

async function getUserAttributes(
  user: CognitoUser,
): Promise<CognitoUserAttribute[]> {
  return new Promise<CognitoUserAttribute[]>((resolve, reject) => {
    rateLimit();
    user.getUserAttributes(
      (err: Error | undefined, result: CognitoUserAttribute[] | undefined) => {
        if (err) {
          // eslint-disable-next-line no-console
          console.error('Error getting user attributes', err);
          reject(err);
          return;
        }
        if (!result) {
          throw new Error('No attributes returned');
        }
        resolve(result);
      },
    );
  });
}

async function logout(user: CognitoUser) {
  return new Promise<void>((resolve) => {
    rateLimit();
    user.signOut(resolve);
  });
}

async function resetPassword(cognitoUser: CognitoUser) {
  return new Promise<
    (verificationCode: string, newPassword: string) => Promise<void>
  >((resolve, reject) => {
    rateLimit();
    cognitoUser.forgotPassword({
      onFailure: (err) => {
        console.error('Cognito Auth forgotPassword error', err);
        reject(err);
      },
      // This callback indicates that the email has been sent successfully.
      inputVerificationCode: () => {
        resolve(
          // Return a function that can be used to reset the password.
          (verificationCode: string, newPassword: string) =>
            new Promise<void>((resolveVerify, rejectVerify) => {
              cognitoUser.confirmPassword(verificationCode, newPassword, {
                onFailure: rejectVerify,
                onSuccess: () => resolveVerify(),
              });
            }),
        );
      },
      // This callback confirms the success of the overall reset operation.
      // NOTE: currently this does not seem to ever get called, possibly
      // because the component gets unmounted?
      onSuccess: (data) =>
        console.log('Cognito Auth CodeDeliveryData from forgotPassword', data),
    });
  });
}

// NOTE: You must call authenticate after successfully resetting the password
// if you want to log the user in automatically.
async function confirmResetPassword(
  cognitoUser: CognitoUser,
  verificationCode: string,
  newPassword: string,
) {
  return new Promise<void>((resolve, reject) => {
    rateLimit();
    cognitoUser.confirmPassword(verificationCode, newPassword, {
      onFailure: reject,
      onSuccess: () => resolve(),
    });
  });
}

async function changePassword(
  user: CognitoUser,
  oldPwd: string,
  newPwd: string,
) {
  return new Promise<void>((resolve, reject) => {
    rateLimit();
    user.changePassword(oldPwd, newPwd, (err) => {
      if (err) {
        console.error('Error changing password', err);
        if (err.name === 'NotAuthorizedException') {
          err = new Error('Invalid Password');
        }
        reject(err);
        return;
      }
      resolve();
    });
  });
}

async function updateAttributes(
  user: CognitoUser,
  attributes: Record<string, string>,
) {
  return new Promise<string | undefined>((resolve, reject) => {
    const cognitoAttributes = Object.entries(attributes).map(
      ([name, value]) => new CognitoUserAttribute({ Name: name, Value: value }),
    );
    rateLimit();
    user.updateAttributes(cognitoAttributes, (err, result) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(result);
    });
  });
}

export async function verifyAttribute(
  user: CognitoUser,
  attributeName: string,
  verificationCode: string,
) {
  return new Promise<void>((resolve, reject) => {
    rateLimit();
    user.verifyAttribute(attributeName, verificationCode, {
      onSuccess: () => resolve(),
      onFailure: reject,
    });
  });
}

/**
 * Disassociate any existing TOTP and generate a new secret key.
 * Can also be used for the MFA_SETUP challenge flow.
 */
export async function associateTotp(user: CognitoUser) {
  return new Promise<string>((resolve, reject) => {
    rateLimit();
    user.associateSoftwareToken({
      associateSecretCode: resolve,
      onFailure: reject,
    });
  });
}

/**
 * Verify the TOTP code.
 * Use to complete the MFA_SETUP challenge flow.
 */
export async function verifyTotp(
  user: CognitoUser,
  {
    totpCode,
    friendlyDeviceName,
  }: { totpCode: string; friendlyDeviceName: string },
) {
  return new Promise<CognitoUserSession>((resolve, reject) => {
    rateLimit();
    user.verifySoftwareToken(totpCode, friendlyDeviceName, {
      onSuccess: resolve,
      onFailure: reject,
    });
  });
}

/**
 * Create a TOTP Uri for use with authenticator apps.
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
export function buildTotpUri({
  accountName,
  secret,
  issuer,
}: {
  accountName: string;
  secret: string;
  issuer: string;
}): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(
    accountName,
  )}?${qs.stringify({ secret, issuer })}`;
}
