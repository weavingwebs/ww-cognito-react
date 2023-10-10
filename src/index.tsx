import * as React from 'react';
import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserAttribute,
  CognitoUserPool,
  CognitoUserSession,
  ICognitoStorage, ICognitoUserAttributeData,
  ICognitoUserPoolData,
} from 'amazon-cognito-identity-js';
import * as qs from 'qs';
import isEqual from 'lodash/isEqual';

export enum AuthResult {
  SUCCESS,
  NEW_PASSWORD_REQUIRED,
  TOTP_REQUIRED,
  MFA_SETUP,
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

export const defaultBuildUser = (user: CognitoUser, attr: ICognitoUserAttributeData[]) => {
  let email: string | undefined;
  attr.forEach((a) => {
    switch (a.Name) {
      case 'email':
      {
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
}

// Copy of amazon-cognito-identity-js/StorageHelper.js (not exported in types).
class StorageHelper {
  protected storageWindow: ICognitoStorage;

  constructor() {
    try {
      this.storageWindow = window.localStorage;
      this.storageWindow.setItem('aws.cognito.test-ls', '1');
      this.storageWindow.removeItem('aws.cognito.test-ls');
    }
    catch (exception) {
      this.storageWindow = new MemoryCognitoStorage();
    }
  }

  public getStorage() {
    return this.storageWindow;
  }
}

export type DefaultUser = ReturnType<typeof defaultBuildUser>

export type UserPoolConfig = { UserPoolId: string; ClientId: string }

export function createCognitoAuth<TUser>(buildUser: (user: CognitoUser, attr: ICognitoUserAttributeData[]) => TUser) {
  const useCognitoAuth = (
    config: UserPoolConfig,
    temporary?: boolean,
  ) => {
    const storeRef = React.useRef<ICognitoStorage>(temporary ? new MemoryCognitoStorage() : new StorageHelper().getStorage());
    const userPoolConfig: ICognitoUserPoolData = {
      ...config,
      Storage: storeRef.current,
    };
    const userPool = new CognitoUserPool(userPoolConfig);
    const [isLoggedIn, setIsLoggedIn] = React.useState<boolean | null>(null);
    const [cachedUser, setCachedUser] = React.useState<TUser & {totpEnabled: boolean} | null>(null);
    const tmpUser = React.useRef<CognitoUser>();

    // NOTE: Cannot find any proper way to detect whether totp is enabled and
    // cannot try and keep mfa preference in sync manually either so we have to
    // track it manually as best we can.
    // https://github.com/aws-amplify/amplify-js/issues/1226
    const setTotpEnabled = (enabled: boolean) => {
      storeRef.current.setItem(`ww-cognito-react.${config.ClientId}.totpEnabled`, enabled ? '1' : '0');
      if (cachedUser) {
        setCachedUser({
          ...cachedUser,
          totpEnabled: enabled,
        })
      }
    }
    const getTotpEnabled = () => {
      return storeRef.current.getItem(`ww-cognito-react.${config.ClientId}.totpEnabled`) === '1';
    }

    const getUserObjectFromUser = async (user: CognitoUser) => {
      return new Promise<TUser & {totpEnabled: boolean}>((resolve, reject) => {
        user.getUserData((err, result) => {
          if (err) {
            console.error('Error getting user attributes', err);
            reject(err);
            return;
          }
          const attr = result?.UserAttributes || [];
          resolve({
            ...buildUser(user, attr),
            totpEnabled: getTotpEnabled(),
          });
        });
      });
    };

    const getSession = (user: CognitoUser | null) =>
      new Promise<CognitoUserSession | null>((resolve, reject) => {
        if (!user) {
          console.debug('no user session');
          setIsLoggedIn(false);
          setCachedUser(null);
          setTotpEnabled(false);
          resolve(null);
          return;
        }
        user.getSession(
          (error: Error | null, session: CognitoUserSession | null) => {
            if (error) {
              console.error('cognito getSession error', error);
              setIsLoggedIn(false);
              setCachedUser(null);
              setTotpEnabled(false);
              reject(error);
              return;
            }
            console.debug('cognito got session', session);
            getUserObjectFromUser(user)
              .then((u) => {
                console.debug('cognito got user object', u);
                if (!isEqual(u, cachedUser)) {
                  setCachedUser(u);
                  setIsLoggedIn(true);
                }
                resolve(session);
              })
              .catch(reject);
          },
        );
      });

    const getUserSession = () => getSession(userPool.getCurrentUser());

    const getUser = async () => {
      const user = userPool.getCurrentUser();
      const session = await getSession(user);
      if (session) {
        return user;
      }
      return null;
    };

    const getUserObject = async () => {
      const user = await getUser();
      if (!user) {
        throw new Error('Not logged in');
      }
      return getUserObjectFromUser(user);
    };

    const authenticate = (email: string, pass: string) =>
      new Promise<AuthResult>((resolve, reject) => {
        tmpUser.current = new CognitoUser({
          Username: email,
          Pool: userPool,
          Storage: storeRef.current,
        });
        tmpUser.current.setAuthenticationFlowType('USER_SRP_AUTH');

        tmpUser.current.authenticateUser(
          new AuthenticationDetails({
            Username: email.trim(),
            Password: pass,
          }),
          {
            onSuccess: (session, userConfirmationNecessary) => {
              console.debug('auth success', {
                session,
                userConfirmationNecessary,
              });

              // Use getUser to trigger an update of cachedUser & isLoggedIn.
              getUser()
                .then(() => resolve(AuthResult.SUCCESS))
                .catch(reject);
            },
            newPasswordRequired: () => resolve(AuthResult.NEW_PASSWORD_REQUIRED),
            mfaSetup: () => {
              resolve(AuthResult.MFA_SETUP);
            },
            totpRequired: () => {
              setTotpEnabled(true);
              resolve(AuthResult.TOTP_REQUIRED);
            },
            onFailure: reject,
          },
        );
      });

    const completeNewPasswordChallenge = (newPassword: string) =>
      new Promise<AuthResult>((resolve, reject) => {
        if (!tmpUser.current) {
          throw new Error(
            'No active authentication, please refresh the page and try again',
          );
        }
        tmpUser.current.completeNewPasswordChallenge(
          newPassword,
          {},
          {
            onSuccess: (session) => {
              console.debug('new password success', session);
              // Use getUser to trigger an update of cachedUser & isLoggedIn.
              getUser()
                .then(() => resolve(AuthResult.SUCCESS))
                .catch(reject);
            },
            onFailure: reject,
            mfaSetup: () => {
              resolve(AuthResult.MFA_SETUP);
            },
            totpRequired: () => {
              setTotpEnabled(true);
              resolve(AuthResult.TOTP_REQUIRED);
            },
          },
        );
      });

    const getJwt = async () => {
      const user = await getUserSession();
      if (!user) {
        return null;
      }
      return user.getIdToken().getJwtToken();
    };

    const logout = () =>
      new Promise<void>((resolve, reject) => {
        const user = userPool.getCurrentUser();
        if (user) {
          user.signOut();

          // Use getUser to trigger an update of cachedUser & isLoggedIn.
          setTotpEnabled(false);
          getUser()
            .then(() => resolve())
            .catch(reject);
        }
        else {
          resolve();
        }
      });

    const resetPassword = (email: string) =>
      new Promise((resolve, reject) => {
        const cognitoUser = new CognitoUser({
          Username: email,
          Pool: userPool,
          Storage: storeRef.current,
        });
        cognitoUser.forgotPassword(
          {
            onFailure: (err) => {
              console.error(err);
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
                      onSuccess: () => {
                        // Use getUser to trigger an update of cachedUser & isLoggedIn.
                        getUser()
                          .then(() => resolveVerify())
                          .catch(rejectVerify);
                      },
                    });
                  }),
              );
            },
            // This callback confirms the success of the overall reset operation.
            // NOTE: currently this does not seem to ever get called, possibly
            // because the component gets unmounted?
            onSuccess: (data) =>
              console.log('CodeDeliveryData from forgotPassword', data),
          },
        );
      });

    const confirmResetPassword = (
      email: string,
      verificationCode: string,
      newPassword: string,
    ) =>
      new Promise<void>((resolve, reject) => {
        const cognitoUser = new CognitoUser({
          Username: email,
          Pool: userPool,
          Storage: storeRef.current,
        });
        cognitoUser.confirmPassword(verificationCode, newPassword, {
          onSuccess: () => resolve(),
          onFailure: reject,
        });
      });

    React.useEffect(() => {
      getUserSession().catch((err) =>
        console.error('failed to get user session', err),
      );
    }, []);

    const updateEmail = async (email: string) => {
      const user = await getUser();
      if (!user) {
        throw new Error(
          'You are no longer logged in, please refresh the page and try again.',
        );
      }
      const attr = new CognitoUserAttribute({
        Name: 'email',
        Value: email,
      });
      return new Promise((resolve, reject) => {
        user.updateAttributes([attr], (err, result) => {
          if (err) {
            console.error('Error updating email', err);
            reject(err);
            return;
          }
          console.debug('Email change requested', result);
          resolve(result);
        });
      });
    };

    const verifyNewEmail = async (code: string) => {
      const user = await getUser();
      if (!user) {
        throw new Error(
          'You are no longer logged in, please refresh the page and try again.',
        );
      }
      return new Promise((resolve, reject) => {
        user.verifyAttribute('email', code, {
          onSuccess: (res) => {
            console.debug('New Email Verified', res);
            getUserObject()
              .then((u) => {
                setCachedUser(u);
                resolve(res);
              })
              .catch(reject);
          },
          onFailure: (err) => {
            console.error('New Email verification error', err);
            reject(err);
          },
        });
      });
    };

    const changePassword = async (oldPwd: string, newPwd: string) => {
      const user = await getUser();
      if (!user) {
        throw new Error('Not logged in');
      }
      if (oldPwd === newPwd) {
        throw new Error('New Password is the same as the old password');
      }
      return new Promise((resolve, reject) => {
        user.changePassword(oldPwd, newPwd, (err, result) => {
          if (err) {
            console.error('Error changing password', err);
            if (err.name === 'NotAuthorizedException') {
              err = new Error('Invalid Password');
            }
            reject(err);
            return;
          }
          console.debug('Password changed', result);
          resolve(result);
        });
      });
    };

    /**
     * Disassociate any existing TOTP and generate a new secret key.
     */
    const associateTotp = async () => {
      const user = await getUser();
      if (!user) {
        throw new Error('Not logged in');
      }
      return new Promise<string>((resolve, reject) => {
        setTotpEnabled(false);
        user.associateSoftwareToken({
          associateSecretCode: resolve,
          onFailure: reject,
        })
      });
    }

    const beginMfaSetupChallenge = () =>
      new Promise<string>((resolve, reject) => {
        if (!tmpUser.current) {
          throw new Error(
            'No active authentication, please refresh the page and try again',
          );
        }
        tmpUser.current.associateSoftwareToken({
          associateSecretCode: resolve,
          onFailure: reject,
        })
      });

    const verifyTotp = async ({totpCode, friendlyDeviceName}: {
      totpCode: string,
      friendlyDeviceName: string,
    }) => {
      const user = await getUser();
      if (!user) {
        throw new Error('Not logged in');
      }
      return new Promise<void>((resolve, reject) => {
        user.verifySoftwareToken(totpCode, friendlyDeviceName, {
          onSuccess: () => resolve(),
          onFailure: reject,
        })
      });
    }

    const completeMfaSetupChallenge = async ({totpCode, friendlyDeviceName}: {
      totpCode: string,
      friendlyDeviceName: string,
    }) => {
      return new Promise<void>((resolve, reject) => {
        if (!tmpUser.current) {
          throw new Error(
            'No active authentication, please refresh the page and try again',
          );
        }
        tmpUser.current.verifySoftwareToken(totpCode, friendlyDeviceName, {
          onSuccess: () => resolve(),
          onFailure: reject,
        })
      });
    }

    const enableTotp = async () => {
      const user = await getUser();
      if (!user) {
        throw new Error('Not logged in');
      }
      return new Promise<string>((resolve, reject) => {
        user.setUserMfaPreference(null, {PreferredMfa: true, Enabled: true}, (err, result) => {
          if (err) {
            reject(err);
            return;
          }
          setTotpEnabled(true);
          resolve(result);
        })
      });
    }

    const respondToTotpChallenge = async (totp: string) => {
      return new Promise<void>((resolve, reject) => {
        if (!tmpUser.current) {
          throw new Error(
            'No active authentication, please refresh the page and try again',
          );
        }
        tmpUser.current.sendMFACode(
          totp,
          {
            onSuccess: () => {
              setTotpEnabled(true);

              // Use getUser to trigger an update of cachedUser & isLoggedIn.
              getUser()
                .then(() => resolve())
                .catch(reject);
            },
            onFailure: reject,
          },
          'SOFTWARE_TOKEN_MFA',
        )
      });
    }

    return {
      isLoggedIn,
      user: cachedUser,
      authenticate,
      getUserSession,
      getUser,
      getJwt,
      logout,
      resetPassword,
      confirmResetPassword,
      completeNewPasswordChallenge,
      updateEmail,
      verifyNewEmail,
      changePassword,
      associateTotp,
      beginMfaSetupChallenge,
      verifyTotp,
      completeMfaSetupChallenge,
      enableTotp,
      respondToTotpChallenge,
    };
  };

  type AuthState = ReturnType<typeof useCognitoAuth>;

  const CognitoAuthContext = React.createContext<AuthState | null>(null);

  const useCognitoAuthContext = () => {
    const ctx = React.useContext(CognitoAuthContext);
    if (!ctx) {
      throw new Error('CognitoAuthContext not initialised');
    }
    return ctx;
  };

  const CognitoAuthProvider: React.FC<React.PropsWithChildren<{ userPool: UserPoolConfig, temporary?: boolean }>> = ({
    userPool,
    temporary,
    children,
  }) => {
    const state = useCognitoAuth(userPool, temporary);
    return <CognitoAuthContext.Provider value={state}>{children}</CognitoAuthContext.Provider>;
  };

  return {
    useCognitoAuthContext,
    CognitoAuthContext,
    CognitoAuthProvider,
  }
}

/**
 * Create a TOTP Uri for use with authenticator apps.
 * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */
export function buildTotpUri({accountName, secret, issuer}: {
  accountName: string,
  secret: string,
  issuer: string,
}): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(accountName)}?${qs.stringify({secret, issuer})}`;
}
