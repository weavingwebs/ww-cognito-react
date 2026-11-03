type GetToken = (
  kind: 'idToken' | 'accessToken',
  expected: string,
) => Promise<string | null>;

export type BoundGetters = {
  getIdJwt: () => Promise<string | null>;
  getAccessJwt: () => Promise<string | null>;
};

// The signed-in state's getters, bound to that state's user (getToken's
// `expected`, so a closure holding an old state cannot get a new user's token)
// and keeping their identity for as long as the user is the same, so consumers
// can use them as hook dependencies (README "Stable user identity"). Kept out
// of the provider so it can be tested without a React tree.
export function createBoundGetters(
  getToken: GetToken,
): (username: string) => BoundGetters {
  let cached: { username: string; getters: BoundGetters } | undefined;
  return (username) => {
    if (cached?.username !== username) {
      cached = {
        username,
        getters: {
          getIdJwt: () => getToken('idToken', username),
          getAccessJwt: () => getToken('accessToken', username),
        },
      };
    }
    return cached.getters;
  };
}
