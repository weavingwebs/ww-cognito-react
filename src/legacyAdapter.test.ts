import { describe, expect, it } from 'vitest';
import { adaptToLegacyBuildUser } from './legacyAdapter';

describe('adaptToLegacyBuildUser', () => {
  it('excludes attributes with an undefined value from the {Name,Value}[] array', () => {
    const { attr } = adaptToLegacyBuildUser(
      { username: 'jdoe' },
      { email: 'jdoe@example.com', 'custom:roles': undefined },
    );

    expect(attr).toEqual([{ Name: 'email', Value: 'jdoe@example.com' }]);
  });

  it('getUsername() returns cognito:username, not sub', () => {
    // authUser.username is cognito:username; authUser.userId (not passed
    // here at all) is sub - the two can differ, and v2's getUsername()
    // always meant the former.
    const { user } = adaptToLegacyBuildUser(
      { username: 'jdoe' },
      { email: 'jdoe@example.com' },
    );

    expect(user.getUsername()).toBe('jdoe');
  });
});
