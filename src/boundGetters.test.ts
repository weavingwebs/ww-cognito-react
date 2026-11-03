// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { createBoundGetters } from './boundGetters';

describe('createBoundGetters', () => {
  it('keeps the same getters for the same user across state rebuilds (consumers use them as hook deps)', () => {
    const bind = createBoundGetters(vi.fn());
    const first = bind('user-a');
    const again = bind('user-a'); // e.g. refreshSession / reauthenticate reloaded the user
    expect(again.getIdJwt).toBe(first.getIdJwt);
    expect(again.getAccessJwt).toBe(first.getAccessJwt);
  });

  it('gives a different user new getters, bound to that user', async () => {
    const getToken = vi.fn().mockResolvedValue('jwt');
    const bind = createBoundGetters(getToken);
    const a = bind('user-a');
    const b = bind('user-b');
    expect(b.getIdJwt).not.toBe(a.getIdJwt);
    await a.getIdJwt();
    await b.getAccessJwt();
    expect(getToken).toHaveBeenNthCalledWith(1, 'idToken', 'user-a');
    expect(getToken).toHaveBeenNthCalledWith(2, 'accessToken', 'user-b');
  });

  it("an old user's getters stay bound to the old user after a switch", async () => {
    const getToken = vi.fn().mockResolvedValue(null);
    const bind = createBoundGetters(getToken);
    const a = bind('user-a');
    bind('user-b');
    await a.getIdJwt();
    expect(getToken).toHaveBeenCalledWith('idToken', 'user-a');
  });
});
