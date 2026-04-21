import { describe, expect, it, vi } from 'vitest';
import { apiFetch, ApiError } from '$lib/api/client';

describe('apiFetch', () => {
  it('returns parsed JSON when response is ok', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ hello: 'world' })
      })
    );

    const result = await apiFetch<{ hello: string }>('/health');
    expect(result.hello).toBe('world');
  });

  it('throws ApiError on non-OK responses', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        text: async () => 'unavailable'
      })
    );

    await expect(apiFetch('/ready')).rejects.toBeInstanceOf(ApiError);
  });

  it('maps AbortError to timeout ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new DOMException('Timed out', 'AbortError'))
    );

    await expect(apiFetch('/hosts', { timeout: 1 })).rejects.toMatchObject({ status: 408 });
  });
});
