const API_KEY = import.meta.env.VITE_ADMIN_API_KEY ?? 'test';
const ADMIN_BASE_URL = (import.meta.env.VITE_ADMIN_BASE_URL ?? 'http://127.0.0.1:3002').replace(
  /\/+$/,
  ''
);

type FetchOptions = RequestInit & { timeout?: number };

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

const resolveUrl = (path: string): string => {
  if (/^https?:\/\//.test(path)) return path;
  if (import.meta.env.DEV) return path;
  return `${ADMIN_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
};

export async function apiFetch<T>(path: string, options: FetchOptions = {}): Promise<T> {
  const { timeout = 8_000, ...init } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(resolveUrl(path), {
      ...init,
      signal: controller.signal,
      headers: {
        'x-api-key': API_KEY,
        'content-type': 'application/json',
        ...init.headers
      }
    });

    if (!response.ok) {
      const message = await response.text();
      throw new ApiError(response.status, message || `HTTP ${response.status}`);
    }

    if (response.status === 204) return undefined as T;

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new ApiError(408, `Request timed out after ${timeout}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
