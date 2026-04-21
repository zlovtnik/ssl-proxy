import type { HostSnapshot } from '$lib/types';
import { apiFetch } from './client';

export const getHosts = (): Promise<HostSnapshot[]> => apiFetch('/hosts');

export const getHostByName = (hostname: string): Promise<HostSnapshot> =>
  apiFetch(`/hosts/${encodeURIComponent(hostname)}`);

export const getTopHosts = (metric: 'bytes' | 'blocks' = 'bytes', limit = 20): Promise<HostSnapshot[]> =>
  apiFetch(`/stats/hosts/top?metric=${metric}&limit=${limit}`);
