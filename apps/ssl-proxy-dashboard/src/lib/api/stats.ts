import type { BandwidthPoint, LiveStats, PeerSummary, StatsSummary } from '$lib/types';
import { apiFetch } from './client';

export const getPeers = (): Promise<PeerSummary[]> => apiFetch('/stats/peers');

export const getBandwidth = (window: '1h' | '24h' | '7d' = '1h'): Promise<BandwidthPoint[]> =>
  apiFetch(`/stats/bandwidth?window=${window}`);

export const getSummary = (): Promise<StatsSummary> => apiFetch('/stats/summary');

export const getLiveStats = (): Promise<LiveStats> => apiFetch('/stats/live');
