import { getBandwidth, getPeers, getSummary } from '$lib/api/stats';
import type { BandwidthPoint, PeerSummary, StatsSummary } from '$lib/types';

export const peers = $state<PeerSummary[]>([]);
export const bandwidth = $state<BandwidthPoint[]>([]);
export const summary = $state<StatsSummary>({
  total_hosts: 0,
  tarpit_count: 0,
  top_category: undefined,
  highest_risk_host: undefined
});

export const peersLoading = $state({ value: false });
export const peersError = $state({ value: null as string | null });

let timer: ReturnType<typeof setInterval> | null = null;

export async function refreshPeers(): Promise<void> {
  peersLoading.value = true;

  try {
    const [peerRows, trendPoints, overview] = await Promise.all([
      getPeers(),
      getBandwidth('1h'),
      getSummary()
    ]);

    peers.splice(0, peers.length, ...peerRows);
    bandwidth.splice(0, bandwidth.length, ...trendPoints);
    Object.assign(summary, overview);
    peersError.value = null;
  } catch (error) {
    peersError.value = String(error);
  } finally {
    peersLoading.value = false;
  }
}

export function startPeersPolling(intervalMs = 10_000): () => void {
  if (timer) clearInterval(timer);
  void refreshPeers();
  const handle = setInterval(() => {
    void refreshPeers();
  }, intervalMs);
  timer = handle;

  return () => {
    clearInterval(handle);
    if (timer === handle) timer = null;
  };
}
