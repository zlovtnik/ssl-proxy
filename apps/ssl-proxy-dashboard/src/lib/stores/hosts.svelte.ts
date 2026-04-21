import { getHosts, getTopHosts } from '$lib/api/hosts';
import type { HostSnapshot } from '$lib/types';

export const hosts = $state<HostSnapshot[]>([]);
export const topHosts = $state<HostSnapshot[]>([]);
export const hostsLoading = $state({ value: false });
export const hostsError = $state({ value: null as string | null });

let timer: ReturnType<typeof setInterval> | null = null;

export async function refreshHosts(): Promise<void> {
  hostsLoading.value = true;

  try {
    const [allHosts, highestRisk] = await Promise.all([getHosts(), getTopHosts('bytes', 8)]);
    hosts.splice(0, hosts.length, ...allHosts);
    topHosts.splice(0, topHosts.length, ...highestRisk);
    hostsError.value = null;
  } catch (error) {
    hostsError.value = String(error);
  } finally {
    hostsLoading.value = false;
  }
}

export function startHostsPolling(intervalMs = 2_000): () => void {
  if (timer) clearInterval(timer);
  void refreshHosts();
  const handle = setInterval(() => {
    void refreshHosts();
  }, intervalMs);
  timer = handle;

  return () => {
    clearInterval(handle);
    if (timer === handle) timer = null;
  };
}
