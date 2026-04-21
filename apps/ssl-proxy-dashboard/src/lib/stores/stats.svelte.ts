import { getLiveStats } from '$lib/api/stats';
import type { LiveStats } from '$lib/types';
import { connection } from './connection.svelte';

export const liveStats = $state<LiveStats>({
  active_tunnels: 0,
  tunnels_opened: 0,
  up_kBps: 0,
  down_kBps: 0,
  bytes_up: 0,
  bytes_down: 0,
  blocked: 0,
  obfuscated: 0
});

export const statsError = $state({ value: null as string | null });

let timer: ReturnType<typeof setInterval> | null = null;

export async function refreshStats(): Promise<void> {
  try {
    const latest = await getLiveStats();
    Object.assign(liveStats, latest);
    connection.status = 'connected';
    statsError.value = null;
  } catch (error) {
    connection.status = 'error';
    statsError.value = String(error);
  }
}

export function startStatsPolling(intervalMs = 2_000): () => void {
  if (timer) clearInterval(timer);
  connection.status = 'connecting';
  void refreshStats();
  timer = setInterval(() => {
    void refreshStats();
  }, intervalMs);

  return () => {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    connection.status = 'disconnected';
  };
}
