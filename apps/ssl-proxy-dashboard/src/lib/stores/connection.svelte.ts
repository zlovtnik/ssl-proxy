import type { WsConnectionStatus } from '$lib/types';

export const connection = $state({
  status: 'disconnected' as WsConnectionStatus
});

export function isLive(): boolean {
  return connection.status === 'connected';
}
