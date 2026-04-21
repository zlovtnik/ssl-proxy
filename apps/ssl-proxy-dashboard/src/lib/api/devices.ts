import type { ClaimResponse, DeviceInfo, DeviceUpsertRequest, DeviceUpsertResponse } from '$lib/types';
import { apiFetch } from './client';

export const getDevices = (wgPubkey?: string): Promise<DeviceInfo[]> => {
  if (!wgPubkey) return apiFetch('/devices');
  return apiFetch(`/devices?wg_pubkey=${encodeURIComponent(wgPubkey)}`);
};

export const getDeviceById = (id: string): Promise<DeviceInfo> =>
  apiFetch(`/devices/${encodeURIComponent(id)}`);

export const upsertDevice = (payload: DeviceUpsertRequest): Promise<DeviceUpsertResponse> =>
  apiFetch('/devices', {
    method: 'POST',
    body: JSON.stringify(payload)
  });

export const claimDevice = (): Promise<ClaimResponse> =>
  apiFetch('/devices/claim', {
    method: 'POST'
  });
