import type { SyncStatusReport } from '$lib/types';
import { apiFetch } from './client';

export const getSyncStatus = (): Promise<SyncStatusReport> => apiFetch('/sync/status');
