import type { HealthStatus } from '$lib/types';
import { apiFetch } from './client';

export const getHealth = (): Promise<HealthStatus> => apiFetch('/health');

export const getReady = (): Promise<HealthStatus> => apiFetch('/ready');
