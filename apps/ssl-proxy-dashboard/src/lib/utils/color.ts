import type { Verdict } from '$lib/types';

interface VerdictStyle {
  color: string;
  bg: string;
  label: string;
}

export const VERDICT_STYLES: Record<Verdict, VerdictStyle> = {
  BLOCKED: {
    color: 'var(--verdict-blocked)',
    bg: 'var(--verdict-blocked-bg)',
    label: 'Blocked'
  },
  PERSISTENT_RECONNECT: {
    color: 'var(--verdict-persistent)',
    bg: 'var(--verdict-persistent-bg)',
    label: 'Persistent'
  },
  AGGRESSIVE_POLLING: {
    color: 'var(--verdict-aggressive)',
    bg: 'var(--verdict-aggressive-bg)',
    label: 'Aggressive'
  },
  HEURISTIC_FLAG_DATA_EXFIL: {
    color: 'var(--verdict-exfil)',
    bg: 'var(--verdict-exfil-bg)',
    label: 'Data Exfil'
  },
  TARPIT: {
    color: 'var(--verdict-tarpit)',
    bg: 'var(--verdict-tarpit-bg)',
    label: 'Tarpit'
  }
};

export const riskBarColor = (score: number): string => {
  if (score >= 1_000_000) return 'var(--color-danger)';
  if (score >= 100_000) return 'var(--verdict-aggressive)';
  if (score >= 10_000) return 'var(--color-warning)';
  return 'var(--color-neutral)';
};
