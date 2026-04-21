export const formatBytes = (n: number): string => {
  if (!Number.isFinite(n) || n < 0) return '—';
  if (n >= 1_073_741_824) return `${(n / 1_073_741_824).toFixed(2)} GB`;
  if (n >= 1_048_576) return `${(n / 1_048_576).toFixed(1)} MB`;
  if (n >= 1_024) return `${(n / 1_024).toFixed(1)} KB`;
  return `${Math.round(n)} B`;
};

export const formatHz = (hz: number): string =>
  hz >= 1 ? `${hz.toFixed(2)} Hz` : `${(hz * 1000).toFixed(0)} mHz`;

export const formatDuration = (ms: number): string => {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
};

export const formatRelativeTime = (iso: string): string => {
  const timestamp = new Date(iso).getTime();
  if (Number.isNaN(timestamp)) return '—';

  const diff = Date.now() - timestamp;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
};

export const formatNumber = (n: number): string =>
  new Intl.NumberFormat().format(Math.round(n));

export const formatPercent = (value: number): string => `${value.toFixed(1)}%`;

export const clamp = (n: number, min: number, max: number): number =>
  Math.min(Math.max(n, min), max);
