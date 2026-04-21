<script lang="ts">
  import type { BandwidthPoint } from '$lib/types';
  import Card from '$lib/components/ui/Card.svelte';
  import { formatBytes, formatPercent } from '$lib/utils/format';

  interface Props {
    points: BandwidthPoint[];
  }

  let { points }: Props = $props();

  const totals = $derived.by(() => {
    return points.reduce(
      (acc, point) => {
        acc.blocked += point.blocked_bytes_delta ?? 0;
        acc.allowed += point.allowed_bytes_delta ?? 0;
        return acc;
      },
      { blocked: 0, allowed: 0 }
    );
  });

  const blockedRatio = $derived.by(() => {
    const total = totals.allowed + totals.blocked;
    if (total === 0) return 0;
    return (totals.blocked / total) * 100;
  });

  const sparkline = $derived.by(() => {
    const map = new Map<string, number>();
    for (const point of points) {
      const total = (point.bytes_up_delta ?? 0) + (point.bytes_down_delta ?? 0);
      map.set(point.bucket, (map.get(point.bucket) ?? 0) + total);
    }

    const entries = [...map.entries()].slice(-28);
    if (!entries.length) return '';
    const values = entries.map(([, value]) => value);
    const max = Math.max(...values, 1);

    return entries
      .map(([, value], idx) => {
        const x = (idx / Math.max(entries.length - 1, 1)) * 100;
        const y = 92 - (value / max) * 84;
        return `${idx === 0 ? 'M' : 'L'} ${x} ${y}`;
      })
      .join(' ');
  });
</script>

<Card title="Bandwidth + Block Ratio" subtitle="Aggregated from /stats/bandwidth">
  <div class="chart-wrap">
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
      <path d={sparkline} stroke="var(--color-info)" stroke-width="1.8" fill="none" />
    </svg>
  </div>

  <div class="stats">
    <div>
      <span>Allowed bytes</span>
      <strong>{formatBytes(totals.allowed)}</strong>
    </div>
    <div>
      <span>Blocked bytes</span>
      <strong>{formatBytes(totals.blocked)}</strong>
    </div>
    <div>
      <span>Blocked ratio</span>
      <strong>{formatPercent(blockedRatio)}</strong>
    </div>
  </div>
</Card>

<style>
  .chart-wrap {
    height: 160px;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    background: linear-gradient(180deg, #122233 0%, #0d1620 100%);
    padding: var(--space-3);
  }

  svg {
    width: 100%;
    height: 100%;
  }

  .stats {
    margin-top: var(--space-3);
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: var(--space-3);
  }

  .stats div {
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-2) var(--space-3);
    background: color-mix(in oklab, var(--bg-overlay) 86%, transparent);
  }

  .stats span {
    display: block;
    color: var(--text-secondary);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stats strong {
    display: block;
    margin-top: var(--space-1);
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-weight: var(--weight-bold);
  }
</style>
