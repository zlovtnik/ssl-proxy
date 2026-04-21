<script lang="ts">
  interface Props {
    label: string;
    value: string | number;
    sublabel?: string;
    color?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  }

  let { label, value, sublabel, color = 'default' }: Props = $props();

  const colorMap = {
    default: 'var(--text-primary)',
    success: 'var(--color-success)',
    warning: 'var(--color-warning)',
    danger: 'var(--color-danger)',
    info: 'var(--color-info)'
  };
</script>

<div class="metric-card" role="figure" aria-label={`${label}: ${value}`}>
  <span class="metric-label">{label}</span>
  <span class="metric-value" style={`color: ${colorMap[color]}`}>{value}</span>
  {#if sublabel}
    <span class="metric-sub">{sublabel}</span>
  {/if}
</div>

<style>
  .metric-card {
    min-height: 104px;
    background: linear-gradient(135deg, color-mix(in oklab, var(--bg-overlay) 88%, #10212f), var(--bg-overlay));
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-3) var(--space-4);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: var(--space-1);
  }

  .metric-label {
    font-size: var(--text-xs);
    font-weight: var(--weight-medium);
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .metric-value {
    font-size: var(--text-2xl);
    font-weight: var(--weight-bold);
    font-family: var(--font-mono);
    line-height: 1;
  }

  .metric-sub {
    font-size: var(--text-xs);
    color: var(--text-muted);
  }
</style>
