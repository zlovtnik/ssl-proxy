<script lang="ts">
  interface Props {
    variant?: 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'outline';
    text: string;
  }

  let { variant = 'neutral', text }: Props = $props();
</script>

<span class={`badge badge-${variant}`}>{text}</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: var(--text-xs);
    font-weight: var(--weight-medium);
    letter-spacing: 0.04em;
    text-transform: uppercase;
    white-space: nowrap;
  }

  .badge-success { background: var(--bg-success); color: var(--color-success); }
  .badge-warning { background: var(--bg-warning); color: var(--color-warning); }
  .badge-danger { background: var(--bg-danger); color: var(--color-danger); }
  .badge-info { background: var(--bg-info); color: var(--color-info); }
  .badge-neutral { background: var(--bg-neutral); color: var(--text-secondary); }
  .badge-outline {
    background: transparent;
    color: var(--text-secondary);
    border: 1px solid var(--border-muted);
  }
</style>
