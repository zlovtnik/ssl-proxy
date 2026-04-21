<script lang="ts">
  import type { DashboardEvent } from '$lib/types';
  import { formatRelativeTime } from '$lib/utils/format';

  interface Props {
    event: DashboardEvent;
  }

  let { event }: Props = $props();

  const kind = $derived.by(() => {
    if (event.type.includes('block')) return 'block';
    if (event.type.includes('open')) return 'open';
    if (event.type.includes('close')) return 'close';
    return 'allow';
  });
</script>

<article class={`event ${kind}`}>
  <div class="line-top">
    <strong>{event.host ?? 'unknown'}</strong>
    <span>{event.type}</span>
    <time datetime={event.time}>{formatRelativeTime(event.time)}</time>
  </div>
  <div class="line-bottom">
    {#if event.verdict}
      <span class="verdict">{event.verdict}</span>
    {/if}
    {#if event.reason}
      <span>{event.reason}</span>
    {/if}
    {#if event.metrics?.attempt_count != null}
      <span>#{event.metrics.attempt_count} @ {event.metrics.frequency_hz ?? 0}Hz</span>
    {/if}
  </div>
</article>

<style>
  .event {
    border-left: 3px solid transparent;
    border-bottom: 1px solid var(--border-subtle);
    padding: var(--space-2) var(--space-3);
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
  }

  .event.block { border-left-color: var(--color-danger); }
  .event.allow { border-left-color: var(--color-success); }
  .event.open { border-left-color: var(--color-info); }
  .event.close { border-left-color: var(--color-neutral); }

  .line-top {
    display: flex;
    gap: var(--space-2);
    align-items: center;
    min-width: 0;
  }

  .line-top strong {
    color: var(--text-primary);
    font-weight: var(--weight-medium);
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .line-top span,
  .line-top time {
    color: var(--text-secondary);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .line-bottom {
    color: var(--text-secondary);
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    font-size: var(--text-sm);
  }

  .verdict {
    color: var(--color-danger);
    font-weight: var(--weight-medium);
  }
</style>
