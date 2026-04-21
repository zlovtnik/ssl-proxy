<script lang="ts">
  import Card from '$lib/components/ui/Card.svelte';
  import type { DashboardEvent } from '$lib/types';
  import EventItem from './EventItem.svelte';

  interface Props {
    events: DashboardEvent[];
    maxItems?: number;
    title?: string;
  }

  let { events, maxItems = 200, title = 'Live Event Feed' }: Props = $props();

  let filter = $state<'all' | 'block' | 'allow' | 'tunnel'>('all');

  const visible = $derived.by(() => {
    const sliced = events.slice(0, maxItems);
    if (filter === 'all') return sliced;

    return sliced.filter((event) => {
      if (filter === 'block') return event.type.includes('block');
      if (filter === 'allow') return event.type.includes('allow');
      return event.type.includes('tunnel');
    });
  });
</script>

<Card title={title} subtitle="Bounded in-memory stream with quick filters">
  <div class="toolbar" role="toolbar" aria-label="Event filters">
    {#each ['all', 'block', 'allow', 'tunnel'] as mode}
      <button
        type="button"
        class:active={filter === mode}
        onclick={() => {
          filter = mode as typeof filter;
        }}
      >
        {mode}
      </button>
    {/each}
  </div>

  <div class="feed" role="list" aria-live="polite">
    {#if visible.length === 0}
      <p class="empty">No events for selected filter.</p>
    {:else}
      {#each visible as event, index (event.time + event.type + index)}
        <EventItem {event} />
      {/each}
    {/if}
  </div>
</Card>

<style>
  .toolbar {
    display: flex;
    gap: var(--space-2);
    margin-bottom: var(--space-3);
  }

  button {
    cursor: pointer;
    border: 1px solid var(--border-muted);
    background: transparent;
    color: var(--text-secondary);
    border-radius: var(--radius-full);
    padding: 4px 10px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-size: var(--text-xs);
    transition: all 0.15s;
  }

  button:hover {
    color: var(--text-primary);
    border-color: var(--border-default);
  }

  button.active {
    color: var(--text-primary);
    background: var(--bg-overlay);
    border-color: var(--color-info);
  }

  .feed {
    max-height: 540px;
    overflow: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  .empty {
    color: var(--text-secondary);
    padding: var(--space-4);
    margin: 0;
  }
</style>
