<script lang="ts">
  import type { HostSnapshot } from '$lib/types';
  import Card from '$lib/components/ui/Card.svelte';
  import HostRow from './HostRow.svelte';

  interface Props {
    hosts: HostSnapshot[];
    loading?: boolean;
    title?: string;
  }

  let { hosts, loading = false, title = 'Host Velocity Heat Map' }: Props = $props();

  let query = $state('');

  const filteredHosts = $derived.by(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return hosts;
    return hosts.filter((row) => row.host.toLowerCase().includes(normalized));
  });
</script>

<Card {title} subtitle="Sorted by backend risk scoring">
  <div class="controls">
    <label>
      <span class="sr-only">Filter hosts</span>
      <input placeholder="Filter host" bind:value={query} />
    </label>
    <span>{filteredHosts.length} hosts</span>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Host</th>
          <th>Attempts</th>
          <th>Hz</th>
          <th>Blocked bytes</th>
          <th>Risk</th>
          <th>Verdict</th>
          <th>Reason</th>
        </tr>
      </thead>
      <tbody>
        {#if loading}
          <tr><td colspan="7" class="state">Loading host telemetry…</td></tr>
        {:else if filteredHosts.length === 0}
          <tr><td colspan="7" class="state">No hosts match current filter.</td></tr>
        {:else}
          {#each filteredHosts as host (host.host)}
            <HostRow {host} />
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
</Card>

<style>
  .controls {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: var(--space-3);
    margin-bottom: var(--space-3);
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  input {
    width: 220px;
    background: var(--bg-page);
    border: 1px solid var(--border-muted);
    color: var(--text-primary);
    border-radius: var(--radius-md);
    padding: 8px 10px;
  }

  .table-wrap {
    overflow: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 800px;
  }

  th,
  td {
    text-align: left;
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--border-subtle);
    white-space: nowrap;
  }

  th {
    color: var(--text-secondary);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    background: color-mix(in oklab, var(--bg-surface) 92%, transparent);
    position: sticky;
    top: 0;
  }

  tr:hover td {
    background: color-mix(in oklab, var(--bg-elevated) 85%, transparent);
  }

  .state {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-6);
  }
</style>
