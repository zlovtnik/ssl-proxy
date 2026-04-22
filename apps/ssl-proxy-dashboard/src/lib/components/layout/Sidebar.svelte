<script lang="ts">
  import { page } from '$app/stores';
  import Badge from '$lib/components/ui/Badge.svelte';
  import { summary } from '$lib/stores/peers.svelte';

  const items = [
    { href: '/hosts', title: 'Host Intel', description: 'Risk velocity and verdict shifts' },
    { href: '/peers', title: 'Peer Telemetry', description: 'Traffic and active sessions' },
    { href: '/devices', title: 'Device Registry', description: 'Claims and identity metadata' },
    { href: '/sync', title: 'Sync Plane', description: 'Publisher and ledger health' }
  ];

  const isActive = (href: string): boolean => $page.url.pathname.startsWith(href);
</script>

<aside class="sidebar" aria-label="Section navigation">
  <div class="panel">
    <h2>Ops Lanes</h2>
    <p>Track the data plane without leaving keyboard flow.</p>
  </div>

  <div class="list" role="tree">
    {#each items as item}
      <a
        href={item.href}
        role="treeitem"
        aria-selected={isActive(item.href)}
        class="item"
        class:active={isActive(item.href)}
      >
        <span class="item-title">{item.title}</span>
        <span class="item-body">{item.description}</span>
      </a>
    {/each}
  </div>

  <div class="panel summary">
    <h3>Snapshot</h3>
    <div class="summary-row">
      <span>Total hosts</span>
      <strong>{summary.total_hosts}</strong>
    </div>
    <div class="summary-row">
      <span>Tarpit hosts</span>
      <Badge variant="info" text={String(summary.tarpit_count)} />
    </div>
    <div class="summary-row">
      <span>Top category</span>
      <strong>{summary.top_category ?? '—'}</strong>
    </div>
  </div>
</aside>

<style>
  .sidebar {
    width: var(--sidebar-width);
    position: sticky;
    top: calc(var(--navbar-height) + var(--space-4));
    align-self: start;
    display: flex;
    flex-direction: column;
    gap: var(--space-4);
  }

  .panel {
    background: color-mix(in oklab, var(--bg-surface) 90%, transparent);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-lg);
    padding: var(--space-4);
  }

  h2,
  h3 {
    margin: 0;
    font-size: var(--text-sm);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-secondary);
  }

  .panel p {
    margin: var(--space-2) 0 0;
    color: var(--text-muted);
    font-size: var(--text-sm);
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .item {
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-3);
    text-decoration: none;
    background: color-mix(in oklab, var(--bg-surface) 82%, transparent);
    transition: border-color 0.15s, background 0.15s;
    cursor: pointer;
  }

  .item:hover {
    background: var(--bg-elevated);
    border-color: var(--border-muted);
  }

  .item.active {
    border-color: color-mix(in oklab, var(--color-info) 45%, transparent);
    background: color-mix(in oklab, var(--bg-overlay) 78%, transparent);
  }

  .item-title {
    display: block;
    color: var(--text-primary);
    font-size: var(--text-md);
    font-weight: var(--weight-medium);
  }

  .item-body {
    display: block;
    color: var(--text-secondary);
    font-size: var(--text-sm);
    margin-top: var(--space-1);
  }

  .summary {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .summary-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .summary-row strong {
    color: var(--text-primary);
    font-family: var(--font-mono);
  }

  @media (max-width: 1024px) {
    .sidebar {
      width: 100%;
      position: static;
      top: 0;
    }

    .list {
      flex-direction: row;
      overflow-x: auto;
      padding-bottom: var(--space-1);
    }

    .item {
      min-width: 220px;
    }
  }
</style>
