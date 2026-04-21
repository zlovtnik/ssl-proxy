<script lang="ts">
  import Card from '$lib/components/ui/Card.svelte';
  import StatusDot from '$lib/components/ui/StatusDot.svelte';
  import { getSyncStatus } from '$lib/api/sync';
  import type { SyncStatusReport } from '$lib/types';
  import { formatRelativeTime } from '$lib/utils/format';

  let status = $state<SyncStatusReport | null>(null);
  let loading = $state(false);
  let error = $state<string | null>(null);

  async function refresh(): Promise<void> {
    loading = true;
    try {
      status = await getSyncStatus();
      error = null;
    } catch (err) {
      error = String(err);
    } finally {
      loading = false;
    }
  }

  const lastAttempt = $derived(status?.publisher.last_attempt_at);
  const lastPublish = $derived(status?.publisher.last_publish_at);

  $effect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 10_000);
    return () => clearInterval(timer);
  });
</script>

<svelte:head>
  <title>Sync Plane | SSL Proxy Dashboard</title>
  <meta
    name="description"
    content="Monitor NATS publisher status, local subject accounting, and retention posture."
  />
  <link rel="canonical" href="/sync" />
</svelte:head>

<section>
  <div class="heading">
    <div>
      <h1>Sync Plane</h1>
      <p>NATS publisher, local subject accounting, and retention posture.</p>
    </div>
    <button type="button" onclick={refresh} disabled={loading}>Refresh</button>
  </div>

  {#if error}
    <p class="error">{error}</p>
  {/if}

  <div class="grid">
    <Card title="Publisher" subtitle="/sync/status">
      <div class="status-row">
        <StatusDot
          status={status?.status === 'ok' ? 'success' : 'danger'}
          label={status?.status ?? 'loading'}
          pulse={status?.status === 'ok'}
        />
      </div>
      <dl>
        <div>
          <dt>Configured</dt>
          <dd>{status?.publisher.configured ? 'yes' : 'no'}</dd>
        </div>
        <div>
          <dt>TLS</dt>
          <dd>{status?.publisher.tls_enabled ? 'enabled' : 'disabled'}</dd>
        </div>
        <div>
          <dt>Auth</dt>
          <dd>{status?.publisher.auth_enabled ? 'enabled' : 'disabled'}</dd>
        </div>
        <div>
          <dt>Last attempt</dt>
          <dd>{lastAttempt ? formatRelativeTime(lastAttempt) : 'none'}</dd>
        </div>
        <div>
          <dt>Last retained publish</dt>
          <dd>{lastPublish ? formatRelativeTime(lastPublish) : 'none'}</dd>
        </div>
      </dl>
      {#if status?.last_error}
        <p class="error">{status.last_error}</p>
      {/if}
    </Card>

    <Card title="Subjects" subtitle="local publisher counts">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Subject</th>
              <th>Count</th>
            </tr>
          </thead>
          <tbody>
            {#if loading && !status}
              <tr><td colspan="2" class="state">Loading sync status...</td></tr>
            {:else if !status || status.published_subjects.length === 0}
              <tr><td colspan="2" class="state">No local publishes yet.</td></tr>
            {:else}
              {#each status.published_subjects as row (row.subject)}
                <tr>
                  <td class="mono">{row.subject}</td>
                  <td>{row.count}</td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>
    </Card>
  </div>
</section>

<style>
  .heading {
    display: flex;
    justify-content: space-between;
    align-items: start;
    gap: var(--space-4);
    margin-bottom: var(--space-4);
  }

  h1 {
    margin: 0;
    font-size: var(--text-xl);
  }

  p {
    margin: var(--space-2) 0 0;
    color: var(--text-secondary);
  }

  button {
    cursor: pointer;
    border: 1px solid color-mix(in oklab, var(--color-info) 60%, transparent);
    background: color-mix(in oklab, var(--bg-overlay) 80%, transparent);
    color: var(--text-primary);
    border-radius: var(--radius-md);
    padding: 9px 12px;
    font-weight: var(--weight-medium);
  }

  button:disabled {
    cursor: wait;
    opacity: 0.7;
  }

  .grid {
    display: grid;
    grid-template-columns: minmax(280px, 0.8fr) minmax(420px, 1.2fr);
    gap: var(--space-4);
  }

  .status-row {
    margin-bottom: var(--space-4);
  }

  dl {
    display: grid;
    gap: var(--space-3);
    margin: 0;
  }

  dl div {
    display: flex;
    justify-content: space-between;
    gap: var(--space-3);
    border-bottom: 1px solid var(--border-subtle);
    padding-bottom: var(--space-2);
  }

  dt {
    color: var(--text-secondary);
  }

  dd {
    margin: 0;
    color: var(--text-primary);
    text-align: right;
  }

  .table-wrap {
    overflow: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 420px;
  }

  th,
  td {
    text-align: left;
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--border-subtle);
  }

  th {
    color: var(--text-secondary);
    font-size: var(--text-xs);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .state {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-6);
  }

  .mono {
    font-family: var(--font-mono);
  }

  .error {
    color: var(--color-danger);
    overflow-wrap: anywhere;
  }

  @media (max-width: 900px) {
    .heading,
    dl div {
      flex-direction: column;
    }

    .grid {
      grid-template-columns: 1fr;
    }

    dd {
      text-align: left;
    }
  }
</style>
