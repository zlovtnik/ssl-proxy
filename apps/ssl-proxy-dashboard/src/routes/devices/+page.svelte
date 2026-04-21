<script lang="ts">
  import Card from '$lib/components/ui/Card.svelte';
  import { getDevices, upsertDevice } from '$lib/api/devices';
  import type { DeviceInfo } from '$lib/types';
  import { formatRelativeTime } from '$lib/utils/format';

  let devices = $state<DeviceInfo[]>([]);
  let loading = $state(false);
  let error = $state<string | null>(null);
  let success = $state<string | null>(null);

  const form = $state({
    device_id: '',
    wg_pubkey: '',
    display_name: '',
    username: '',
    hostname: '',
    os_hint: '',
    notes: ''
  });

  async function refresh(): Promise<void> {
    loading = true;
    try {
      devices = await getDevices();
      error = null;
    } catch (err) {
      error = String(err);
    } finally {
      loading = false;
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    success = null;

    try {
      const payload = {
        ...form,
        device_id: form.device_id || undefined,
        wg_pubkey: form.wg_pubkey || undefined,
        display_name: form.display_name || undefined,
        username: form.username || undefined,
        hostname: form.hostname || undefined,
        os_hint: form.os_hint || undefined,
        notes: form.notes || undefined
      };

      const response = await upsertDevice(payload);
      success = `Device upserted: ${response.device_id}`;
      await refresh();
    } catch (err) {
      error = String(err);
    }
  }

  $effect(() => {
    void refresh();
  });
</script>

<section>
  <h1>Device Registry</h1>
  <p>Review claimed devices and upsert metadata for peer identity context.</p>

  <div class="grid">
    <Card title="Upsert Device" subtitle="POST /devices">
      <form class="device-form" onsubmit={submit}>
        <label>
          Device ID (optional)
          <input bind:value={form.device_id} />
        </label>
        <label>
          WireGuard Pubkey
          <input bind:value={form.wg_pubkey} />
        </label>
        <label>
          Display Name
          <input bind:value={form.display_name} />
        </label>
        <label>
          Username
          <input bind:value={form.username} />
        </label>
        <label>
          Hostname
          <input bind:value={form.hostname} />
        </label>
        <label>
          OS Hint
          <input bind:value={form.os_hint} />
        </label>
        <label>
          Notes
          <textarea rows="3" bind:value={form.notes}></textarea>
        </label>
        <button type="submit">Upsert device</button>
      </form>

      {#if success}
        <p class="success">{success}</p>
      {/if}
      {#if error}
        <p class="error">{error}</p>
      {/if}
    </Card>

    <Card title="Known Devices" subtitle="GET /devices">
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>Identity</th>
              <th>Host</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {#if loading}
              <tr><td colspan="4" class="state">Loading devices…</td></tr>
            {:else if devices.length === 0}
              <tr><td colspan="4" class="state">No devices yet.</td></tr>
            {:else}
              {#each devices as device (device.device_id)}
                <tr>
                  <td class="mono">{device.device_id}</td>
                  <td>{device.display_name ?? device.username ?? '—'}</td>
                  <td>{device.hostname ?? '—'}</td>
                  <td>{formatRelativeTime(device.last_seen)}</td>
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
  h1 {
    margin: 0;
    font-size: var(--text-xl);
  }

  p {
    margin: var(--space-2) 0 var(--space-4);
    color: var(--text-secondary);
  }

  .grid {
    display: grid;
    gap: var(--space-4);
    grid-template-columns: 1fr 1.4fr;
  }

  .device-form {
    display: grid;
    gap: var(--space-3);
  }

  label {
    display: grid;
    gap: var(--space-1);
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  input,
  textarea {
    width: 100%;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-muted);
    background: var(--bg-page);
    color: var(--text-primary);
    padding: 8px 10px;
  }

  button {
    cursor: pointer;
    border: 1px solid color-mix(in oklab, var(--color-info) 60%, transparent);
    background: color-mix(in oklab, var(--bg-overlay) 80%, transparent);
    color: var(--text-primary);
    border-radius: var(--radius-md);
    padding: 10px 12px;
    font-weight: var(--weight-medium);
  }

  .table-wrap {
    overflow: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 620px;
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
    font-size: var(--text-sm);
  }

  .error {
    color: var(--color-danger);
    margin: var(--space-2) 0 0;
  }

  .success {
    color: var(--color-success);
    margin: var(--space-2) 0 0;
  }

  @media (max-width: 1024px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>
