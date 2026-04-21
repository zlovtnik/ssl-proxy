<script lang="ts">
  import type { PeerSummary } from '$lib/types';
  import Card from '$lib/components/ui/Card.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import { formatBytes, formatNumber, formatRelativeTime } from '$lib/utils/format';

  interface Props {
    peers: PeerSummary[];
    loading?: boolean;
  }

  let { peers, loading = false }: Props = $props();
</script>

<Card title="Peer Telemetry" subtitle="Top peers by downstream bytes">
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Peer</th>
          <th>Identity</th>
          <th>Down</th>
          <th>Blocked</th>
          <th>Sessions</th>
          <th>Last handshake</th>
        </tr>
      </thead>
      <tbody>
        {#if loading}
          <tr><td colspan="6" class="state">Loading peer telemetry…</td></tr>
        {:else if peers.length === 0}
          <tr><td colspan="6" class="state">No active peers yet.</td></tr>
        {:else}
          {#each peers as peer (peer.wg_pubkey)}
            <tr>
              <td class="peer">{peer.peer_hostname ?? peer.wg_pubkey.slice(0, 14)}</td>
              <td>{peer.display_name ?? peer.username ?? '—'}</td>
              <td>{formatBytes(peer.bytes_down)}</td>
              <td>{formatBytes(peer.blocked_bytes_approx)}</td>
              <td>
                <Badge
                  variant={peer.sessions_active > 0 ? 'info' : 'neutral'}
                  text={formatNumber(peer.sessions_active)}
                />
              </td>
              <td>{peer.last_handshake_at ? formatRelativeTime(peer.last_handshake_at) : 'never'}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
</Card>

<style>
  .table-wrap {
    overflow: auto;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 760px;
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
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }

  tr:hover td {
    background: color-mix(in oklab, var(--bg-elevated) 88%, transparent);
  }

  .peer {
    font-family: var(--font-mono);
  }

  .state {
    text-align: center;
    color: var(--text-secondary);
    padding: var(--space-5);
  }
</style>
