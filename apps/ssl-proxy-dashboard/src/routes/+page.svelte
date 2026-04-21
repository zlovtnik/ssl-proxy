<script lang="ts">
  import Card from '$lib/components/ui/Card.svelte';
  import MetricCard from '$lib/components/ui/MetricCard.svelte';
  import HostHeatmap from '$lib/components/hosts/HostHeatmap.svelte';
  import BandwidthChart from '$lib/components/peers/BandwidthChart.svelte';
  import { liveStats } from '$lib/stores/stats.svelte';
  import { hosts, hostsLoading } from '$lib/stores/hosts.svelte';
  import { peers, bandwidth, peersLoading } from '$lib/stores/peers.svelte';
  import { formatBytes } from '$lib/utils/format';

  const heroTrend = $derived.by(() => {
    if (liveStats.down_kBps === 0) return 'No downstream flow yet';
    return `${liveStats.up_kBps} / ${liveStats.down_kBps} kB/s`; 
  });
</script>

<section class="hero">
  <div>
    <h1>Real-time Command Center</h1>
    <p>WireGuard tunnel posture, host risk acceleration, and policy event flow in one surface.</p>
  </div>
  <Card variant="elevated" padded={true}>
    <div class="hero-callout">
      <span>Throughput now</span>
      <strong>{heroTrend}</strong>
      <small>total down: {formatBytes(liveStats.bytes_down)}</small>
    </div>
  </Card>
</section>

<section class="metric-grid">
  <MetricCard label="Active tunnels" value={liveStats.active_tunnels} color="info" />
  <MetricCard label="Opened" value={liveStats.tunnels_opened} />
  <MetricCard label="Blocked events" value={liveStats.blocked} color="danger" />
  <MetricCard label="Obfuscated" value={liveStats.obfuscated} color="success" />
  <MetricCard label="Upstream bytes" value={formatBytes(liveStats.bytes_up)} />
  <MetricCard label="Downstream bytes" value={formatBytes(liveStats.bytes_down)} />
</section>

<section class="grid-two">
  <HostHeatmap hosts={hosts.slice(0, 12)} loading={hostsLoading.value} title="Top Hosts (Preview)" />
  <BandwidthChart points={bandwidth} />
</section>

<section>
  <Card title="Peer Preview" subtitle="Top 8 peers by downstream">
    <div class="peer-preview">
      {#if peersLoading.value}
        <p>Loading peers…</p>
      {:else if peers.length === 0}
        <p>No peers reported yet.</p>
      {:else}
        {#each peers.slice(0, 8) as peer}
          <article>
            <strong>{peer.peer_hostname ?? peer.wg_pubkey.slice(0, 12)}</strong>
            <span>{peer.display_name ?? peer.username ?? '—'}</span>
            <small>{formatBytes(peer.bytes_down)} down</small>
          </article>
        {/each}
      {/if}
    </div>
  </Card>
</section>

<style>
  .hero {
    display: grid;
    grid-template-columns: 1.2fr 1fr;
    gap: var(--space-4);
    align-items: stretch;
  }

  h1 {
    margin: 0;
    font-size: var(--text-3xl);
    line-height: 1.1;
  }

  p {
    margin: var(--space-2) 0 0;
    color: var(--text-secondary);
  }

  .hero-callout {
    display: flex;
    flex-direction: column;
    justify-content: center;
    height: 100%;
    gap: var(--space-1);
  }

  .hero-callout span {
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: var(--text-xs);
  }

  .hero-callout strong {
    font-family: var(--font-mono);
    font-size: var(--text-2xl);
    color: var(--color-info);
  }

  .hero-callout small {
    color: var(--text-secondary);
  }

  .metric-grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(0, 1fr));
    gap: var(--space-3);
  }

  .grid-two {
    display: grid;
    gap: var(--space-4);
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .peer-preview {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .peer-preview article {
    display: grid;
    grid-template-columns: 1.2fr 1fr auto;
    gap: var(--space-2);
    align-items: center;
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-md);
    padding: var(--space-2) var(--space-3);
    background: color-mix(in oklab, var(--bg-surface) 90%, transparent);
  }

  .peer-preview span,
  .peer-preview small {
    color: var(--text-secondary);
  }

  @media (max-width: 1280px) {
    .metric-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
  }

  @media (max-width: 1024px) {
    .hero,
    .grid-two,
    .metric-grid {
      grid-template-columns: 1fr;
    }

    .peer-preview article {
      grid-template-columns: 1fr;
    }
  }
</style>
