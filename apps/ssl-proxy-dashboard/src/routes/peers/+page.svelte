<script lang="ts">
  import PeerList from '$lib/components/peers/PeerList.svelte';
  import BandwidthChart from '$lib/components/peers/BandwidthChart.svelte';
  import { peers, peersLoading, peersError, bandwidth } from '$lib/stores/peers.svelte';
</script>

<section>
  <h1>Peer Telemetry</h1>
  <p>Peer traffic distribution, blocked-vs-allowed bytes, and active-session pressure.</p>

  {#if peersError.value}
    <p class="error">{peersError.value}</p>
  {/if}

  <div class="grid">
    <PeerList {peers} loading={peersLoading.value} />
    <BandwidthChart points={bandwidth} />
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

  .error {
    color: var(--color-danger);
    margin-bottom: var(--space-2);
  }

  .grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: var(--space-4);
  }

  @media (max-width: 1024px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>
