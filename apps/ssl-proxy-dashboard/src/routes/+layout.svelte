<script lang="ts">
  import { onMount } from 'svelte';
  import PageShell from '$lib/components/layout/PageShell.svelte';
  import { startStatsPolling } from '$lib/stores/stats.svelte';
  import { startHostsPolling } from '$lib/stores/hosts.svelte';
  import { startPeersPolling } from '$lib/stores/peers.svelte';
  import '../app.css';

  onMount(() => {
    const stopStats = startStatsPolling(2_000);
    const stopHosts = startHostsPolling(2_000);
    const stopPeers = startPeersPolling(10_000);

    return () => {
      stopStats();
      stopHosts();
      stopPeers();
    };
  });
</script>

<PageShell>
  <slot />
</PageShell>
