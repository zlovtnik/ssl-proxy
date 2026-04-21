<script lang="ts">
  import HostHeatmap from '$lib/components/hosts/HostHeatmap.svelte';
  import { hosts, hostsLoading, hostsError } from '$lib/stores/hosts.svelte';
</script>

<section>
  <h1>Host Heat Map</h1>
  <p>Inspect verdict distribution and high-frequency host behavior.</p>

  {#if hostsError.value}
    <p class="error">{hostsError.value}</p>
  {/if}

  <HostHeatmap hosts={hosts} loading={hostsLoading.value} title="Full Host Velocity Heat Map" />
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
</style>
