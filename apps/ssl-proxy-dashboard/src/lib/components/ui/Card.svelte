<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title?: string;
    subtitle?: string;
    variant?: 'surface' | 'elevated' | 'metric' | 'transparent';
    padded?: boolean;
    children?: Snippet;
  }

  let { title, subtitle, variant = 'surface', padded = true, children }: Props = $props();
</script>

<section class={`card card-${variant}`}>
  {#if title}
    <header class="card-header">
      <h2>{title}</h2>
      {#if subtitle}
        <p>{subtitle}</p>
      {/if}
    </header>
  {/if}
  <div class:card-body={padded}>
    {@render children?.()}
  </div>
</section>

<style>
  .card {
    border-radius: var(--radius-lg);
    border: 1px solid var(--border-subtle);
    backdrop-filter: blur(6px);
  }

  .card-surface {
    background: color-mix(in oklab, var(--bg-surface) 86%, transparent);
  }

  .card-elevated {
    background: color-mix(in oklab, var(--bg-elevated) 88%, transparent);
    border-color: var(--border-muted);
  }

  .card-metric {
    background: var(--bg-overlay);
    border: none;
    border-radius: var(--radius-md);
  }

  .card-transparent {
    background: transparent;
  }

  .card-header {
    padding: var(--space-4) var(--space-5) 0;
  }

  .card-header h2 {
    margin: 0;
    font-size: var(--text-lg);
    font-weight: var(--weight-medium);
  }

  .card-header p {
    margin: var(--space-1) 0 0;
    color: var(--text-secondary);
    font-size: var(--text-sm);
  }

  .card-body {
    padding: var(--space-4) var(--space-5);
  }
</style>
