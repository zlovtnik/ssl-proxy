<script lang="ts">
  import Navbar from '$lib/components/layout/Navbar.svelte';
  import Sidebar from '$lib/components/layout/Sidebar.svelte';
</script>

<Navbar />

<div class="shell">
  <Sidebar />
  <main class="content" aria-live="polite">
    <slot />
  </main>
</div>

<style>
  .shell {
    width: min(calc(100% - var(--space-6) * 2), calc(var(--content-max) + var(--sidebar-width) + var(--space-8)));
    margin: calc(var(--navbar-height) + var(--space-5)) auto var(--space-8);
    display: grid;
    grid-template-columns: var(--sidebar-width) 1fr;
    gap: var(--space-6);
    position: relative;
    z-index: 1;
  }

  .content {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-5);
  }

  @media (max-width: 1024px) {
    .shell {
      width: min(calc(100% - var(--space-3) * 2), var(--content-max));
      margin-top: calc(var(--navbar-height) + var(--space-3));
      grid-template-columns: 1fr;
      gap: var(--space-4);
    }
  }
</style>
