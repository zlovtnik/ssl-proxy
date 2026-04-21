<script lang="ts">
  import { page } from '$app/stores';
  import StatusDot from '$lib/components/ui/StatusDot.svelte';
  import { connection } from '$lib/stores/connection.svelte';

  const navLinks = [
    { href: '/', label: 'Dashboard' },
    { href: '/hosts', label: 'Hosts' },
    { href: '/peers', label: 'Peers' },
    { href: '/devices', label: 'Devices' }
  ];

  const isActive = (href: string): boolean =>
    href === '/' ? $page.url.pathname === '/' : $page.url.pathname.startsWith(href);

  const live = $derived(connection.status === 'connected');
</script>

<nav class="navbar">
  <a href="/" class="brand" aria-label="ssl-proxy dashboard">
    <div class="brand-mark" aria-hidden="true"></div>
    <span class="brand-name">ssl-proxy</span>
  </a>

  <div class="nav-links" role="navigation" aria-label="Main navigation">
    {#each navLinks as { href, label }}
      <a {href} class="nav-link" class:active={isActive(href)}>{label}</a>
    {/each}
  </div>

  <div class="nav-end">
    <StatusDot status={live ? 'success' : 'neutral'} pulse={live} label={live ? 'Live' : 'Degraded'} />
  </div>
</nav>

<style>
  .navbar {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    height: var(--navbar-height);
    display: flex;
    align-items: center;
    gap: var(--space-4);
    padding: 0 var(--space-6);
    background: color-mix(in oklab, var(--bg-surface) 88%, transparent);
    border-bottom: 0.5px solid var(--border-subtle);
    backdrop-filter: blur(12px);
    z-index: 100;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    text-decoration: none;
    flex-shrink: 0;
  }

  .brand-mark {
    width: 24px;
    height: 24px;
    background: linear-gradient(145deg, var(--color-info), #1a7dd9);
    border-radius: var(--radius-sm);
    box-shadow: 0 0 18px rgba(88, 166, 255, 0.35);
  }

  .brand-name {
    font-size: var(--text-md);
    font-weight: var(--weight-bold);
    color: var(--text-primary);
    font-family: var(--font-mono);
  }

  .nav-links {
    display: flex;
    align-items: center;
    gap: var(--space-1);
    flex: 1;
    overflow-x: auto;
  }

  .nav-link {
    padding: 6px var(--space-3);
    border-radius: var(--radius-md);
    font-size: var(--text-base);
    font-weight: var(--weight-medium);
    color: var(--text-secondary);
    text-decoration: none;
    transition: background 0.15s, color 0.15s;
  }

  .nav-link:hover {
    background: var(--bg-elevated);
    color: var(--text-primary);
  }

  .nav-link.active {
    background: var(--bg-overlay);
    color: var(--text-primary);
  }

  .nav-end {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    flex-shrink: 0;
  }

  @media (max-width: 1024px) {
    .navbar {
      padding: 0 var(--space-3);
    }

    .brand-name {
      display: none;
    }
  }
</style>
