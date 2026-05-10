<script>
  import { onMount, onDestroy } from "svelte"

  let theme = "dark"
  let mediaQuery

  onMount(() => {
    const savedTheme = localStorage.getItem("theme")
    if (savedTheme) {
      setTheme(savedTheme, true)
    } else {
      const systemTheme = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"
      setTheme(systemTheme, false)
    }

    mediaQuery = window.matchMedia("(prefers-color-scheme: light)")
    mediaQuery.addEventListener("change", handleSystemThemeChange)
  })

  onDestroy(() => {
    if (mediaQuery) {
      mediaQuery.removeEventListener("change", handleSystemThemeChange)
    }
  })

  function setTheme(newTheme, persist = false) {
    theme = newTheme
    document.documentElement.setAttribute("data-theme", theme)
    if (persist) {
      localStorage.setItem("theme", theme)
    }
  }

  function toggleTheme() {
    const newTheme = theme === "dark" ? "light" : "dark"
    setTheme(newTheme, true)
  }

  function handleSystemThemeChange(event) {
    if (!localStorage.getItem("theme")) {
      const newTheme = event.matches ? "light" : "dark"
      setTheme(newTheme, false)
    }
  }
</script>

<button
  class="theme-switcher"
  on:click={toggleTheme}
  aria-label="Toggle theme"
  title="Toggle between light and dark theme"
>
  {#if theme === "dark"}
    <svg class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="12" cy="12" r="5"/>
      <line x1="12" y1="1" x2="12" y2="3"/>
      <line x1="12" y1="21" x2="12" y2="23"/>
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
      <line x1="1" y1="12" x2="3" y2="12"/>
      <line x1="21" y1="12" x2="23" y2="12"/>
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
    </svg>
  {:else}
    <svg class="theme-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
    </svg>
  {/if}
</button>

<style>
  .theme-switcher {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 36px;
    height: 36px;
    border: 1px solid var(--color-control-border);
    border-radius: 6px;
    background: var(--color-surface);
    color: var(--color-accent);
    cursor: pointer;
    transition: background-color 150ms ease, border-color 150ms ease;
  }

  .theme-switcher:hover {
    background: var(--color-surface-hover);
    border-color: var(--color-accent);
  }

  .theme-icon {
    width: 20px;
    height: 20px;
  }
</style>