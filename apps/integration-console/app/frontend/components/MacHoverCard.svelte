<script context="module">
  const lookupCache = new Map()
  const CACHE_LIMIT = 200
  const CACHE_TTL_MS = 60_000
</script>

<script>
  import { tick } from "svelte"
  import { formatTime, searchQueryForMac, searchUrl } from "../lib/format"

  export let mac = ""
  export let anchor = null
  export let open = false
  export let auditLogsUrl = ""
  export let identitiesUrl = ""
  export let shadowItUrl = ""
  export let inventoryUrl = ""
  export let summaryUrl = ""
  export let recentAuditLogsUrl = ""
  export let onDismiss = () => {}

  let loading = false
  let error = false
  let copied = false
  let data = null
  let placement = "below"
  let align = "left"
  let cardElement

  $: if (open && mac) load()

  async function load(force = false) {
    const key = mac.toLowerCase()
    const cached = cacheEntry(key)
    if (!force && cached) {
      data = cached.data
      error = false
      position()
      return
    }

    loading = true
    error = false

    try {
      const query = searchQueryForMac(mac)
      data = summaryUrl ? await fetchSummary(query) : await fetchLegacySummary(query)
      setCacheEntry(key, data)
    } catch {
      error = true
      data = null
    } finally {
      loading = false
      position()
    }
  }

  async function fetchJson(baseUrl, query) {
    if (!baseUrl) return []

    const url = new URL(baseUrl, window.location.origin)
    url.searchParams.set("q", query)
    if (!url.searchParams.has("limit")) url.searchParams.set("limit", "100")

    const response = await fetch(url, { headers: { accept: "application/json" } })
    if (!response.ok) throw new Error("Lookup failed")

    const body = await response.json()
    return Array.isArray(body) ? body : body.rows || []
  }

  async function fetchSummary(query) {
    const url = new URL(summaryUrl, window.location.origin)
    url.searchParams.set("q", query)

    const response = await fetch(url, { headers: { accept: "application/json" } })
    if (!response.ok) throw new Error("Lookup failed")

    return summarizePayload(await response.json())
  }

  async function fetchLegacySummary(query) {
    const [devices, auditLogs] = await Promise.all([
      fetchJson(inventoryUrl, query),
      fetchJson(recentAuditLogsUrl, query)
    ])

    return summarize(devices, auditLogs)
  }

  function summarizePayload(payload) {
    const inventory = payload?.inventory || {}
    const auditLogs = payload?.recentAuditLogs || []
    const registry = payload?.device || {}
    const base = summarize(inventory.source_mac ? [inventory] : [], auditLogs)

    return {
      ...base,
      registry,
      device: {
        ...base.device,
        ...inventory
      }
    }
  }

  function summarize(devices, auditLogs) {
    const normalized = mac.toLowerCase()
    const device = devices.find((entry) => entry.source_mac?.toLowerCase() === normalized) || devices[0] || {}
    const signals = auditLogs.map((row) => Number.parseInt(row.signal_dbm, 10)).filter(Number.isFinite)
    const sessions = unique(auditLogs.map((row) => row.session_key).filter(Boolean)).slice(0, 3)
    const observed = auditLogs.map((row) => row.observed_at).filter(Boolean).sort()
    const minSignal = signals.length ? Math.min(...signals) : null
    const maxSignal = signals.length ? Math.max(...signals) : null

    return {
      device,
      sessions,
      count: auditLogs.length || device.frame_count || 0,
      signal: minSignal === null ? "" : minSignal === maxSignal ? `${maxSignal} dBm` : `${minSignal} to ${maxSignal} dBm`,
      firstSeen: device.first_seen || observed[0],
      lastSeen: device.last_seen || observed[observed.length - 1]
    }
  }

  function unique(values) {
    return Array.from(new Set(values))
  }

  function cacheEntry(key) {
    const entry = lookupCache.get(key)
    if (!entry) return null

    if (Date.now() - entry.cachedAt > CACHE_TTL_MS) {
      lookupCache.delete(key)
      return null
    }

    return entry
  }

  function setCacheEntry(key, value) {
    lookupCache.set(key, { data: value, cachedAt: Date.now() })
    evictCache()
  }

  function evictCache() {
    const now = Date.now()
    for (const [key, entry] of lookupCache.entries()) {
      if (now - entry.cachedAt > CACHE_TTL_MS) lookupCache.delete(key)
    }

    while (lookupCache.size > CACHE_LIMIT) {
      lookupCache.delete(lookupCache.keys().next().value)
    }
  }

  async function position() {
    await tick()
    if (!anchor || !cardElement) return

    const rect = anchor.getBoundingClientRect()
    const cardRect = cardElement.getBoundingClientRect()
    placement = rect.bottom + cardRect.height + 12 > window.innerHeight && rect.top > cardRect.height ? "above" : "below"
    align = rect.left + cardRect.width > window.innerWidth - 12 ? "right" : "left"
  }

  function retry() {
    lookupCache.delete(mac.toLowerCase())
    load(true)
  }

  function copyMac() {
    navigator.clipboard?.writeText(mac).then(() => {
      copied = true
      window.setTimeout(() => {
        copied = false
      }, 1500)
    })
  }

  function handleKeydown(event) {
    if (event.key === "Escape") {
      event.preventDefault()
      onDismiss()
      return
    }

    if (event.key !== "Tab" || !cardElement) return

    const focusable = Array.from(cardElement.querySelectorAll("a[href], button:not([disabled])"))
    if (focusable.length === 0) return

    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  }

  function link(baseUrl) {
    return searchUrl(baseUrl || window.location.pathname, searchQueryForMac(mac))
  }
</script>

{#if open}
  <div
    bind:this={cardElement}
    class={[
      "absolute z-50 w-80 rounded-lg border border-(--color-border-strong) bg-(--color-surface) p-3 text-sm text-(--color-text) shadow-(--shadow-popover)",
      placement === "above" ? "bottom-full mb-2" : "top-full mt-2",
      align === "right" ? "right-0" : "left-0"
    ].join(" ")}
    role="dialog"
    aria-label={`MAC summary for ${mac}`}
    tabindex="-1"
    on:keydown={handleKeydown}
  >
    <div class="mb-2 flex items-start justify-between gap-2">
      <div class="min-w-0">
        <div class="truncate font-semibold text-(--color-accent-vivid)">{mac}</div>
        {#if data?.registry?.display_name || data?.registry?.username}
          <div class="mt-1 truncate text-xs text-(--color-text-muted)">{data.registry.display_name || "Known device"}{#if data.registry.username} / {data.registry.username}{/if}</div>
        {/if}
        {#if data?.device?.ssid}
          <div class="mt-1 inline-flex max-w-full rounded border border-(--color-border-strong) bg-(--color-accent-surface) px-2 py-0.5 text-xs text-(--color-accent-vivid)">{data.device.ssid}</div>
        {/if}
      </div>
      <button type="button" class="rounded border border-(--color-border-muted) px-2 py-1 text-xs text-(--color-accent-vivid)" on:click={onDismiss} aria-label="Close MAC summary">Close</button>
    </div>

    {#if loading}
      <div class="rounded bg-(--color-bg) p-3 text-(--color-text-muted)">Loading...</div>
    {:else if error}
      <div class="rounded border border-(--color-danger-border) bg-(--color-danger-surface) p-3 text-(--color-danger-text)">
        <div>No MAC summary available.</div>
        <button type="button" class="mt-2 rounded border border-(--color-danger-text) px-2 py-1 text-xs text-(--color-danger-text)" on:click={retry}>Retry</button>
      </div>
    {:else if data}
      <div class="grid grid-cols-3 gap-2">
        <div class="rounded bg-(--color-bg) p-2">
          <div class="truncate text-base font-semibold text-(--color-accent-vivid)">{data.count || "-"}</div>
          <div class="text-xs text-(--color-text-faint)">frames</div>
        </div>
        <div class="rounded bg-(--color-bg) p-2">
          <div class="truncate text-base font-semibold text-(--color-accent-vivid)">{data.signal || "-"}</div>
          <div class="text-xs text-(--color-text-faint)">signal</div>
        </div>
        <div class="rounded bg-(--color-bg) p-2">
          <div class="truncate text-base font-semibold text-(--color-accent-vivid)">{data.device?.protected_frame_count ?? "-"}</div>
          <div class="text-xs text-(--color-text-faint)">encrypted</div>
        </div>
      </div>

      {#if data.device?.ip_addresses}
        <div class="mt-2 truncate text-xs text-(--color-text-muted)">{data.device.ip_addresses}</div>
      {/if}
      {#if data.device?.services}
        <div class="mt-1 truncate text-xs text-(--color-text-muted)">{data.device.services}</div>
      {/if}

      <div class="mt-2 text-xs leading-5 text-(--color-text-faint)">
        <div>First: {formatTime(data.firstSeen) || "-"}</div>
        <div>Last: {formatTime(data.lastSeen) || "-"}</div>
      </div>

      <div class="mt-2 border-t border-(--color-border-muted) pt-2">
        <div class="mb-1 text-xs font-semibold uppercase tracking-wide text-(--color-accent-vivid)">Sessions</div>
        {#if data.sessions.length}
          <ul class="space-y-1">
            {#each data.sessions as session}
              <li class="truncate rounded bg-(--color-bg) px-2 py-1 text-xs text-(--color-text-muted)">{session}</li>
            {/each}
          </ul>
        {:else}
          <div class="text-xs text-(--color-text-faint)">No recent sessions.</div>
        {/if}
      </div>
    {/if}

    <div class="mt-3 flex flex-wrap gap-2 border-t border-(--color-border-muted) pt-2">
      <a class="rounded border border-(--color-border-strong) px-2 py-1 text-xs text-(--color-accent-vivid) hover:bg-(--color-accent-surface)" href={link(auditLogsUrl)}>Audit logs</a>
      <a class="rounded border border-(--color-border-strong) px-2 py-1 text-xs text-(--color-accent-vivid) hover:bg-(--color-accent-surface)" href={link(identitiesUrl)}>Identities</a>
      <a class="rounded border border-(--color-border-strong) px-2 py-1 text-xs text-(--color-accent-vivid) hover:bg-(--color-accent-surface)" href={link(shadowItUrl)}>Shadow IT</a>
      <button type="button" class="rounded border border-(--color-border-strong) px-2 py-1 text-xs text-(--color-accent-vivid) hover:bg-(--color-accent-surface)" on:click={copyMac}>{copied ? "Copied (OK)" : "Copy MAC"}</button>
    </div>
  </div>
{/if}
