<script context="module">
  const lookupCache = new Map()
  const CACHE_LIMIT = 80
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
    if (!force && lookupCache.has(key)) {
      data = lookupCache.get(key)
      error = false
      position()
      return
    }

    loading = true
    error = false

    try {
      const query = searchQueryForMac(mac)
      const [devices, auditLogs] = await Promise.all([
        fetchJson(inventoryUrl, query),
        fetchJson(recentAuditLogsUrl, query)
      ])

      data = summarize(devices, auditLogs)
      lookupCache.set(key, data)
      if (lookupCache.size > CACHE_LIMIT) lookupCache.delete(lookupCache.keys().next().value)
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
      "absolute z-50 w-80 rounded-lg border border-[#1f6b1f] bg-[#111a11] p-3 text-sm text-[#c8e6c8] shadow-2xl shadow-black/60",
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
        <div class="truncate font-semibold text-[#4ade80]">{mac}</div>
        {#if data?.device?.ssid}
          <div class="mt-1 inline-flex max-w-full rounded border border-[#1f6b1f] bg-[#0f2d0f] px-2 py-0.5 text-xs text-[#86efac]">{data.device.ssid}</div>
        {/if}
      </div>
      <button type="button" class="rounded border border-[#1f3320] px-2 py-1 text-xs text-[#86efac]" on:click={onDismiss} aria-label="Close MAC summary">Close</button>
    </div>

    {#if loading}
      <div class="rounded bg-[#0d130d] p-3 text-[#6b9e6b]">Loading...</div>
    {:else if error}
      <div class="rounded border border-[#7f1d1d] bg-[#190d0d] p-3 text-[#f87171]">
        <div>No MAC summary available.</div>
        <button type="button" class="mt-2 rounded border border-[#f87171] px-2 py-1 text-xs text-[#fecaca]" on:click={retry}>Retry</button>
      </div>
    {:else if data}
      <div class="grid grid-cols-3 gap-2">
        <div class="rounded bg-[#0d130d] p-2">
          <div class="truncate text-base font-semibold text-[#4ade80]">{data.count || "-"}</div>
          <div class="text-xs text-[#4d7a4d]">frames</div>
        </div>
        <div class="rounded bg-[#0d130d] p-2">
          <div class="truncate text-base font-semibold text-[#4ade80]">{data.signal || "-"}</div>
          <div class="text-xs text-[#4d7a4d]">signal</div>
        </div>
        <div class="rounded bg-[#0d130d] p-2">
          <div class="truncate text-base font-semibold text-[#4ade80]">{data.device?.protected_frame_count ?? "-"}</div>
          <div class="text-xs text-[#4d7a4d]">encrypted</div>
        </div>
      </div>

      {#if data.device?.ip_addresses}
        <div class="mt-2 truncate text-xs text-[#6b9e6b]">{data.device.ip_addresses}</div>
      {/if}
      {#if data.device?.services}
        <div class="mt-1 truncate text-xs text-[#6b9e6b]">{data.device.services}</div>
      {/if}

      <div class="mt-2 text-xs leading-5 text-[#4d7a4d]">
        <div>First: {formatTime(data.firstSeen) || "-"}</div>
        <div>Last: {formatTime(data.lastSeen) || "-"}</div>
      </div>

      <div class="mt-2 border-t border-[#1a2e1a] pt-2">
        <div class="mb-1 text-xs font-semibold uppercase tracking-wide text-[#86efac]">Sessions</div>
        {#if data.sessions.length}
          <ul class="space-y-1">
            {#each data.sessions as session}
              <li class="truncate rounded bg-[#0d130d] px-2 py-1 text-xs text-[#a3d9a3]">{session}</li>
            {/each}
          </ul>
        {:else}
          <div class="text-xs text-[#4d7a4d]">No recent sessions.</div>
        {/if}
      </div>
    {/if}

    <div class="mt-3 flex flex-wrap gap-2 border-t border-[#1a2e1a] pt-2">
      <a class="rounded border border-[#1f6b1f] px-2 py-1 text-xs text-[#86efac] hover:bg-[#0f2d0f]" href={link(auditLogsUrl)}>Audit logs</a>
      <a class="rounded border border-[#1f6b1f] px-2 py-1 text-xs text-[#86efac] hover:bg-[#0f2d0f]" href={link(identitiesUrl)}>Identities</a>
      <a class="rounded border border-[#1f6b1f] px-2 py-1 text-xs text-[#86efac] hover:bg-[#0f2d0f]" href={link(shadowItUrl)}>Shadow IT</a>
      <button type="button" class="rounded border border-[#1f6b1f] px-2 py-1 text-xs text-[#86efac] hover:bg-[#0f2d0f]" on:click={copyMac}>{copied ? "Copied" : "Copy MAC"}</button>
    </div>
  </div>
{/if}

