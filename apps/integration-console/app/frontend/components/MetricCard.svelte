<script>
  import { icons } from "../lib/icons"

  export let label = ""
  export let value = ""
  export let subValue = ""
  export let status = "neutral"
  export let trend = "flat"
  export let trendLabel = ""
  export let icon = null
  export let loading = false
  export let sparkline = []

  $: statusClass = {
    ok: "border-l-[#4ade80]",
    warn: "border-l-[#fbbf24]",
    alert: "border-l-[#f87171]",
    neutral: "border-l-[#4d7a4d]"
  }[status] || "border-l-[#4d7a4d]"

  $: trendClass = {
    up: "text-[#4ade80]",
    down: "text-[#f87171]",
    flat: "text-[#6b9e6b]"
  }[trend] || "text-[#6b9e6b]"

  $: path = sparklinePath(sparkline)
  $: iconPaths = icons[icon] || []

  function sparklinePath(points) {
    if (!Array.isArray(points) || points.length < 2) return ""

    const numbers = points.map(Number).filter(Number.isFinite)
    if (numbers.length < 2) return ""

    const min = Math.min(...numbers)
    const max = Math.max(...numbers)
    const span = max - min || 1
    const step = 100 / (numbers.length - 1)

    return numbers.map((point, index) => {
      const x = index * step
      const y = 28 - ((point - min) / span) * 24
      return `${index === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`
    }).join(" ")
  }
</script>

<article class={`rounded-lg border border-[#1f3320] border-l-4 ${statusClass} bg-[#111a11] p-4`}>
  <div class="flex items-start justify-between gap-3">
    <div>
      <div class="text-xs font-semibold uppercase tracking-wide text-[#6b9e6b]">{label}</div>
      {#if loading}
        <div class="mt-3 h-8 w-24 animate-pulse rounded bg-[#1f3320]"></div>
      {:else}
        <div class="mt-2 text-3xl font-bold text-[#4ade80]">{value}</div>
      {/if}
      {#if subValue}
        <div class="mt-1 text-sm text-[#a3d9a3]">{subValue}</div>
      {/if}
    </div>
    {#if iconPaths.length}
      <svg class="h-8 w-8 shrink-0 text-[#86efac]" viewBox="0 0 24 24" aria-hidden="true">
        {#each iconPaths as d}
          <path {d} fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        {/each}
      </svg>
    {/if}
  </div>

  {#if trendLabel}
    <div class={`mt-3 text-sm font-semibold ${trendClass}`}>
      <span aria-hidden="true">{#if trend === "up"}&uarr;{:else if trend === "down"}&darr;{:else}&rarr;{/if}</span>
      <span>{trendLabel}</span>
    </div>
  {/if}

  {#if path}
    <svg class="mt-3 h-8 w-full text-[#4ade80]" viewBox="0 0 100 32" preserveAspectRatio="none" aria-hidden="true">
      <path d={path} fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" />
    </svg>
  {/if}
</article>
