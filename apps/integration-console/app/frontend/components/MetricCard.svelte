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
    ok: "border-l-[var(--color-accent-vivid)]",
    warn: "border-l-[var(--color-accent)]",
    alert: "border-l-[var(--color-danger-text)]",
    neutral: "border-l-[var(--color-border)]"
  }[status] || "border-l-[var(--color-border)]"

  $: trendClass = {
    up: "text-[var(--color-accent-vivid)]",
    down: "text-[var(--color-danger-text)]",
    flat: "text-[var(--color-text-muted)]"
  }[trend] || "text-[var(--color-text-muted)]"

  $: path = sparklinePath(sparkline)
  $: iconPaths = icons[icon] || []

  function sparklinePath(points) {
    if (!Array.isArray(points) || points.length === 0) return ""

    const numbers = points.map(Number).filter(Number.isFinite)
    if (numbers.length === 0) return ""
    if (numbers.length === 1) numbers.push(numbers[0])

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

<article class={`rounded-lg border border-[var(--color-border-muted)] border-l-4 ${statusClass} bg-[var(--color-surface)] p-4`}>
  <div class="flex items-start justify-between gap-3">
    <div>
      <div class="text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">{label}</div>
      {#if loading}
        <div class="mt-3 h-8 w-24 animate-pulse rounded bg-[var(--color-border-muted)]"></div>
      {:else}
        <div class="mt-2 text-3xl font-bold text-[var(--color-accent-vivid)]">{value}</div>
      {/if}
      {#if subValue}
        <div class="mt-1 text-sm text-[var(--color-text-muted)]">{subValue}</div>
      {/if}
    </div>
    {#if iconPaths.length}
      <svg class="h-8 w-8 shrink-0 text-[var(--color-accent-vivid)]" viewBox="0 0 24 24" aria-hidden="true">
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
    <svg class="mt-3 h-8 w-full text-[var(--color-accent-vivid)]" viewBox="0 0 100 32" preserveAspectRatio="none" aria-hidden="true">
      <path d={path} fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" />
    </svg>
  {/if}
</article>
