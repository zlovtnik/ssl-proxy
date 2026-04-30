<script>
  import { icons } from "../lib/icons"
  import SkeletonCard from "./SkeletonCard.svelte"

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
    ok: "border-l-(--color-accent-vivid)",
    warn: "border-l-(--color-accent)",
    alert: "border-l-(--color-danger-text)",
    neutral: "border-l-(--color-border)"
  }[status] || "border-l-(--color-border)"

  $: trendClass = {
    up: "text-(--color-accent-vivid)",
    down: "text-(--color-danger-text)",
    flat: "text-(--color-text-muted)"
  }[trend] || "text-(--color-text-muted)"

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

{#if loading}
  <SkeletonCard>
    <svelte:fragment slot="label">
      <div class="text-xs font-semibold uppercase tracking-wide text-(--color-text-muted)">{label}</div>
    </svelte:fragment>
    <svelte:fragment slot="icon">
      {#if iconPaths.length}
        <svg class="h-8 w-8 shrink-0 text-(--color-accent-vivid)" viewBox="0 0 24 24" aria-hidden="true">
          {#each iconPaths as d}
            <path {d} fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          {/each}
        </svg>
      {/if}
    </svelte:fragment>
  </SkeletonCard>
{:else}
<article class={`rounded-lg border border-(--color-border-muted) border-l-4 ${statusClass} bg-(--color-surface) p-4`}>
  <div class="flex items-start justify-between gap-3">
    <div>
      <div class="text-xs font-semibold uppercase tracking-wide text-(--color-text-muted)">{label}</div>
      <div class="mt-2 text-3xl font-bold text-(--color-accent-vivid)">{value}</div>
      {#if subValue}
        <div class="mt-1 text-sm text-(--color-text-muted)">{subValue}</div>
      {/if}
    </div>
    {#if iconPaths.length}
      <svg class="h-8 w-8 shrink-0 text-(--color-accent-vivid)" viewBox="0 0 24 24" aria-hidden="true">
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
    <svg class="mt-3 h-8 w-full text-(--color-accent-vivid)" viewBox="0 0 100 32" preserveAspectRatio="none" aria-hidden="true">
      <path d={path} fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" />
    </svg>
  {/if}
</article>
{/if}
