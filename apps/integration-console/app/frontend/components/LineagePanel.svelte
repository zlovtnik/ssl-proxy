<script>
  export let lineage = { nodes: [], edges: [] }

  $: nodes = lineage?.nodes || []
  $: edges = lineage?.edges || []
  $: layout = positionNodes(nodes)
  $: positioned = layout.nodes
  $: viewBoxHeight = layout.height

  function positionNodes(list) {
    const xByType = { source: 80, store: 280, destination: 500 }
    const counts = {}
    for (const node of list) counts[node.type] = (counts[node.type] || 0) + 1
    const maxCount = Math.max(1, ...Object.values(counts))
    const top = 52
    const bottom = 52
    const spacing = 95
    const height = Math.max(320, top + bottom + (maxCount - 1) * spacing)
    const placedCounts = {}

    return {
      height,
      nodes: list.map((node) => {
        const index = placedCounts[node.type] || 0
        placedCounts[node.type] = index + 1
        return { ...node, x: xByType[node.type] || 80, y: top + index * spacing }
      })
    }
  }

  function edgeKey(edge, index) {
    return edge.id || `${edge.from}-${edge.to}-${edge.label || index}`
  }

  function nodeKey(item, index) {
    return item.id || item.key || index
  }

  function node(id) {
    return positioned.find((item) => item.id === id)
  }

  function edgeClass(status) {
    if (status === "error") return "stroke-(--color-danger-text)"
    if (status === "warn") return "stroke-(--color-accent)"
    return "stroke-(--color-accent-vivid)"
  }
</script>

<div class="rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-3">
  {#if nodes.length === 0}
    <div class="text-sm text-(--color-text-muted)">No enabled integrations yet.</div>
  {:else}
    <svg class="w-full" style={`height: ${viewBoxHeight}px`} viewBox={`0 0 620 ${viewBoxHeight}`} role="img" aria-label="Integration lineage">
      {#each edges as edge, index (edgeKey(edge, index))}
        {@const from = node(edge.from)}
        {@const to = node(edge.to)}
        {#if from && to}
          <line x1={from.x + 45} y1={from.y} x2={to.x - 45} y2={to.y} class={edgeClass(edge.status)} stroke-width="3" />
          <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 8} text-anchor="middle" class="fill-(--color-text-muted) text-xs">{edge.label}</text>
        {/if}
      {/each}
      {#each positioned as item, index (nodeKey(item, index))}
        {#if item.type === "source"}
          <circle cx={item.x} cy={item.y} r="38" class="fill-(--color-accent-surface) stroke-(--color-border-strong)" stroke-width="2" />
        {:else if item.type === "destination"}
          <rect x={item.x - 34} y={item.y - 34} width="68" height="68" transform={`rotate(45 ${item.x} ${item.y})`} class="fill-(--color-bg) stroke-(--color-border-strong)" stroke-width="2" />
        {:else}
          <rect x={item.x - 58} y={item.y - 30} width="116" height="60" rx="6" class="fill-(--color-bg) stroke-(--color-border-strong)" stroke-width="2" />
        {/if}
        <text x={item.x} y={item.y - 4} text-anchor="middle" class="fill-(--color-text) text-xs font-semibold">{item.label}</text>
        <text x={item.x} y={item.y + 14} text-anchor="middle" class="fill-(--color-text-muted) text-xs">{item.event_count_24h ?? item.row_count ?? 0} rows</text>
      {/each}
    </svg>
  {/if}
</div>
