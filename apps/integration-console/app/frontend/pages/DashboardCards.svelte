<script>
  import { onMount } from "svelte"
  import MetricCardGrid from "../components/MetricCardGrid.svelte"

  export let initial = {}

  let cards = initial.cards || skeletonCards()
  let endpoint = initial.endpoint || "/health/cards.json"
  let loadingLabels = new Set(cards.map((card) => card.label))
  let errors = {}
  let lastFetchAt = 0
  let pendingFetch = null
  const MIN_FETCH_INTERVAL_MS = 5000

  onMount(() => {
    fetchCards()
    const refresh = () => scheduleFetchCards()
    window.addEventListener("sensor-health", refresh)
    window.addEventListener("alert", refresh)

    return () => {
      window.removeEventListener("sensor-health", refresh)
      window.removeEventListener("alert", refresh)
      window.clearTimeout(pendingFetch)
    }
  })

  function scheduleFetchCards() {
    const elapsed = Date.now() - lastFetchAt
    if (elapsed >= MIN_FETCH_INTERVAL_MS) {
      fetchCards()
      return
    }

    window.clearTimeout(pendingFetch)
    pendingFetch = window.setTimeout(fetchCards, MIN_FETCH_INTERVAL_MS - elapsed)
  }

  async function fetchCards() {
    window.clearTimeout(pendingFetch)
    pendingFetch = null
    lastFetchAt = Date.now()
    try {
      const response = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)
      if (response?.status === 304) return
      if (!response?.ok) {
        markErrors("Unable to load cards.")
        return
      }

      let payload
      try {
        payload = await response.json()
      } catch {
        return
      }

      const nextCards = payload.cards || []
      cards = nextCards.length ? nextCards : cards
      loadingLabels = new Set()
      errors = {}
    } finally {
    }
  }

  function markErrors(message) {
    loadingLabels = new Set()
    errors = Object.fromEntries(cards.map((card) => [card.label, message]))
  }

  function skeletonCards() {
    return [
      { label: "Active Sensors", icon: "sensor" },
      { label: "Stale Sensors", icon: "wifi" },
      { label: "Backlog Pending / Failed", icon: "backlog" },
      { label: "Wireless Events 24h", icon: "wifi" },
      { label: "Ingest Pending", icon: "backlog" },
      { label: "Open Shadow IT", icon: "alert" },
      { label: "Job Orphans", icon: "backlog" }
    ]
  }
</script>

<MetricCardGrid cards={cards.map((card) => ({ ...card, loading: loadingLabels.has(card.label), subValue: errors[card.label] || card.subValue }))} columns={3} />
