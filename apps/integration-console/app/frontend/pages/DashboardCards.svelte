<script>
  import { onMount } from "svelte"
  import MetricCardGrid from "../components/MetricCardGrid.svelte"

  export let initial = {}

  let cards = initial.cards || []
  let endpoint = initial.endpoint || "/?format=json"
  let loading = false
  let lastFetchAt = 0
  let pendingFetch = null
  const MIN_FETCH_INTERVAL_MS = 5000

  onMount(() => {
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
    loading = true
    try {
      const response = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)
      if (response?.status === 304) return
      if (!response?.ok) return

      let payload
      try {
        payload = await response.json()
      } catch {
        return
      }

      cards = payload.cards || cards
    } finally {
      loading = false
    }
  }
</script>

<MetricCardGrid cards={cards.map((card) => ({ ...card, loading }))} columns={3} />
