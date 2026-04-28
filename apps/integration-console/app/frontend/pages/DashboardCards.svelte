<script>
  import { onMount } from "svelte"
  import MetricCardGrid from "../components/MetricCardGrid.svelte"

  export let initial = {}

  let cards = initial.cards || []
  let endpoint = initial.endpoint || "/?format=json"
  let loading = false

  onMount(() => {
    const refresh = () => fetchCards()
    window.addEventListener("sensor-health", refresh)
    window.addEventListener("alert", refresh)

    return () => {
      window.removeEventListener("sensor-health", refresh)
      window.removeEventListener("alert", refresh)
    }
  })

  async function fetchCards() {
    loading = true
    const response = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)
    loading = false
    if (!response?.ok) return

    const payload = await response.json()
    cards = payload.cards || cards
  }
</script>

<MetricCardGrid cards={cards.map((card) => ({ ...card, loading }))} columns={3} />
