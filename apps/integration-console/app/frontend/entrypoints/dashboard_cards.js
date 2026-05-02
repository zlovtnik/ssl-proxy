import { mountPage } from "../lib/mount"
import DashboardCards from "../pages/DashboardCards.svelte"
import LiveFeedPanel from "../pages/LiveFeedPanel.svelte"
import NatsThroughputPanel from "../pages/NatsThroughputPanel.svelte"
import RecentAlertsPanel from "../pages/RecentAlertsPanel.svelte"
import SensorsPanel from "../pages/SensorsPanel.svelte"
import SyncHealthPanel from "../pages/SyncHealthPanel.svelte"
import ThreatAlertsPanel from "../pages/ThreatAlertsPanel.svelte"

mountPage(DashboardCards, "dashboard-cards-svelte-root")
mountPage(LiveFeedPanel, "live-feed-panel-svelte-root")
mountPage(NatsThroughputPanel, "nats-throughput-svelte-root")
mountPage(RecentAlertsPanel, "recent-alerts-svelte-root")
mountPage(SyncHealthPanel, "sync-health-svelte-root")
mountPage(SensorsPanel, "sensors-panel-svelte-root")
mountPage(ThreatAlertsPanel, "threat-alerts-panel-svelte-root")
