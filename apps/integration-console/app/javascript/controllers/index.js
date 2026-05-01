import { application } from "./application"
import AuditLogController from "./audit_log_controller"
import FlashController from "./flash_controller"
import LiveFeedController from "./live_feed_controller"
import MacLinkController from "./mac_link_controller"
import SidebarController from "./sidebar_controller"
import TurboLoadingController from "./turbo_loading_controller"

application.register("audit-log", AuditLogController)
application.register("flash", FlashController)
application.register("live-feed", LiveFeedController)
application.register("mac-link", MacLinkController)
application.register("sidebar", SidebarController)
application.register("turbo-loading", TurboLoadingController)
