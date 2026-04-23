import { application } from "controllers/application"
import AuditLogController from "controllers/audit_log_controller"
import FlashController from "controllers/flash_controller"
import LiveFeedController from "controllers/live_feed_controller"
import MacLinkController from "controllers/mac_link_controller"
import SidebarController from "controllers/sidebar_controller"
import TurboLoadingController from "controllers/turbo_loading_controller"

application.register("audit-log", AuditLogController)
application.register("flash", FlashController)
application.register("live-feed", LiveFeedController)
application.register("mac-link", MacLinkController)
application.register("sidebar", SidebarController)
application.register("turbo-loading", TurboLoadingController)
