import { application } from "controllers/application"
import LiveFeedController from "controllers/live_feed_controller"

application.register("live-feed", LiveFeedController)
