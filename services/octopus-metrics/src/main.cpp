#include "metrics/service.hpp"
#include <csignal>
#include <pthread.h>

int main() {
  using namespace metrics;
  try {
    // All workers inherit blocked termination signals. Only the main thread
    // consumes them; no async-signal-unsafe handler touches C++ objects.
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &signals, nullptr) != 0)
      return 1;
    const auto config = read_config(process_environment());
    if (!config) {
      log_event("startup_failed", config.error());
      return 1;
    }
    const CurlRuntime curl;
    {
      Repository repository{*config};
      if (auto verified =
              repository.verify(std::chrono::steady_clock::now() +
                                    std::chrono::seconds{config->timeout},
                                {});
          !verified) {
        log_event("schema_preflight_failed", verified.error());
        return 1;
      }
    }
    Service service{*config};
    service.start();
    while (!service.failed()) {
      sigset_t pending;
      if (sigpending(&pending) != 0)
        return 1;
      if (sigismember(&pending, SIGTERM) || sigismember(&pending, SIGINT)) {
        int received{};
        if (sigwait(&signals, &received) != 0)
          return 1;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    service.stop();
    log_event("metrics_stopped");
    return service.failed() ? 1 : 0;
  } catch (...) {
    log_event("startup_failed", Error::configuration);
    return 1;
  }
}
