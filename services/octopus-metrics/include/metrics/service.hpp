#pragma once
#include "metrics/adapters.hpp"
#include "metrics/queue.hpp"
#include <atomic>
#include <thread>
#include <vector>

namespace metrics {
class Service {
public:
  explicit Service(const Config &config);
  ~Service();
  void start();
  void stop();
  bool failed() const noexcept { return failed_.load(); }

private:
  const Config &config_;
  Cache cache_;
  JobQueue queue_;
  std::stop_source stop_;
  std::atomic<bool> failed_{};
  std::array<std::atomic<std::uint64_t>, 3> successes_{};
  std::atomic<std::uint64_t> errors_{};
  std::atomic<std::uint64_t> coalesced_{};
  std::atomic<std::uint64_t> publishes_{};
  std::atomic<std::int64_t> last_publish_{};
  std::vector<std::jthread> threads_;
  void worker();
  void scheduler();
  void publisher();
  void health();
  void launch(void (Service::*run)());
};
void log_event(std::string_view event,
               std::optional<Error> error = std::nullopt);
} // namespace metrics
