#include "metrics/service.hpp"

#include <algorithm>
#include <condition_variable>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace metrics {
using namespace std::chrono;
void log_event(std::string_view event, std::optional<Error> error) {
  static std::mutex log_mutex;
  const std::lock_guard lock(log_mutex);
  auto& output = std::cerr;
  output << "{\"event\":\"" << event << '"';
  if (error)
    output << ",\"error\":\"" << error_name(*error) << '"';
  output << "}\n";
}
namespace {
bool wait_until(Deadline deadline, std::stop_token stop) {
  std::mutex mutex;
  std::condition_variable_any condition;
  std::unique_lock lock(mutex);
  condition.wait_until(lock, stop, deadline, [] { return false; });
  return !stop.stop_requested();
}
class Socket {
public:
  explicit Socket(int fd) : fd_(fd) {}
  ~Socket() {
    if (fd_ >= 0)
      ::close(fd_);
  }
  Socket(const Socket &) = delete;
  Socket &operator=(const Socket &) = delete;
  int get() const noexcept { return fd_; }

private:
  int fd_;
};
} // namespace
Service::Service(const Config &config) : config_(config) {}
Service::~Service() { stop(); }
void Service::launch(void (Service::*run)()) {
  threads_.emplace_back([this, run] {
    try {
      (this->*run)();
    } catch (...) {
      failed_.store(true);
      log_event("thread_failed", Error::invalid_data);
      stop_.request_stop();
      queue_.close();
    }
  });
}
void Service::start() {
  threads_.reserve(static_cast<std::size_t>(config_.workers) + 3);
  for (int i = 0; i < config_.workers; ++i)
    launch(&Service::worker);
  launch(&Service::scheduler);
  launch(&Service::publisher);
  launch(&Service::health);
  log_event("metrics_started");
}
void Service::stop() {
  stop_.request_stop();
  queue_.close();
  for (auto &thread : threads_)
    if (thread.joinable())
      thread.join();
  threads_.clear();
}
void Service::worker() {
  // Thread-confined connections/parser handles. Blocking stores run exclusively
  // in the publisher, so a store outage cannot consume a compute worker.
  Repository repository{config_};
  Http http{config_};
  const auto stop = stop_.get_token();
  while (const auto job = queue_.take(stop)) {
    const Completion completion{queue_, *job};
    const auto at = now();
    const auto deadline = steady_clock::now() + seconds{config_.timeout};
    Result<void> result;
    switch (*job) {
    case Job::peaks: {
      auto value = repository.aggregates(deadline, stop);
      if (value)
        cache_.update(&State::aggregates, Measured<Aggregates>{*value, at});
      else
        result = std::unexpected(value.error());
      break;
    }
    case Job::history: {
      auto value = repository.history(at, deadline, stop);
      if (value)
        cache_.update(&State::history, Measured<History>{*value, at});
      else
        result = std::unexpected(value.error());
      break;
    }
    case Job::live: {
      auto value = http.live(deadline, stop);
      if (value)
        cache_.update(&State::live, *value);
      else
        result = std::unexpected(value.error());
      break;
    }
    }
    if (result)
      ++successes_[static_cast<std::size_t>(*job)];
    else {
      ++errors_;
      log_event("refresh_failed", result.error());
    }
  }
}
void Service::scheduler() {
  const std::array intervals{seconds{config_.peaks_interval},
                             seconds{config_.history_interval},
                             seconds{config_.live_interval}};
  const auto stop = stop_.get_token();
  std::array<Deadline, 3> due{};
  due.fill(steady_clock::now());
  while (!stop.stop_requested()) {
    const auto at = steady_clock::now();
    for (std::size_t i = 0; i < due.size(); ++i) {
      if (due[i] <= at) {
        if (!queue_.offer(static_cast<Job>(i)))
          ++coalesced_;
        due[i] = at + intervals[i];
      }
    }
    if (!wait_until(*std::min_element(due.begin(), due.end()), stop))
      break;
  }
}
void Service::publisher() {
  Http http{config_};
  Redis redis{config_};
  Repository repository{config_};
  const auto stop = stop_.get_token();
  while (wait_until(steady_clock::now() + seconds{config_.publish_interval},
                    stop)) {
    const auto state = cache_.read();
    // Gate publication on the canonical schema proof, also after a schema
    // change. Measurement failures still publish partial last-good data.
    auto proof = repository.verify(steady_clock::now() + seconds{config_.timeout}, stop);
    if (!proof) {
      ++errors_;
      log_event("schema_preflight_failed", proof.error());
      continue;
    }
    const auto at = now();
    std::array<std::byte, 32768> buffer{};
    std::pmr::monotonic_buffer_resource arena{buffer.data(), buffer.size(),
                                              std::pmr::null_memory_resource()};
    const auto json = serialize(state, at, arena);
    // Give each independent destination its own deadline. One outage must not
    // exhaust the other destination's opportunity to publish the same snapshot.
    auto hot =
        redis.save(json, steady_clock::now() + seconds{config_.timeout}, stop);
    if (!hot) {
      ++errors_;
      log_event("redis_publish_failed", hot.error());
    }
    bool durable = false;
    const auto paths = object_paths(at);
    for (std::size_t i = 0; i < paths.size() && !stop.stop_requested(); ++i) {
      auto saved =
          http.object(paths[i], json, at,
                      steady_clock::now() + seconds{config_.timeout}, stop);
      if (i == 0)
        durable = saved.has_value();
      if (!saved) {
        ++errors_;
        log_event("object_publish_failed", saved.error());
      }
    }
    if (hot || durable) {
      ++publishes_;
      last_publish_.store(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
      log_event("snapshot_published");
    }
  }
}
void Service::health() {
  const Socket listener{socket(AF_INET, SOCK_STREAM, 0)};
  if (listener.get() < 0)
    throw std::runtime_error("health socket");
  if (fcntl(listener.get(), F_SETFL, O_NONBLOCK) != 0)
    throw std::runtime_error("health socket");
  const int reuse = 1;
  if (setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &reuse,
                 sizeof(reuse)) != 0)
    throw std::runtime_error("health socket");
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  address.sin_port = htons(static_cast<std::uint16_t>(config_.http_port));
  if (bind(listener.get(), reinterpret_cast<const sockaddr *>(&address),
           sizeof(address)) != 0 ||
      listen(listener.get(), 16) != 0)
    throw std::runtime_error("health bind");
  const auto stop = stop_.get_token();
  while (!stop.stop_requested()) {
    pollfd socket_poll{listener.get(), POLLIN, 0};
    if (poll(&socket_poll, 1, 100) <= 0)
      continue;
    const Socket client{accept(listener.get(), nullptr, nullptr)};
    if (client.get() < 0)
      continue;
#ifdef SO_NOSIGPIPE
    const int no_signal = 1;
    if (setsockopt(client.get(), SOL_SOCKET, SO_NOSIGPIPE, &no_signal,
                   sizeof(no_signal)) != 0)
      continue;
#endif
    const timeval limit{0, 250000};
    if (setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, &limit,
                   sizeof(limit)) != 0 ||
        setsockopt(client.get(), SOL_SOCKET, SO_SNDTIMEO, &limit,
                   sizeof(limit)) != 0)
      continue;
    std::array<char, 2048> request{};
    std::size_t count{};
    const auto request_deadline = steady_clock::now() + milliseconds{250};
    while (count < request.size() && !stop.stop_requested() && steady_clock::now() < request_deadline) {
      pollfd input{client.get(), POLLIN, 0};
      if (poll(&input, 1, 20) <= 0) continue;
      const auto received = recv(client.get(), request.data() + count, request.size() - count, 0);
      if (received <= 0) break;
      count += static_cast<std::size_t>(received);
      if (std::string_view{request.data(), count}.find("\r\n") != std::string_view::npos) break;
    }
    if (count == 0)
      continue;
    const std::string_view line{request.data(), count};
    std::string body;
    std::string_view status = "200 OK";
    std::string_view type = "application/json";
    if (line.starts_with("GET /live HTTP/1."))
      body = "{\"status\":\"UP\"}";
    else if (line.starts_with("GET /ready HTTP/1.")) {
      const auto state = cache_.read();
      const auto at = now();
      const auto published_at = last_publish_.load();
      const auto monotonic_now = duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
      const bool ready =
          state.aggregates && state.history && published_at > 0 &&
          monotonic_now - published_at <= (config_.publish_interval * 2LL + config_.timeout) * 1000 &&
          at >= state.aggregates->at &&
          at - state.aggregates->at <=
              seconds{config_.peaks_interval * 2 + config_.timeout} &&
          at >= state.history->at &&
          at - state.history->at <=
              seconds{config_.history_interval * 2 + config_.timeout};
      body = ready ? "{\"status\":\"UP\"}" : "{\"status\":\"DOWN\"}";
      if (!ready)
        status = "503 Service Unavailable";
    } else if (line.starts_with("GET /metrics HTTP/1.")) {
      type = "text/plain; version=0.0.4";
      body = "# TYPE octopus_metrics_refresh_total counter\n";
      constexpr std::array names{"peaks", "history", "live"};
      for (std::size_t i = 0; i < names.size(); ++i)
        body += "octopus_metrics_refresh_total{job=\"" + std::string{names[i]} +
                "\"} " + std::to_string(successes_[i].load()) + "\n";
      body += "# TYPE octopus_metrics_errors_total "
              "counter\noctopus_metrics_errors_total " +
              std::to_string(errors_.load()) +
              "\n# TYPE octopus_metrics_coalesced_total "
              "counter\noctopus_metrics_coalesced_total " +
              std::to_string(coalesced_.load()) +
              "\n# TYPE octopus_metrics_publish_total "
              "counter\noctopus_metrics_publish_total " +
              std::to_string(publishes_.load()) + "\n";
    } else {
      status = "404 Not Found";
      body = "{}";
    }
    const auto response = "HTTP/1.1 " + std::string{status} +
                          "\r\nContent-Type: " + std::string{type} +
                          "\r\nConnection: close\r\nContent-Length: " +
                          std::to_string(body.size()) + "\r\n\r\n" + body;
    std::size_t offset{};
    const auto response_deadline = steady_clock::now() + milliseconds{250};
    while (offset < response.size() && !stop.stop_requested() && steady_clock::now() < response_deadline) {
#ifdef MSG_NOSIGNAL
      constexpr int flags = MSG_NOSIGNAL;
#else
      constexpr int flags = 0;
#endif
      const auto sent = send(client.get(), response.data() + offset,
                             response.size() - offset, flags);
      if (sent <= 0)
        break;
      offset += static_cast<std::size_t>(sent);
    }
  }
}
} // namespace metrics
