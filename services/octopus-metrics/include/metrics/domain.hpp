#pragma once

#include <array>
#include <chrono>
#include <concepts>
#include <cstdint>
#include <expected>
#include <memory_resource>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace metrics {
using Time = std::chrono::sys_time<std::chrono::milliseconds>;
using Deadline = std::chrono::steady_clock::time_point;
enum class Error {
  configuration,
  cancelled,
  timeout,
  network,
  database,
  schema,
  invalid_data,
  conflict
};
std::string_view error_name(Error error) noexcept;
template <class T> using Result = std::expected<T, Error>;
Time now();
std::string iso(Time at);
std::string date(Time at);
Result<Time> parse_time(std::string_view text);
Result<std::string> ordering_stamp(std::string_view text);
Result<std::int64_t> parse_count(std::string_view text);

struct DayPeak {
  std::int64_t records;
  Time day;
};
struct WeekPeak {
  std::int64_t records;
  Time start;
  Time end;
};
struct Aggregates {
  std::optional<DayPeak> day;
  std::optional<WeekPeak> week;
  std::int64_t records_total{};
  std::int64_t days_counted{};
};
struct HourPoint {
  Time start;
  std::int64_t records;
};
// All buckets are implicit from 'until'; the hot numeric array is contiguous.
struct History {
  Time until;
  std::array<std::int64_t, 168> counts{};
};
Result<History> fill_hours(std::span<const HourPoint> rows, Time at);
struct Live {
  double rate{};
  std::int64_t pending{};
  std::optional<Time> last_success;
  bool backpressure{};
};
template <class T> struct Measured {
  T value;
  Time at;
};
struct State {
  std::optional<Measured<Aggregates>> aggregates;
  std::optional<Measured<History>> history;
  std::optional<Measured<std::optional<Live>>> live;
};
// Ref.update equivalent. Work/I/O runs outside the mutex; copy a coherent view
// in one short critical section. No mutable state escapes the cache.
class Cache {
public:
  template <class T>
  void update(std::optional<Measured<T>> State::*member, Measured<T> value) {
    const std::lock_guard lock(mutex_);
    auto &previous = state_.*member;
    if (!previous || previous->at <= value.at)
      previous = std::move(value);
  }
  State read() const {
    const std::lock_guard lock(mutex_);
    return state_;
  }

private:
  mutable std::mutex mutex_;
  State state_;
};
std::pmr::string serialize(const State &state, Time at,
                           std::pmr::memory_resource &arena);
std::array<std::string, 3> object_paths(Time at);
} // namespace metrics
