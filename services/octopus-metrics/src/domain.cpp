#include "metrics/domain.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <limits>

namespace metrics {
using namespace std::chrono;
std::string_view error_name(Error error) noexcept {
  switch (error) {
  case Error::configuration:
    return "configuration";
  case Error::cancelled:
    return "cancelled";
  case Error::timeout:
    return "timeout";
  case Error::network:
    return "network";
  case Error::database:
    return "database";
  case Error::schema:
    return "schema";
  case Error::invalid_data:
    return "invalid_data";
  case Error::conflict:
    return "conflict";
  }
  return "unknown";
}
Time now() { return time_point_cast<milliseconds>(system_clock::now()); }
namespace {
template<class T> concept Text = std::same_as<T, std::string> || std::same_as<T, std::pmr::string>;
template<Text Buffer> void digits(Buffer &out, int value, unsigned width) {
  std::array<char, 16> buffer{};
  const auto [end, error] =
      std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (error != std::errc{})
    throw std::logic_error("timestamp out of range");
  const auto size = static_cast<unsigned>(end - buffer.data());
  if (size > width)
    throw std::logic_error("timestamp out of range");
  out.append(width - size, '0');
  out.append(buffer.data(), size);
}
template<Text Buffer> void append_date(Buffer& out, Time at) {
  const year_month_day day{floor<days>(at)};
  const int y = int(day.year());
  if (y < 0 || y > 9999) throw std::logic_error("timestamp out of range");
  digits(out, y, 4); out += '-';
  digits(out, static_cast<int>(unsigned(day.month())), 2); out += '-';
  digits(out, static_cast<int>(unsigned(day.day())), 2);
}
template<Text Buffer> void append_iso(Buffer& out, Time at) {
  append_date(out, at);
  const hh_mm_ss time{at - floor<days>(at)};
  out += 'T'; digits(out, static_cast<int>(time.hours().count()), 2);
  out += ':'; digits(out, static_cast<int>(time.minutes().count()), 2);
  out += ':'; digits(out, static_cast<int>(time.seconds().count()), 2);
  if (time.subseconds().count() != 0) {
    out += '.'; digits(out, static_cast<int>(time.subseconds().count()), 3);
  }
  out += 'Z';
}
template <class T>
  requires(std::integral<T> || std::floating_point<T>)
void number(std::pmr::string &out, T value) {
  std::array<char, 64> buffer{};
  const auto [end, error] =
      std::to_chars(buffer.data(), buffer.data() + buffer.size(), value);
  if (error != std::errc{})
    throw std::logic_error("invalid numeric metric");
  out.append(buffer.data(), static_cast<std::size_t>(end - buffer.data()));
}
void quoted(std::pmr::string &out, Time at, bool include_time = true) {
  // Generate timestamps directly into the arena without per-bucket strings.
  out += '"';
  if (include_time) append_iso(out, at); else append_date(out, at);
  out += '"';
}
void series(std::pmr::string &out, const History &history, std::size_t hours) {
  out += "{\"bucket\":\"hour\",\"series\":[";
  for (auto i = history.counts.size() - hours; i < history.counts.size(); ++i) {
    if (i != history.counts.size() - hours)
      out += ',';
    out += "{\"bucketStart\":";
    quoted(out, history.until - std::chrono::hours(history.counts.size() - i));
    out += ",\"records\":";
    number(out, history.counts[i]);
    out += '}';
  }
  out += "]}";
}
} // namespace
std::string date(Time at) {
  std::string result;
  append_date(result, at);
  return result;
}
std::string iso(Time at) {
  std::string result;
  result.reserve(24);
  append_iso(result, at);
  return result;
}
Result<Time> parse_time(std::string_view text) {
  if (text.size() < 20 || text.size() > 30 || text[4] != '-' ||
      text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':' ||
      text.back() != 'Z')
    return std::unexpected(Error::invalid_data);
  auto part = [&](std::size_t begin, std::size_t size) -> int {
    int value{};
    auto first = text.data() + begin;
    const auto [end, error] = std::from_chars(first, first + size, value);
    return error == std::errc{} && end == first + size ? value : -1;
  };
  const int y = part(0, 4);
  if (y < 0)
    return std::unexpected(Error::invalid_data);
  const year_month_day day{year{y},
                           month{static_cast<unsigned>(part(5, 2))},
                           std::chrono::day{static_cast<unsigned>(part(8, 2))}};
  const int h = part(11, 2), m = part(14, 2), s = part(17, 2);
  if (!day.ok() || h < 0 || h > 23 || m < 0 || m > 59 || s < 0 || s > 59)
    return std::unexpected(Error::invalid_data);
  int fraction{};
  if (text.size() != 20) {
    if (text[19] != '.' || text.size() < 22)
      return std::unexpected(Error::invalid_data);
    const auto count = text.size() - 21;
    for (std::size_t i = 0; i < count; ++i) {
      const auto digit = text[20 + i];
      if (digit < '0' || digit > '9')
        return std::unexpected(Error::invalid_data);
      if (i < 3)
        fraction = fraction * 10 + digit - '0';
    }
    for (auto i = count; i < 3; ++i)
      fraction *= 10;
  }
  return time_point_cast<milliseconds>(sys_days{day} + hours{h} + minutes{m} +
                                       seconds{s}) +
         milliseconds{fraction};
}
Result<std::string> ordering_stamp(std::string_view text) {
  if (!parse_time(text)) return std::unexpected(Error::invalid_data);
  // Preserve all nine fractional digits when fencing legacy ISO_INSTANT
  // snapshots; reducing the old timestamp to milliseconds could regress it.
  std::string result{text.substr(0, 19)};
  if (text.size() > 20) result.append(text.substr(20, text.size() - 21));
  result.resize(28, '0');
  return result;
}
Result<std::int64_t> parse_count(std::string_view text) {
  if (text.empty()) return std::unexpected(Error::invalid_data);
  std::int64_t value{};
  const auto [end, error] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size() || value < 0)
    return std::unexpected(Error::invalid_data);
  return value;
}
Result<History> fill_hours(std::span<const HourPoint> rows, Time at) {
  History history{time_point_cast<milliseconds>(floor<hours>(at)), {}};
  std::array<bool, 168> seen{};
  for (const auto &row : rows) {
    const auto offset =
        duration_cast<hours>(row.start - (history.until - hours{168})).count();
    if (row.records < 0 || row.start != floor<hours>(row.start) || offset < 0 ||
        offset >= 168)
      return std::unexpected(Error::invalid_data);
    const auto index = static_cast<std::size_t>(offset);
    if (seen[index])
      return std::unexpected(Error::invalid_data);
    seen[index] = true;
    history.counts[index] = row.records;
  }
  return history;
}
std::pmr::string serialize(const State &state, Time at,
                           std::pmr::memory_resource &arena) {
  std::pmr::string out{&arena};
  out.reserve(16384);
  out += "{\"asOf\":";
  quoted(out, at);
  out += ",\"peaksComputedAt\":";
  const auto &peaks = state.aggregates;
  if (peaks)
    quoted(out, peaks->at);
  else
    out += "null";
  out += ",\"peakRecordsDay\":";
  if (peaks && peaks->value.day)
    number(out, peaks->value.day->records);
  else
    out += "null";
  out += ",\"peakRecordsDayDate\":";
  if (peaks && peaks->value.day)
    quoted(out, peaks->value.day->day, false);
  else
    out += "null";
  out += ",\"peakRecordsWeek\":";
  if (peaks && peaks->value.week)
    number(out, peaks->value.week->records);
  else
    out += "null";
  out += ",\"peakRecordsWeekStart\":";
  if (peaks && peaks->value.week)
    quoted(out, peaks->value.week->start, false);
  else
    out += "null";
  out += ",\"peakRecordsWeekEnd\":";
  if (peaks && peaks->value.week)
    quoted(out, peaks->value.week->end, false);
  else
    out += "null";
  out += ",\"lifetimeTotals\":";
  if (peaks) {
    out += "{\"recordsTotal\":";
    number(out, peaks->value.records_total);
    out += ",\"daysCounted\":";
    number(out, peaks->value.days_counted);
    out += ",\"computedAt\":";
    quoted(out, peaks->at);
    out += '}';
  } else
    out += "null";
  out += ",\"liveStrip\":";
  const auto &live = state.live;
  if (live && live->value && live->at <= at + seconds{5} && at - live->at <= seconds{60}) {
    const auto &value = *live->value;
    out += "{\"ingestProcessedRatePerSec\":";
    number(out, value.rate);
    out += ",\"pendingLedgerCount\":";
    number(out, value.pending);
    out += ",\"brokerLagCount\":";
    if (value.broker_lag)
      number(out, *value.broker_lag);
    else
      out += "null";
    out += ",\"lastIngestSuccessAt\":";
    if (value.last_success)
      quoted(out, *value.last_success);
    else
      out += "null";
    out += ",\"backpressureActive\":";
    out += value.backpressure ? "true}" : "false}";
  } else
    out += "null";
  // A failed refresh must not erase measured history at the next UTC hour.
  // Bucket timestamps identify the original window without inventing new data.
  const bool measured =
      state.history && state.history->value.until <= floor<hours>(at);
  out += ",\"throughput24h\":";
  if (measured)
    series(out, state.history->value, 24);
  else
    out += "null";
  out += ",\"throughput7d\":";
  if (measured)
    series(out, state.history->value, 168);
  else
    out += "null";
  out += '}';
  return out;
}
std::array<std::string, 3> object_paths(Time at) {
  const auto d = date(at);
  const auto stamp = iso(time_point_cast<milliseconds>(floor<hours>(at)));
  return {"latest.json",
          "history/" + d.substr(0, 4) + "/" + d.substr(5, 2) + "/" +
              d.substr(8, 2) + "/stats-" + d.substr(0, 4) + d.substr(5, 2) +
              d.substr(8, 2) + "T" + stamp.substr(11, 2) + ".json",
          "daily/" + d.substr(0, 4) + "/" + d.substr(5, 2) + "/stats-" + d +
              ".json"};
}
} // namespace metrics
