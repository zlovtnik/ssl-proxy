#include "metrics/adapters.hpp"
#include "metrics/queue.hpp"
#include <atomic>
#include <iostream>
#include <limits>
#include <map>
#include <simdjson.h>
#include <thread>
#include <vector>

namespace {
using namespace metrics;
using namespace std::chrono;
void require(bool condition, std::string_view message) {
  if (!condition)
    throw std::runtime_error(std::string{message});
}
Time instant(std::string_view text) {
  const auto value = parse_time(text);
  require(value.has_value(), "test timestamp");
  return *value;
}
simdjson::dom::element decode(simdjson::dom::parser &parser, const State &state,
                              Time at) {
  std::pmr::monotonic_buffer_resource arena;
  const auto json = serialize(state, at, arena);
  return parser.parse(json.data(), json.size());
}
void timestamps() {
  for (const auto text : {"2026-10-08T12:30:00Z", "1970-01-01T00:00:00Z",
                          "2024-02-29T23:59:59.123Z"})
    require(iso(instant(text)) == text, "UTC roundtrip");
  require(iso(instant("2026-10-08T12:30:00.123456789Z")) ==
              "2026-10-08T12:30:00.123Z",
          "fraction truncation");
  for (const auto bad :
       {"2026-02-29T12:00:00Z", "2026-10-08T24:00:00Z", "2026-10-08T00:00:00.Z",
        "2026-10-08T00:00:00+00:00", "abcd-10-08T00:00:00Z",
        "-001-10-08T00:00:00Z", "20a6-10-08T00:00:00Z"})
    require(!parse_time(bad), "reject invalid timestamp");
  require(!parse_count({}) && !parse_count("-1") && !parse_count("9223372036854775808") &&
              !parse_count("1junk"),
          "strict counts");
  require(ordering_stamp("2026-10-08T12:30:00.900000001Z").value() >
          ordering_stamp("2026-10-08T12:30:00.900Z").value(), "nanosecond publication fence");
}
void history_and_contract() {
  const auto at = instant("2026-10-08T12:30:00Z");
  const std::array rows{HourPoint{instant("2026-10-08T11:00:00Z"), 7}};
  auto history = fill_hours(rows, at);
  require(history.has_value() && history->counts.back() == 7 &&
              history->counts.front() == 0,
          "dense hours");
  const std::array duplicates{rows[0], rows[0]};
  require(!fill_hours(duplicates, at), "duplicate bucket is invalid");
  const std::array current{HourPoint{instant("2026-10-08T12:00:00Z"), 1}};
  require(!fill_hours(current, at), "exclusive upper bound");
  State state;
  simdjson::dom::parser parser;
  auto cold = decode(parser, state, at);
  require(cold["peakRecordsDay"].is_null() && cold["lifetimeTotals"].is_null(),
          "unknown is null");
  require(cold["throughput7d"].is_null() && cold["liveStrip"].is_null(),
          "cold history and live");
  state.aggregates =
      Measured<Aggregates>{Aggregates{std::nullopt, std::nullopt, 0, 0}, at};
  state.history = Measured<History>{*history, at};
  auto measured = decode(parser, state, at);
  require(std::int64_t(measured["lifetimeTotals"]["recordsTotal"]) == 0,
          "measured empty is zero");
  require(measured["peakRecordsDay"].is_null(), "measured empty peak is null");
  auto day = measured["throughput24h"]["series"].get_array().value();
  auto week = measured["throughput7d"]["series"].get_array().value();
  require(day.size() == 24 && week.size() == 168, "history contract lengths");
  require(std::string_view(week.at(167)["bucketStart"]) ==
              "2026-10-08T11:00:00Z",
          "complete hour");
  require(std::int64_t(week.at(167)["records"]) == 7, "numeric count");
  auto stale = decode(parser, state, at + hours{1});
  require(stale["throughput24h"]["series"].get_array().value().size() == 24 &&
              stale["throughput7d"]["series"].get_array().value().size() == 168,
          "last-good history survives hour rollover");
  require(std::string_view(stale["throughput7d"]["series"].at(167)["bucketStart"]) ==
              "2026-10-08T11:00:00Z" &&
              std::int64_t(stale["throughput7d"]["series"].at(167)["records"]) == 7,
          "historical window retains original buckets and counts");
  require(std::string_view(stale["lifetimeTotals"]["computedAt"]) == iso(at),
          "last-good timestamp retained");
  const auto paths = object_paths(at);
  require(paths[1] == "history/2026/10/08/stats-20261008T12.json" &&
              paths[2] == "daily/2026/10/stats-2026-10-08.json",
          "unchanged history keys");
  state.history->value.counts.fill(std::numeric_limits<std::int64_t>::max());
  state.aggregates->value.records_total = std::numeric_limits<std::int64_t>::max();
  state.live = Measured<std::optional<Live>>{Live{std::numeric_limits<double>::max(),
      std::numeric_limits<std::int64_t>::max(), at, true}, at};
  std::array<std::byte, 32768> buffer{};
  std::pmr::monotonic_buffer_resource arena{buffer.data(), buffer.size(), std::pmr::null_memory_resource()};
  const auto largest = serialize(state, at, arena);
  require(largest.size() < 16384, "maximum numeric snapshot fits fixed arena");
}
void live_contract() {
  const auto at = instant("2026-10-08T12:30:00Z");
  constexpr std::string_view payload =
      R"({"asOf":"2026-10-08T12:30:00Z","liveStrip":{"ingestProcessedRatePerSec":2.5,"pendingLedgerCount":9,"lastIngestSuccessAt":null,"backpressureActive":false}})";
  const auto live = parse_live(payload, at);
  require(live.has_value() && live->value && live->value->pending == 9,
          "live decoder");
  require(!live->value->broker_lag, "older bridge keeps broker lag unknown");
  const auto broker = parse_live(
      R"({"asOf":"2026-10-08T12:30:00Z","liveStrip":{"ingestProcessedRatePerSec":2.5,"pendingLedgerCount":0,"brokerLagCount":16300000,"lastIngestSuccessAt":null,"backpressureActive":false}})", at);
  require(broker && broker->value && broker->value->broker_lag == 16300000,
          "broker backlog independent from empty ledger");
  for (const auto count : {"null", "0", "-1", "1.5", "\"9\""}) {
    const auto json = std::string{R"({"asOf":"2026-10-08T12:30:00Z","liveStrip":{"ingestProcessedRatePerSec":2.5,"pendingLedgerCount":0,"lastIngestSuccessAt":null,"backpressureActive":false,"brokerLagCount":)"} + count + "}}";
    require(parse_live(json, at).has_value() == (std::string_view{count} == "null" || std::string_view{count} == "0"),
            "optional broker lag remains strict");
  }
  require(parse_live(payload, at + seconds{60}).has_value(), "decoder accepts staleness boundary");
  require(!parse_live(payload, at + seconds{60} + milliseconds{1}), "decoder rejects stale sample");
  require(parse_live(payload, at - seconds{1}).has_value(), "decoder tolerates future clock offset");
  require(parse_live(payload, at - seconds{5}).has_value(), "decoder accepts future offset boundary");
  require(!parse_live(payload, at - seconds{5} - milliseconds{1}), "decoder rejects excessive future offset");
  require(!parse_live(R"({"asOf":"2026-10-08T12:30:00Z","liveStrip":{}})", at),
          "required live fields strict");
  require(
      !parse_live(
          R"({"asOf":"2026-10-08T12:30:00Z","liveStrip":{"ingestProcessedRatePerSec":-1,"pendingLedgerCount":9,"lastIngestSuccessAt":null,"backpressureActive":false}})",
          at),
      "negative rate rejected");
  State state;
  state.live = *broker;
  simdjson::dom::parser broker_parser;
  require(std::int64_t(decode(broker_parser, state, at)["liveStrip"]["brokerLagCount"]) == 16300000,
          "snapshot preserves broker backlog");
  state.live = *live;
  simdjson::dom::parser parser;
  require(!decode(parser, state, at + seconds{60})["liveStrip"].is_null(),
          "fresh boundary included");
  require(decode(parser, state, at + seconds{60} + milliseconds{1})["liveStrip"].is_null(),
          "live cache expiration");
  require(!decode(parser, state, at - seconds{1})["liveStrip"].is_null(), "serializer tolerates future clock offset");
  require(!decode(parser, state, at - seconds{5})["liveStrip"].is_null(), "serializer accepts future offset boundary");
  require(decode(parser, state, at - seconds{5} - milliseconds{1})["liveStrip"].is_null(), "serializer rejects excessive future offset");
  const auto missing =
      parse_live(R"({"asOf":"2026-10-08T12:30:00Z","liveStrip":null})", at);
  require(missing.has_value() && !missing->value,
          "unavailable reading preserved");
}
void cache_ordering() {
  Cache cache;
  const auto at = instant("2026-10-08T12:30:00Z");
  std::vector<std::jthread> writers;
  for (int i = 0; i < 8; ++i)
    writers.emplace_back([&, i] {
      for (int j = 0; j < 1000; ++j)
        cache.update(
            &State::aggregates,
            Measured<Aggregates>{Aggregates{std::nullopt, std::nullopt, i, 1},
                                 at + seconds{i}});
    });
  writers.clear();
  const auto value = cache.read();
  require(value.aggregates && value.aggregates->value.records_total == 7 &&
              value.aggregates->at == at + seconds{7},
          "out-of-order cache cannot regress");
}
void queue_and_shutdown() {
  JobQueue queue;
  require(queue.offer(Job::peaks) && queue.offer(Job::history) &&
              queue.offer(Job::live),
          "all three kinds accepted");
  for (int i = 0; i < 100000; ++i)
    require(!queue.offer(Job::peaks), "timer burst bounded");
  const auto job = queue.take({});
  require(job == Job::peaks && !queue.offer(Job::peaks),
          "active work coalesces");
  queue.complete(*job);
  require(queue.offer(Job::peaks), "completion releases kind");
  JobQueue empty;
  std::atomic<bool> cancelled{};
  std::jthread waiter{
      [&](std::stop_token stop) { cancelled.store(!empty.take(stop)); }};
  waiter.request_stop();
  waiter.join();
  require(cancelled.load(), "blocked take cancels");
  queue.close();
  require(!queue.offer(Job::live) && !queue.take({}),
          "closed queue never blocks");
  JobQueue concurrent;
  std::atomic<int> accepted{}, consumed{};
  std::jthread consumer{[&](std::stop_token stop) {
    while (auto next = concurrent.take(stop)) {
      ++consumed;
      concurrent.complete(*next);
    }
  }};
  std::vector<std::jthread> producers;
  for (int i = 0; i < 6; ++i)
    producers.emplace_back([&, i] {
      for (int j = 0; j < 10000; ++j)
        if (concurrent.offer(static_cast<Job>(i % 3)))
          ++accepted;
    });
  producers.clear();
  const auto limit = steady_clock::now() + seconds{2};
  while (consumed.load() != accepted.load() && steady_clock::now() < limit)
    std::this_thread::yield();
  concurrent.close();
  consumer.join();
  require(accepted.load() == consumed.load(),
          "concurrent offered work consumed once");
}
void configuration() {
  std::map<std::string, std::string> values{
      {"POSTGRES_PASSWORD", "test"},
      {"MINIO_ACCESS_KEY_ID", "test"},
      {"MINIO_SECRET_ACCESS_KEY", "test"}};
  auto env = [&](std::string_view key) -> std::optional<std::string> {
    const auto found = values.find(std::string{key});
    return found == values.end() ? std::nullopt
                                 : std::optional<std::string>{found->second};
  };
  require(read_config(env).has_value(), "valid production defaults");
  values["STATS_WORKER_COUNT"] = "0";
  require(!read_config(env), "zero workers rejected");
  values["STATS_WORKER_COUNT"] = "9";
  require(!read_config(env), "worker cap enforced");
  values.erase("STATS_WORKER_COUNT");
  values["POSTGRES_SSL_MODE"] = "disable";
  require(!read_config(env), "insecure production TLS rejected");
  values["STATS_LOCAL_DEV"] = "true";
  require(read_config(env).has_value(), "explicit local bypass");
  values["REDIS_ADDR"] = "rediss://host:6379";
  require(!read_config(env), "TLS never downgraded");
  values.erase("REDIS_ADDR");
  values["MINIO_STATS_PREFIX"] = "../escape";
  require(!read_config(env), "object prefix validated");
}
} // namespace
int main() {
  try {
    timestamps();
    history_and_contract();
    live_contract();
    cache_ordering();
    queue_and_shutdown();
    configuration();
    std::cout << "6 test groups passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
