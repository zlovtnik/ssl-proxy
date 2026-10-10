#include "metrics/adapters.hpp"

#include <curl/curl.h>
#include <hiredis/hiredis.h>
#include <libpq-fe.h>
#include <simdjson.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstring>
#include <netdb.h>
#include <poll.h>
#include <stdexcept>
#include <vector>

namespace metrics {
using namespace std::chrono;
namespace {
template <class T, auto Free> struct Deleter {
  void operator()(T *value) const noexcept { Free(value); }
};
using Connection = std::unique_ptr<PGconn, Deleter<PGconn, PQfinish>>;
using Rows = std::unique_ptr<PGresult, Deleter<PGresult, PQclear>>;
using Easy = std::unique_ptr<CURL, Deleter<CURL, curl_easy_cleanup>>;
using Headers =
    std::unique_ptr<curl_slist, Deleter<curl_slist, curl_slist_free_all>>;
using RedisConnection =
    std::unique_ptr<redisContext, Deleter<redisContext, redisFree>>;
struct ReplyDeleter {
  void operator()(redisReply *reply) const noexcept { freeReplyObject(reply); }
};
using Reply = std::unique_ptr<redisReply, ReplyDeleter>;
Result<void> active(Deadline deadline, std::stop_token stop) {
  if (stop.stop_requested())
    return std::unexpected(Error::cancelled);
  if (steady_clock::now() >= deadline)
    return std::unexpected(Error::timeout);
  return {};
}
Result<void> socket_ready(int socket, short events, Deadline deadline,
                          std::stop_token stop) {
  while (true) {
    if (auto check = active(deadline, stop); !check)
      return check;
    pollfd descriptor{socket, events, 0};
    const auto remaining =
        duration_cast<milliseconds>(deadline - steady_clock::now()).count();
    const auto polled =
        poll(&descriptor, 1,
             static_cast<int>(std::clamp<std::int64_t>(remaining, 1, 50)));
    if (polled < 0 && errno == EINTR)
      continue;
    if (polled < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)))
      return std::unexpected(Error::network);
    if (polled > 0 && (descriptor.revents & events))
      return {};
  }
}
std::string_view cell(const Rows &rows, int row, int column) {
  if (PQgetisnull(rows.get(), row, column))
    return {};
  return {PQgetvalue(rows.get(), row, column),
          static_cast<std::size_t>(PQgetlength(rows.get(), row, column))};
}
// One scan of the evidence timestamp column. Daily counts also supply weekly
// peaks and lifetime totals. Exact semantics match the former three queries.
constexpr auto aggregates_sql = R"SQL(
WITH daily AS MATERIALIZED (
  SELECT (first_seen_at AT TIME ZONE 'UTC')::date AS day, count(*) AS records
  FROM octopus_core.ingestion_evidence GROUP BY 1
), weekly AS (
  SELECT date_trunc('week', day::timestamp)::date AS week, sum(records)::bigint AS records
  FROM daily GROUP BY 1
), peak_day AS (SELECT day, records FROM daily ORDER BY records DESC, day ASC LIMIT 1),
peak_week AS (SELECT week, records FROM weekly ORDER BY records DESC, week ASC LIMIT 1)
SELECT d.records::text, to_char(d.day, 'YYYY-MM-DD'), w.records::text,
       to_char(w.week, 'YYYY-MM-DD'), to_char(w.week + 6, 'YYYY-MM-DD'),
       (SELECT coalesce(sum(records), 0)::bigint::text FROM daily),
       (SELECT count(*)::text FROM daily)
FROM (SELECT 1) seed LEFT JOIN peak_day d ON true LEFT JOIN peak_week w ON true
)SQL";
constexpr auto history_sql = R"SQL(
SELECT to_char(date_trunc('hour', first_seen_at AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:00:00Z'),
       count(*)::text
FROM octopus_core.ingestion_evidence
WHERE first_seen_at >= $1::timestamptz AND first_seen_at < $2::timestamptz
GROUP BY 1 ORDER BY 1
)SQL";
constexpr auto schema_sql = R"SQL(
SELECT ready AND required_version = $1 AND applied_version = $1
       AND required_checksum = $2 AND applied_checksum = $2
FROM octopus_core.schema_readiness WHERE domain = 'octopus_core'
)SQL";
} // namespace
struct Repository::Impl {
  const Config &config;
  Connection connection;
  explicit Impl(const Config &cfg) : config(cfg) {}
  Result<void> connect(Deadline deadline, std::stop_token stop) {
    if (connection && PQstatus(connection.get()) == CONNECTION_OK)
      return active(deadline, stop);
    connection.reset();
    if (auto check = active(deadline, stop); !check)
      return check;
    // libpq 'host' is the TLS identity; hostaddr is the network destination.
    // Resolve the configured destination only when a distinct identity is used.
    std::string address;
    if (!config.pg_server_name.empty() &&
        config.pg_host != config.pg_server_name) {
      addrinfo hints{};
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_family = AF_UNSPEC;
      addrinfo *raw = nullptr;
      if (getaddrinfo(config.pg_host.c_str(), nullptr, &hints, &raw) != 0)
        return std::unexpected(Error::network);
      const std::unique_ptr<addrinfo, Deleter<addrinfo, freeaddrinfo>> resolved{
          raw};
      std::array<char, NI_MAXHOST> host{};
      if (!resolved ||
          getnameinfo(resolved->ai_addr, resolved->ai_addrlen, host.data(),
                      host.size(), nullptr, 0, NI_NUMERICHOST) != 0)
        return std::unexpected(Error::network);
      address = host.data();
    }
    const auto &identity =
        config.pg_server_name.empty() ? config.pg_host : config.pg_server_name;
    const std::array<const char *, 11> keys{"host",
                                            "hostaddr",
                                            "port",
                                            "dbname",
                                            "user",
                                            "password",
                                            "sslmode",
                                            "sslrootcert",
                                            "application_name",
                                            "connect_timeout",
                                            nullptr};
    const std::string timeout = std::to_string(config.timeout);
    const std::array<const char *, 11> values{
        identity.c_str(),
        address.empty() ? nullptr : address.c_str(),
        config.pg_port.c_str(),
        config.pg_database.c_str(),
        config.pg_user.c_str(),
        config.pg_password.c_str(),
        config.pg_ssl_mode.c_str(),
        config.pg_ca.empty() ? nullptr : config.pg_ca.c_str(),
        "octopus-metrics",
        timeout.c_str(),
        nullptr};
    connection.reset(PQconnectStartParams(keys.data(), values.data(), 0));
    if (!connection)
      return std::unexpected(Error::network);
    while (true) {
      if (auto check = active(deadline, stop); !check) {
        connection.reset();
        return check;
      }
      const auto status = PQconnectPoll(connection.get());
      if (status == PGRES_POLLING_OK)
        break;
      if (status == PGRES_POLLING_FAILED) {
        connection.reset();
        return std::unexpected(Error::network);
      }
      auto check = socket_ready(
          PQsocket(connection.get()),
          status == PGRES_POLLING_WRITING ? POLLOUT : POLLIN, deadline, stop);
      if (!check) {
        connection.reset();
        return check;
      }
    }
    if (PQsetnonblocking(connection.get(), 1) != 0) {
      connection.reset();
      return std::unexpected(Error::network);
    }
    return {};
  }
  Result<Rows> query(const char *sql, std::span<const std::string> params,
                     Deadline deadline, std::stop_token stop) {
    if (auto check = active(deadline, stop); !check)
      return std::unexpected(check.error());
    if (!connection || PQstatus(connection.get()) != CONNECTION_OK)
      return std::unexpected(Error::network);
    std::vector<const char *> values;
    values.reserve(params.size());
    for (const auto &param : params)
      values.push_back(param.c_str());
    if (PQsendQueryParams(connection.get(), sql,
                          static_cast<int>(values.size()), nullptr,
                          values.data(), nullptr, nullptr, 0) != 1) {
      connection.reset();
      return std::unexpected(Error::network);
    }
    while (true) {
      const auto flushed = PQflush(connection.get());
      if (flushed == 0)
        break;
      if (flushed < 0) {
        connection.reset();
        return std::unexpected(Error::network);
      }
      if (auto check =
              socket_ready(PQsocket(connection.get()), POLLOUT, deadline, stop);
          !check) {
        connection.reset();
        return std::unexpected(check.error());
      }
    }
    Rows result;
    while (true) {
      if (auto check = active(deadline, stop); !check) {
        connection.reset();
        return std::unexpected(check.error());
      }
      if (PQconsumeInput(connection.get()) != 1) {
        connection.reset();
        return std::unexpected(Error::network);
      }
      if (PQisBusy(connection.get())) {
        if (auto check = socket_ready(PQsocket(connection.get()), POLLIN,
                                      deadline, stop);
            !check) {
          connection.reset();
          return std::unexpected(check.error());
        }
        continue;
      }
      Rows next{PQgetResult(connection.get())};
      if (!next)
        break;
      const auto status = PQresultStatus(next.get());
      if (status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK) {
        const auto state = PQresultErrorField(next.get(), PG_DIAG_SQLSTATE);
        const auto error = state && std::string_view{state} == "57014"
                               ? Error::timeout
                               : Error::database;
        connection.reset();
        return std::unexpected(error);
      }
      if (result) {
        connection.reset();
        return std::unexpected(Error::invalid_data);
      }
      result = std::move(next);
    }
    if (!result)
      return std::unexpected(Error::database);
    return result;
  }
  Result<Rows> read(const char *sql, std::span<const std::string> params,
                    Deadline deadline, std::stop_token stop) {
    if (auto check = connect(deadline, stop); !check)
      return std::unexpected(check.error());
    auto begin = query("BEGIN READ ONLY", {}, deadline, stop);
    if (!begin)
      return std::unexpected(begin.error());
    const std::array timeout{std::to_string(config.timeout * 1000)};
    auto limit = query("SELECT set_config('statement_timeout', $1, true)",
                       timeout, deadline, stop);
    if (!limit) {
      connection.reset();
      return std::unexpected(limit.error());
    }
    const std::array schema{std::string{METRICS_MANIFEST_VERSION},
                            std::string{METRICS_MANIFEST_SHA}};
    auto check = query(schema_sql, schema, deadline, stop);
    if (!check || PQntuples(check->get()) != 1 || cell(*check, 0, 0) != "t") {
      connection.reset();
      return std::unexpected(check ? Error::schema : check.error());
    }
    auto result = query(sql, params, deadline, stop);
    if (!result) {
      connection.reset();
      return std::unexpected(result.error());
    }
    auto commit = query("COMMIT", {}, deadline, stop);
    if (!commit) {
      connection.reset();
      return std::unexpected(commit.error());
    }
    return result;
  }
};
Repository::Repository(const Config &config)
    : impl_(std::make_unique<Impl>(config)) {}
Repository::~Repository() = default;
Result<void> Repository::verify(Deadline deadline, std::stop_token stop) {
  const auto rows = impl_->read("SELECT 1", {}, deadline, stop);
  if (!rows)
    return std::unexpected(rows.error());
  return {};
}
Result<Aggregates> Repository::aggregates(Deadline deadline,
                                          std::stop_token stop) {
  auto rows = impl_->read(aggregates_sql, {}, deadline, stop);
  if (!rows)
    return std::unexpected(rows.error());
  if (PQntuples(rows->get()) != 1 || PQnfields(rows->get()) != 7)
    return std::unexpected(Error::invalid_data);
  Aggregates aggregate;
  auto total = parse_count(cell(*rows, 0, 5)),
       days = parse_count(cell(*rows, 0, 6));
  if (!total || !days)
    return std::unexpected(Error::invalid_data);
  aggregate.records_total = *total;
  aggregate.days_counted = *days;
  if (!PQgetisnull(rows->get(), 0, 0)) {
    auto count = parse_count(cell(*rows, 0, 0));
    auto day = parse_time(std::string{cell(*rows, 0, 1)} + "T00:00:00Z");
    if (!count || !day)
      return std::unexpected(Error::invalid_data);
    aggregate.day = DayPeak{*count, *day};
  }
  if (!PQgetisnull(rows->get(), 0, 2)) {
    auto count = parse_count(cell(*rows, 0, 2));
    auto start = parse_time(std::string{cell(*rows, 0, 3)} + "T00:00:00Z");
    auto end = parse_time(std::string{cell(*rows, 0, 4)} + "T00:00:00Z");
    if (!count || !start || !end)
      return std::unexpected(Error::invalid_data);
    aggregate.week = WeekPeak{*count, *start, *end};
  }
  return aggregate;
}
Result<History> Repository::history(Time at, Deadline deadline,
                                    std::stop_token stop) {
  const auto until = time_point_cast<milliseconds>(floor<hours>(at));
  const std::array params{iso(until - hours{168}), iso(until)};
  auto rows = impl_->read(history_sql, params, deadline, stop);
  if (!rows)
    return std::unexpected(rows.error());
  const auto count = PQntuples(rows->get());
  if (count > 168 || PQnfields(rows->get()) != 2)
    return std::unexpected(Error::invalid_data);
  std::array<HourPoint, 168> points{};
  for (int i = 0; i < count; ++i) {
    auto start = parse_time(cell(*rows, i, 0));
    auto records = parse_count(cell(*rows, i, 1));
    if (!start || !records)
      return std::unexpected(Error::invalid_data);
    points[static_cast<std::size_t>(i)] = HourPoint{*start, *records};
  }
  return fill_hours(std::span{points}.first(static_cast<std::size_t>(count)),
                    at);
}

CurlRuntime::CurlRuntime() {
  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
    throw std::runtime_error("curl initialization");
}
CurlRuntime::~CurlRuntime() { curl_global_cleanup(); }
namespace {
struct Response {
  long status{};
  std::string body;
  std::string etag;
};
struct Transfer {
  Response response;
  Deadline deadline;
  std::stop_token stop;
};
struct ClearOptions {
  Easy& handle;
  ~ClearOptions() { curl_easy_reset(handle.get()); }
};
std::size_t body_callback(char *data, std::size_t size, std::size_t count,
                          void *context) noexcept {
  auto &transfer = *static_cast<Transfer *>(context);
  if (size != 0 && count > 65536 / size)
    return 0;
  const auto bytes = size * count;
  if (bytes > 65536 - transfer.response.body.size())
    return 0;
  try {
    transfer.response.body.append(data, bytes);
  } catch (...) {
    return 0;
  }
  return bytes;
}
std::size_t header_callback(char *data, std::size_t size, std::size_t count,
                            void *context) noexcept {
  if (size != 0 && count > 8192 / size)
    return 0;
  const auto bytes = size * count;
  const std::string_view header{data, bytes};
  try {
    if (header.starts_with("HTTP/"))
      static_cast<Transfer *>(context)->response.etag.clear();
    if (header.size() >= 5 &&
        (header.substr(0, 5) == "ETag:" || header.substr(0, 5) == "etag:")) {
      auto value = header.substr(5);
      while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
      while (!value.empty() && (value.back() == '\r' || value.back() == '\n' ||
                                value.back() == ' '))
        value.remove_suffix(1);
      if (value.find_first_of("\r\n") != std::string_view::npos)
        return 0;
      static_cast<Transfer *>(context)->response.etag = value;
    }
  } catch (...) {
    return 0;
  }
  return bytes;
}
int progress_callback(void *context, curl_off_t, curl_off_t, curl_off_t,
                      curl_off_t) noexcept {
  const auto &transfer = *static_cast<Transfer *>(context);
  return transfer.stop.stop_requested() ||
                 steady_clock::now() >= transfer.deadline
             ? 1
             : 0;
}
Result<std::string> json_timestamp(std::string_view json) {
  try {
    simdjson::ondemand::parser parser;
    simdjson::padded_string input{json};
    auto document = parser.iterate(input);
    std::string_view stamp = document["asOf"].get_string();
    return ordering_stamp(stamp);
  } catch (const simdjson::simdjson_error &) {
    return std::unexpected(Error::invalid_data);
  }
}
} // namespace
struct Http::Impl {
  const Config &config;
  Easy easy{curl_easy_init()};
  explicit Impl(const Config &cfg) : config(cfg) {
    if (!easy)
      throw std::bad_alloc{};
  }
  Result<Response> request(const std::string &url, bool signed_request,
                           std::string_view body,
                           const std::optional<std::string> &condition,
                           Deadline deadline, std::stop_token stop) {
    if (auto check = active(deadline, stop); !check)
      return std::unexpected(check.error());
    curl_easy_reset(easy.get());
    Transfer transfer{{}, deadline, stop};
    Headers headers;
    const ClearOptions clear_options{easy};
    transfer.response.body.reserve(16384);
    const auto timeout = std::max<std::int64_t>(
        1, duration_cast<milliseconds>(deadline - steady_clock::now()).count());
    auto set = [&](CURLoption option, auto value) {
      if (curl_easy_setopt(easy.get(), option, value) != CURLE_OK)
        throw std::runtime_error("curl option");
    };
    set(CURLOPT_URL, url.c_str());
    set(CURLOPT_PROTOCOLS_STR, "http,https");
    set(CURLOPT_NOSIGNAL, 1L);
    set(CURLOPT_TIMEOUT_MS, static_cast<long>(timeout));
    set(CURLOPT_CONNECTTIMEOUT_MS,
        static_cast<long>(std::min<std::int64_t>(timeout, 5000)));
    set(CURLOPT_WRITEFUNCTION, &body_callback);
    set(CURLOPT_WRITEDATA, &transfer);
    set(CURLOPT_HEADERFUNCTION, &header_callback);
    set(CURLOPT_HEADERDATA, &transfer);
    set(CURLOPT_XFERINFOFUNCTION, &progress_callback);
    set(CURLOPT_XFERINFODATA, &transfer);
    set(CURLOPT_NOPROGRESS, 0L);
    // Do not inherit ambient proxy credentials or forward S3 credentials
    // through a redirect.
    set(CURLOPT_PROXY, "");
    set(CURLOPT_FOLLOWLOCATION, 0L);
    if (signed_request) {
      const auto signature = "aws:amz:" + config.minio_region + ":s3";
      set(CURLOPT_AWS_SIGV4, signature.c_str());
      set(CURLOPT_USERNAME, config.minio_access.c_str());
      set(CURLOPT_PASSWORD, config.minio_secret.c_str());
    }
    if (condition) {
      const auto line = condition->empty() ? std::string{"If-None-Match: *"}
                                           : "If-Match: " + *condition;
      headers.reset(curl_slist_append(nullptr, line.c_str()));
      if (!headers)
        throw std::bad_alloc{};
      auto next =
          curl_slist_append(headers.get(), "Content-Type: application/json");
      if (!next)
        throw std::bad_alloc{};
      headers.release();
      headers.reset(next);
      set(CURLOPT_HTTPHEADER, headers.get());
      set(CURLOPT_CUSTOMREQUEST, "PUT");
      set(CURLOPT_POSTFIELDS, body.data());
      set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    }
    const auto performed = curl_easy_perform(easy.get());
    if (performed != CURLE_OK) {
      if (auto check = active(deadline, stop); !check)
        return std::unexpected(check.error());
      return std::unexpected(performed == CURLE_OPERATION_TIMEDOUT
                                 ? Error::timeout
                                 : Error::network);
    }
    if (curl_easy_getinfo(easy.get(), CURLINFO_RESPONSE_CODE,
                          &transfer.response.status) != CURLE_OK)
      return std::unexpected(Error::network);
    return std::move(transfer.response);
  }
};
Http::Http(const Config &config) : impl_(std::make_unique<Impl>(config)) {}
Http::~Http() = default;
Result<Measured<std::optional<Live>>> parse_live(std::string_view json,
                                                 Time received_at) {
  if (json.size() > 65536)
    return std::unexpected(Error::invalid_data);
  try {
    simdjson::ondemand::parser parser;
    simdjson::padded_string input{json};
    auto document = parser.iterate(input);
    std::string_view stamp = document["asOf"].get_string();
    auto at = parse_time(stamp);
    if (!at || *at > received_at + seconds{5} || received_at - *at > seconds{60})
      return std::unexpected(Error::invalid_data);
    auto strip = document["liveStrip"];
    if (strip.is_null())
      return Measured<std::optional<Live>>{std::nullopt, *at};
    Live value;
    value.rate = strip["ingestProcessedRatePerSec"].get_double();
    value.pending = strip["pendingLedgerCount"].get_int64();
    auto success = strip["lastIngestSuccessAt"];
    if (!success.is_null()) {
      std::string_view timestamp = success.get_string();
      auto last = parse_time(timestamp);
      if (!last || *last > *at)
        return std::unexpected(Error::invalid_data);
      value.last_success = *last;
    }
    value.backpressure = strip["backpressureActive"].get_bool();
    auto lag = strip["brokerLagCount"];
    if (lag.error() != simdjson::NO_SUCH_FIELD) {
      if (lag.error())
        return std::unexpected(Error::invalid_data);
      if (!lag.is_null()) {
        value.broker_lag = lag.get_int64();
        if (*value.broker_lag < 0)
          return std::unexpected(Error::invalid_data);
      }
    }
    if (!std::isfinite(value.rate) || value.rate < 0 || value.pending < 0)
      return std::unexpected(Error::invalid_data);
    return Measured<std::optional<Live>>{value, *at};
  } catch (const simdjson::simdjson_error &) {
    return std::unexpected(Error::invalid_data);
  }
}
Result<Measured<std::optional<Live>>> Http::live(Deadline deadline,
                                                 std::stop_token stop) {
  const auto response = impl_->request(impl_->config.live_url, false, {},
                                       std::nullopt, deadline, stop);
  if (!response)
    return std::unexpected(response.error());
  if (response->status != 200)
    return std::unexpected(Error::network);
  return parse_live(response->body, now());
}
Result<void> Http::object(std::string_view path, std::string_view json, Time at,
                          Deadline deadline, std::stop_token stop) {
  const auto &config = impl_->config;
  const std::string url = config.minio_endpoint + "/" + config.minio_bucket +
                          "/" + config.minio_prefix + std::string{path};
  const auto incoming = ordering_stamp(iso(at));
  if (!incoming) return std::unexpected(incoming.error());
  // Store-side compare-and-swap is the fence. Process-local ordering or a DB
  // lease cannot protect an external object after a stalled publisher resumes.
  for (int attempt = 0; attempt < 3; ++attempt) {
    auto existing = impl_->request(url, true, {}, std::nullopt, deadline, stop);
    if (!existing)
      return std::unexpected(existing.error());
    std::optional<std::string> condition;
    if (existing->status == 404)
      condition = "";
    else if (existing->status == 200 && !existing->etag.empty()) {
      auto previous = json_timestamp(existing->body);
      if (!previous)
        return std::unexpected(previous.error());
      if (*previous > *incoming)
        return {};
      condition = existing->etag;
    } else
      return std::unexpected(Error::network);
    auto saved = impl_->request(url, true, json, condition, deadline, stop);
    if (!saved)
      return std::unexpected(saved.error());
    if (saved->status >= 200 && saved->status < 300)
      return {};
    if (saved->status != 409 && saved->status != 412)
      return std::unexpected(Error::network);
  }
  return std::unexpected(Error::conflict);
}
struct Redis::Impl {
  const Config &config;
  RedisConnection connection;
  explicit Impl(const Config &cfg) : config(cfg) {}
};
Redis::Redis(const Config &config) : impl_(std::make_unique<Impl>(config)) {}
Redis::~Redis() = default;
Result<void> Redis::save(std::string_view json, Deadline deadline,
                         std::stop_token stop) {
  if (auto check = active(deadline, stop); !check)
    return check;
  const auto &config = impl_->config;
  const auto remaining = std::max<std::int64_t>(
      1, duration_cast<milliseconds>(deadline - steady_clock::now()).count());
  const timeval timeout{static_cast<time_t>(remaining / 1000),
                        static_cast<suseconds_t>((remaining % 1000) * 1000)};
  auto &connection = impl_->connection;
  if (!connection) {
    redisOptions options{};
    REDIS_OPTIONS_SET_TCP(&options, config.redis_host.c_str(),
                          config.redis_port);
    options.connect_timeout = &timeout;
    options.command_timeout = &timeout;
    connection.reset(redisConnectWithOptions(&options));
    if (!connection || connection->err) {
      connection.reset();
      return std::unexpected(Error::network);
    }
    if (!config.redis_password.empty()) {
      Reply auth{static_cast<redisReply *>(redisCommand(
          connection.get(), "AUTH %b", config.redis_password.data(),
          config.redis_password.size()))};
      if (!auth || auth->type != REDIS_REPLY_STATUS ||
          std::string_view{auth->str, auth->len} != "OK") {
        connection.reset();
        return std::unexpected(Error::network);
      }
    }
  }
  if (auto check = active(deadline, stop); !check) {
    connection.reset();
    return check;
  }
  const auto command_ms = std::max<std::int64_t>(
      1, duration_cast<milliseconds>(deadline - steady_clock::now()).count());
  const timeval command_timeout{
      static_cast<time_t>(command_ms / 1000),
      static_cast<suseconds_t>((command_ms % 1000) * 1000)};
  if (redisSetTimeout(connection.get(), command_timeout) != REDIS_OK) {
    connection.reset();
    return std::unexpected(Error::network);
  }
  constexpr auto script = R"LUA(
local function stamp(s)
  local base, frac = string.match(s, '^(%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d)%.?(%d*)Z$')
  if not base or #frac > 9 then error('invalid snapshot timestamp') end
  return base .. frac .. string.rep('0', 9 - #frac)
end
local incoming = cjson.decode(ARGV[1])
local next_stamp = stamp(incoming.asOf)
local current = redis.call('GET', KEYS[1])
if current and stamp(cjson.decode(current).asOf) > next_stamp then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
return 1
)LUA";
  Reply reply{static_cast<redisReply *>(redisCommand(
      connection.get(), "EVAL %s 1 %b %b %d", script, config.redis_key.data(),
      config.redis_key.size(), json.data(), json.size(), config.redis_ttl))};
  if (!reply || reply->type != REDIS_REPLY_INTEGER) {
    connection.reset();
    return std::unexpected(Error::network);
  }
  if (auto check = active(deadline, stop); !check) {
    connection.reset();
    return check;
  }
  return {};
}
} // namespace metrics
