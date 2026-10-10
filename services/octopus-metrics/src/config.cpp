#include "metrics/config.hpp"
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iterator>

namespace metrics {
namespace {
bool safe_key(std::string_view text, bool slash) {
  return !text.empty() && text.size() < 512 &&
         text.find("..") == std::string_view::npos && text.front() != '/' &&
         text.find_first_not_of(slash ? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"
                                        "MNOPQRSTUVWXYZ0123456789-_/.:"
                                      : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"
                                        "MNOPQRSTUVWXYZ0123456789-_:") ==
             std::string_view::npos;
}
bool http_url(std::string_view text) {
  const auto offset = text.starts_with("http://")    ? 7U
                      : text.starts_with("https://") ? 8U
                                                     : 0U;
  if (offset == 0 || text.size() <= offset || text.size() > 2048)
    return false;
  return text.find_first_of("\r\n\t @?#\\") == std::string_view::npos;
}
} // namespace
Environment process_environment() {
  return [](std::string_view key) -> std::optional<std::string> {
    const std::string name{key};
    const auto value = std::getenv(name.c_str());
    return value ? std::optional<std::string>{value} : std::nullopt;
  };
}
Result<Config> read_config(const Environment &env) {
  Config config;
  auto field = [&](std::string_view key, std::string &value) {
    if (auto found = env(key))
      value = *found;
  };
  field("POSTGRES_HOST", config.pg_host);
  field("POSTGRES_PORT", config.pg_port);
  field("POSTGRES_DATABASE", config.pg_database);
  field("POSTGRES_USER", config.pg_user);
  field("POSTGRES_PASSWORD", config.pg_password);
  field("POSTGRES_SSL_MODE", config.pg_ssl_mode);
  field("POSTGRES_SSL_CA_PATH", config.pg_ca);
  field("POSTGRES_SSL_SERVER_NAME", config.pg_server_name);
  field("REDIS_PASSWORD", config.redis_password);
  field("STATS_REDIS_KEY", config.redis_key);
  field("MINIO_ENDPOINT", config.minio_endpoint);
  field("MINIO_ACCESS_KEY_ID", config.minio_access);
  field("MINIO_SECRET_ACCESS_KEY", config.minio_secret);
  field("MINIO_REGION", config.minio_region);
  field("MINIO_STATS_BUCKET", config.minio_bucket);
  field("MINIO_STATS_PREFIX", config.minio_prefix);
  field("STATS_OCTOPUS_LIVE_URL", config.live_url);
  auto integer = [&](std::string_view key, int &value, int max) -> bool {
    if (const auto text = env(key)) {
      const auto [end, error] =
          std::from_chars(text->data(), text->data() + text->size(), value);
      if (error != std::errc{} || end != text->data() + text->size())
        return false;
    }
    return value > 0 && value <= max;
  };
  if (!integer("STATS_WORKER_COUNT", config.workers, 8) ||
      !integer("STATS_HTTP_PORT", config.http_port, 65535) ||
      !integer("STATS_PEAKS_INTERVAL_SECONDS", config.peaks_interval, 86400) ||
      !integer("STATS_HISTORY_INTERVAL_SECONDS", config.history_interval,
               3600) ||
      !integer("STATS_LIVE_INTERVAL_SECONDS", config.live_interval, 60) ||
      !integer("STATS_PUBLISH_INTERVAL_SECONDS", config.publish_interval,
               3600) ||
      !integer("STATS_JOB_TIMEOUT_SECONDS", config.timeout, 300) ||
      !integer("STATS_REDIS_TTL_SECONDS", config.redis_ttl, 86400))
    return std::unexpected(Error::configuration);
  if (const auto flag = env("STATS_LOCAL_DEV")) {
    if (*flag != "true" && *flag != "false")
      return std::unexpected(Error::configuration);
    config.local_dev = *flag == "true";
  }
  if (const auto file = env("POSTGRES_PASSWORD_FILE")) {
    if (env("POSTGRES_PASSWORD") || file->empty())
      return std::unexpected(Error::configuration);
    std::ifstream stream{*file};
    if (!stream)
      return std::unexpected(Error::configuration);
    // Secret reads are bounded; accidental use of a device cannot exhaust
    // memory.
    std::array<char, 4097> bytes{};
    stream.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (stream.gcount() >= static_cast<std::streamsize>(bytes.size()))
      return std::unexpected(Error::configuration);
    config.pg_password.assign(bytes.data(),
                              static_cast<std::size_t>(stream.gcount()));
    while (!config.pg_password.empty() && (config.pg_password.back() == '\n' ||
                                           config.pg_password.back() == '\r'))
      config.pg_password.pop_back();
  }
  if (const auto addr = env("REDIS_ADDR")) {
    // Plain host:port, or bracketed IPv6. Reject URI schemes rather than
    // silently downgrading rediss to plaintext (the retired Scala parser did
    // that).
    const auto colon = addr->rfind(':');
    if (colon == std::string::npos)
      return std::unexpected(Error::configuration);
    config.redis_host = addr->substr(0, colon);
    if (config.redis_host.starts_with('[') && config.redis_host.ends_with(']'))
      config.redis_host =
          config.redis_host.substr(1, config.redis_host.size() - 2);
    const auto port = addr->substr(colon + 1);
    const auto [end, error] = std::from_chars(
        port.data(), port.data() + port.size(), config.redis_port);
    if (error != std::errc{} || end != port.data() + port.size() ||
        config.redis_port <= 0 || config.redis_port > 65535 ||
        config.redis_host.empty() ||
        config.redis_host.find_first_of("/ @\r\n") != std::string::npos)
      return std::unexpected(Error::configuration);
  }
  int port{};
  const auto [end, error] =
      std::from_chars(config.pg_port.data(),
                      config.pg_port.data() + config.pg_port.size(), port);
  if (error != std::errc{} ||
      end != config.pg_port.data() + config.pg_port.size() || port <= 0 ||
      port > 65535 || config.pg_host.empty() || config.pg_database.empty() ||
      config.pg_user.empty() || config.pg_password.empty() ||
      config.pg_password.find('\0') != std::string::npos ||
      config.pg_user == "postgres" ||
      (!config.local_dev &&
       (config.pg_ssl_mode != "verify-full" || config.pg_ca.empty())) ||
      (config.local_dev && config.pg_ssl_mode != "disable" &&
       config.pg_ssl_mode != "verify-full") ||
      !safe_key(config.redis_key, false) ||
      !safe_key(config.minio_bucket, false) ||
      (!config.minio_prefix.empty() && !safe_key(config.minio_prefix, true)) ||
      !safe_key(config.minio_region, false) ||
      !http_url(config.minio_endpoint) || !http_url(config.live_url) ||
      config.minio_access.empty() || config.minio_secret.empty() ||
      config.redis_ttl <= config.publish_interval)
    return std::unexpected(Error::configuration);
  while (config.minio_endpoint.ends_with('/'))
    config.minio_endpoint.pop_back();
  if (!config.minio_prefix.empty() && !config.minio_prefix.ends_with('/'))
    config.minio_prefix += '/';
  return config;
}
} // namespace metrics
