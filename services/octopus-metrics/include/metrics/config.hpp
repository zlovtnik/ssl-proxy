#pragma once
#include "metrics/domain.hpp"
#include <functional>

namespace metrics {
struct Config {
  std::string pg_host = "postgres-pgbouncer";
  std::string pg_port = "5432";
  std::string pg_database = "sync";
  std::string pg_user = "octopus_metrics";
  std::string pg_password;
  std::string pg_ssl_mode = "verify-full";
  std::string pg_ca = "/etc/postgres/tls/ca.crt";
  std::string pg_server_name = "postgres-pgbouncer";
  std::string redis_host = "ssl-proxy-redis-runtime";
  int redis_port = 6379;
  std::string redis_password;
  std::string redis_key = "stats:current:v2";
  int redis_ttl = 180;
  std::string minio_endpoint = "http://ssl-proxy-minio-api:9000";
  std::string minio_access;
  std::string minio_secret;
  std::string minio_region = "us-east-1";
  std::string minio_bucket = "ssl-proxy-stats";
  std::string minio_prefix = "stats/";
  std::string live_url =
      "http://ssl-proxy-java-coordinator:8080/internal/metrics/live";
  int workers = 3;
  int http_port = 9092;
  int peaks_interval = 300;
  int history_interval = 60;
  int live_interval = 15;
  int publish_interval = 30;
  int timeout = 60;
  bool local_dev = false;
};
using Environment = std::function<std::optional<std::string>(std::string_view)>;
Result<Config> read_config(const Environment &env);
Environment process_environment();
} // namespace metrics
