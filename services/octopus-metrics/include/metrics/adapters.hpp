#pragma once
#include "metrics/config.hpp"
#include <memory>
#include <stop_token>

namespace metrics {
// Only owning RAII wrappers cross the C library boundary. Library callbacks
// and result views borrow memory for the duration of one operation.
class Repository {
public:
  explicit Repository(const Config &config);
  ~Repository();
  Repository(const Repository &) = delete;
  Repository &operator=(const Repository &) = delete;
  Result<void> verify(Deadline deadline, std::stop_token stop);
  Result<Aggregates> aggregates(Deadline deadline, std::stop_token stop);
  Result<History> history(Time at, Deadline deadline, std::stop_token stop);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
class Http {
public:
  explicit Http(const Config &config);
  ~Http();
  Http(const Http &) = delete;
  Http &operator=(const Http &) = delete;
  Result<Measured<std::optional<Live>>> live(Deadline deadline,
                                             std::stop_token stop);
  Result<void> object(std::string_view path, std::string_view json, Time at,
                      Deadline deadline, std::stop_token stop);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
class Redis {
public:
  explicit Redis(const Config &config);
  ~Redis();
  Result<void> save(std::string_view json, Deadline deadline,
                    std::stop_token stop);

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};
Result<Measured<std::optional<Live>>> parse_live(std::string_view json,
                                                 Time received_at);
class CurlRuntime {
public:
  CurlRuntime();
  ~CurlRuntime();
  CurlRuntime(const CurlRuntime &) = delete;
  CurlRuntime &operator=(const CurlRuntime &) = delete;
};
} // namespace metrics
