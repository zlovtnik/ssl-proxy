#include "metrics/adapters.hpp"
#include <fstream>
#include <iostream>
#include <iterator>

int main(int argc, char **argv) {
  using namespace metrics;
  try {
    if (argc < 2)
      return 2;
    const auto config = read_config(process_environment());
    if (!config)
      return 2;
    const CurlRuntime runtime;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds{config->timeout};
    const std::string_view command{argv[1]};
    Repository repository{*config};
    State state;
    const auto at = argc > 2 ? parse_time(argv[2]) : Result<Time>{now()};
    if (!at)
      return 2;
    if (command == "verify") {
      const auto verified = repository.verify(deadline, {});
      if (!verified) {
        std::cerr << error_name(verified.error());
        return 1;
      }
      return 0;
    }
    if (command == "snapshot") {
      const auto aggregates = repository.aggregates(deadline, {});
      const auto history = repository.history(*at, deadline, {});
      if (!aggregates || !history) {
        std::cerr << error_name(aggregates ? history.error()
                                           : aggregates.error());
        return 1;
      }
      state.aggregates = Measured<Aggregates>{*aggregates, *at};
      state.history = Measured<History>{*history, *at};
      std::pmr::monotonic_buffer_resource arena;
      std::cout << serialize(state, *at, arena);
      return 0;
    }
    if (argc < 4)
      return 2;
    std::ifstream input{argv[3]};
    const std::string json{std::istreambuf_iterator<char>{input}, {}};
    if (command == "redis") {
      Redis redis{*config};
      const auto saved = redis.save(json, deadline, {});
      if (!saved) {
        std::cerr << error_name(saved.error());
        return 1;
      }
      return 0;
    }
    if (command == "object") {
      Http http{*config};
      const auto saved = http.object("latest.json", json, *at, deadline, {});
      if (!saved) {
        std::cerr << error_name(saved.error());
        return 1;
      }
      return 0;
    }
    return 2;
  } catch (...) {
    return 2;
  }
}
