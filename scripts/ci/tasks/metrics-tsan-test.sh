#!/bin/sh
set -eu
metrics_tsan_build="${1:?Pass the ThreadSanitizer build directory}"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    # Apply ADDR_NO_RANDOMIZE only to CTest and its instrumented children.
    # Permission errors and sanitizer/test failures remain hard CI failures.
    exec setarch x86_64 -R ctest --test-dir "$metrics_tsan_build" --output-on-failure
    ;;
  *)
    exec ctest --test-dir "$metrics_tsan_build" --output-on-failure
    ;;
esac
