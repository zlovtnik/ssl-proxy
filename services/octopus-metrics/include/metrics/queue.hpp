#pragma once

#include <array>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <stop_token>

namespace metrics {
enum class Job : std::size_t { peaks, history, live };
// Bounded MPMC mailbox with one outstanding job per kind, including active
// work. Timer overload coalesces instead of allocating or accumulating debt.
class JobQueue {
public:
  bool offer(Job job) {
    const std::lock_guard lock(mutex_);
    const auto index = static_cast<std::size_t>(job);
    if (closed_ || outstanding_[index])
      return false;
    ring_[(head_ + size_) % ring_.size()] = job;
    ++size_;
    outstanding_[index] = true;
    ready_.notify_one();
    return true;
  }
  std::optional<Job> take(std::stop_token stop) {
    std::unique_lock lock(mutex_);
    if (!ready_.wait(lock, stop, [&] { return closed_ || size_ != 0; }) ||
        closed_)
      return std::nullopt;
    const auto job = ring_[head_];
    head_ = (head_ + 1) % ring_.size();
    --size_;
    return job;
  }
  void complete(Job job) {
    const std::lock_guard lock(mutex_);
    outstanding_[static_cast<std::size_t>(job)] = false;
  }
  void close() {
    const std::lock_guard lock(mutex_);
    closed_ = true;
    ready_.notify_all();
  }

private:
  std::mutex mutex_;
  std::condition_variable_any ready_;
  std::array<Job, 3> ring_{};
  std::array<bool, 3> outstanding_{};
  std::size_t head_{};
  std::size_t size_{};
  bool closed_{};
};
class Completion {
public:
  Completion(JobQueue &queue, Job job) : queue_(queue), job_(job) {}
  ~Completion() { queue_.complete(job_); }
  Completion(const Completion &) = delete;
  Completion &operator=(const Completion &) = delete;

private:
  JobQueue &queue_;
  Job job_;
};
} // namespace metrics
