#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <utility>

namespace latencydesk {

class CallbackGate final {
 public:
  class Lease final {
   public:
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;

    Lease(Lease&& other) noexcept : gate_(std::exchange(other.gate_, nullptr)) {}

    Lease& operator=(Lease&& other) noexcept {
      if (this != &other) {
        release();
        gate_ = std::exchange(other.gate_, nullptr);
      }
      return *this;
    }

    ~Lease() { release(); }

   private:
    friend class CallbackGate;

    explicit Lease(CallbackGate* gate) noexcept : gate_(gate) {}

    void release() noexcept {
      if (gate_ != nullptr) {
        gate_->leave();
        gate_ = nullptr;
      }
    }

    CallbackGate* gate_{};
  };

  CallbackGate() = default;
  CallbackGate(const CallbackGate&) = delete;
  CallbackGate& operator=(const CallbackGate&) = delete;

  [[nodiscard]] std::optional<Lease> try_enter() {
    std::scoped_lock lock(mutex_);
    if (closed_) return std::nullopt;
    ++active_callbacks_;
    return Lease(this);
  }

  void close() noexcept {
    std::scoped_lock lock(mutex_);
    closed_ = true;
    if (active_callbacks_ == 0) drained_.notify_all();
  }

  void wait_for_drain() {
    std::unique_lock lock(mutex_);
    drained_.wait(lock, [this] { return active_callbacks_ == 0; });
  }

 private:
  void leave() noexcept {
    std::scoped_lock lock(mutex_);
    --active_callbacks_;
    if (closed_ && active_callbacks_ == 0) drained_.notify_all();
  }

  std::mutex mutex_;
  std::condition_variable drained_;
  std::size_t active_callbacks_{};
  bool closed_{};
};

}  // namespace latencydesk
