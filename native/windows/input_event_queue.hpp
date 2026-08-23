#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>

namespace latencydesk::windows_bridge {

inline constexpr std::uint8_t kInputKindMouseMove = 1;
inline constexpr std::uint8_t kInputKindButton = 2;
inline constexpr std::uint8_t kInputKindKey = 3;
inline constexpr std::uint8_t kInputKindWheel = 4;
inline constexpr std::uint8_t kInputKindReleaseAll = 5;
inline constexpr std::uint8_t kInputKindOverflow = 6;

struct QueuedInput final {
  std::uint8_t kind{};
  std::uint8_t button{};
  std::uint8_t pressed{};
  std::int32_t x{};
  std::int32_t y{};
  std::int32_t wheel{};
  std::uint32_t vk{};
};

// Bounded input queue with safety-aware overflow semantics. Absolute mouse
// motion is replaceable; key/button/wheel/release transitions are not. If a
// queue containing only non-replaceable transitions saturates, one explicit
// overflow marker replaces the queue so the Rust client can ReleaseAll and
// disconnect instead of silently losing a key-up or button-up.
class InputEventQueue final {
 public:
  static constexpr std::size_t kCapacity = 64;

  void push(const QueuedInput& event) {
    if (overflow_latched_) {
      return;
    }

    if (event.kind == kInputKindMouseMove) {
      if (!events_.empty() && events_.back().kind == kInputKindMouseMove) {
        events_.back() = event;
      } else if (events_.size() < kCapacity) {
        events_.push_back(event);
      }
      return;
    }

    if (events_.size() >= kCapacity) {
      const auto replaceable = std::find_if(
          events_.begin(), events_.end(), [](const QueuedInput& queued) {
            return queued.kind == kInputKindMouseMove;
          });
      if (replaceable != events_.end()) {
        events_.erase(replaceable);
      } else {
        events_.clear();
        events_.push_back(QueuedInput{.kind = kInputKindOverflow});
        overflow_latched_ = true;
        return;
      }
    }
    events_.push_back(event);
  }

  [[nodiscard]] bool pop(QueuedInput& event) {
    if (events_.empty()) {
      return false;
    }
    event = events_.front();
    events_.pop_front();
    return true;
  }

  [[nodiscard]] std::size_t size() const noexcept { return events_.size(); }
  [[nodiscard]] bool overflow_latched() const noexcept {
    return overflow_latched_;
  }

 private:
  std::deque<QueuedInput> events_;
  bool overflow_latched_{};
};

}  // namespace latencydesk::windows_bridge
