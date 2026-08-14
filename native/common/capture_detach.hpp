#pragma once

namespace latencydesk {

class CaptureDetachState final {
 public:
  void native_work_started() noexcept { native_work_started_ = true; }

  void completion_proven() noexcept { completion_proven_ = true; }

  [[nodiscard]] bool release_permitted() const noexcept {
    return !native_work_started_ || completion_proven_;
  }

 private:
  bool native_work_started_{};
  bool completion_proven_{};
};

}  // namespace latencydesk
