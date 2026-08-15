#pragma once

#include <cstdint>
#include <memory>

#if __has_include("rust/cxx.h")
#include "rust/cxx.h"
#else
namespace rust {
template <typename T>
class Slice final {
 public:
  Slice() noexcept : data_(nullptr), length_(0) {}
  Slice(T* data, std::size_t length) noexcept : data_(data), length_(length) {}
  [[nodiscard]] T* data() const noexcept { return data_; }
  [[nodiscard]] std::size_t size() const noexcept { return length_; }
  [[nodiscard]] std::size_t length() const noexcept { return length_; }
 private:
  T* data_;
  std::size_t length_;
};
}
#endif

namespace latencydesk::windows_bridge {

inline constexpr std::uint32_t kBridgeAbiVersion = 2U;
inline constexpr std::uint32_t kDesktopDuplicationPendingFrameCapacity = 1U;

enum class BridgeStatus : std::uint32_t {
  Ok = 0U,
  NoFrame = 1U,
  AccessLost = 2U,
  ProtectedContent = 3U,
  PermissionDenied = 4U,
  PermissionRevoked = 5U,
  DeviceLost = 6U,
  InvalidState = 7U,
  InvalidArgument = 8U,
  QueueFull = 9U,
  Unsupported = 10U,
  SessionChanged = 11U,
  InternalFailure = 12U,
};

[[nodiscard]] constexpr std::uint32_t status_code(BridgeStatus status) noexcept {
  return static_cast<std::uint32_t>(status);
}
[[nodiscard]] BridgeStatus status_from_hresult(long status) noexcept;
[[nodiscard]] BridgeStatus status_from_wer_hresult(long status) noexcept;

[[nodiscard]] constexpr bool valid_capture_queue_capacity(
    std::uint32_t capacity) noexcept {
  return capacity == kDesktopDuplicationPendingFrameCapacity;
}

class CaptureImpl;
class SurfaceImpl;
class Surface;

// CXX requires a complete C++ class definition for UniquePtr deletion. These
// handles use Pimpl, so their COM/D3D/DXGI/WinRT state remains private to the
// C++ translation unit and is still opaque to Rust.
class Capture final {
 public:
  Capture(std::uint32_t adapter_index, std::uint32_t output_index);
  ~Capture();
  Capture(const Capture&) = delete;
  Capture& operator=(const Capture&) = delete;
  Capture(Capture&&) = delete;
  Capture& operator=(Capture&&) = delete;

  [[nodiscard]] BridgeStatus start();
  [[nodiscard]] BridgeStatus poll(std::uint32_t timeout_ms);
  [[nodiscard]] std::unique_ptr<Surface> detach(std::uint32_t destination_format = 0U,
                                                std::uint32_t destination_width = 0U,
                                                std::uint32_t destination_height = 0U);
  [[nodiscard]] BridgeStatus discard();
  [[nodiscard]] BridgeStatus stop();
  [[nodiscard]] std::uint32_t pending_width() const noexcept;
  [[nodiscard]] std::uint32_t pending_height() const noexcept;
  [[nodiscard]] std::uint32_t pending_format() const noexcept;
  [[nodiscard]] bool pending_pointer_visible() const noexcept;
  [[nodiscard]] std::int32_t pending_pointer_x() const noexcept;
  [[nodiscard]] std::int32_t pending_pointer_y() const noexcept;

 private:
  std::unique_ptr<CaptureImpl> impl_;
};

class Surface final {
 public:
  ~Surface();
  Surface(const Surface&) = delete;
  Surface& operator=(const Surface&) = delete;
  Surface(Surface&&) = delete;
  Surface& operator=(Surface&&) = delete;

  [[nodiscard]] std::uint32_t width() const noexcept;
  [[nodiscard]] std::uint32_t height() const noexcept;
  [[nodiscard]] std::uint32_t format() const noexcept;

 private:
  friend class CaptureImpl;
  friend class EncoderImpl;
  friend class RendererImpl;

  explicit Surface(std::unique_ptr<SurfaceImpl> impl);

  std::unique_ptr<SurfaceImpl> impl_;
};

class EncoderImpl;

class Encoder final {
 public:
  Encoder(std::uint32_t adapter_index, std::uint32_t width, std::uint32_t height,
          std::uint32_t target_bitrate_bps, std::uint32_t fps, std::uint32_t max_queue_depth);
  ~Encoder();
  Encoder(const Encoder&) = delete;
  Encoder& operator=(const Encoder&) = delete;
  Encoder(Encoder&&) = delete;
  Encoder& operator=(Encoder&&) = delete;

  [[nodiscard]] BridgeStatus encode(const Surface& surface, std::uint64_t capture_sequence, std::uint64_t timestamp_ns);
  [[nodiscard]] BridgeStatus poll_output(std::uint8_t* output_buffer, std::size_t buffer_capacity,
                                         std::size_t& output_size, bool& is_keyframe,
                                         std::uint64_t& capture_sequence, std::uint64_t& timestamp_ns);
  [[nodiscard]] BridgeStatus request_idr();
  [[nodiscard]] BridgeStatus update_bitrate(std::uint32_t target_bitrate_bps);
  [[nodiscard]] BridgeStatus drain();
  [[nodiscard]] BridgeStatus quiesce() noexcept;

 private:
  std::unique_ptr<EncoderImpl> impl_;
};

class RendererImpl;

class Renderer final {
 public:
  Renderer(std::uint32_t width, std::uint32_t height);
  ~Renderer();
  Renderer(const Renderer&) = delete;
  Renderer& operator=(const Renderer&) = delete;
  Renderer(Renderer&&) = delete;
  Renderer& operator=(Renderer&&) = delete;

  [[nodiscard]] bool pump_messages();
  [[nodiscard]] BridgeStatus present(const Surface& surface);
  [[nodiscard]] bool is_open() const noexcept;
  void close() noexcept;

 private:
  std::unique_ptr<RendererImpl> impl_;
};
class Input;

[[nodiscard]] std::uint32_t bridge_abi_version() noexcept;

// Registers the current executable with per-user Windows Error Reporting
// exclusion before any identity or capture material is created. The operation
// is idempotent within this process and fails closed through BridgeStatus.
[[nodiscard]] std::uint32_t prepare_current_process_wer_exclusion() noexcept;

// Desktop Duplication is the only capture factory exposed to ordinary Rust
// callers. WGC must be constructed from an authorization capability retained
// by native code; it is never a fallback for this factory.
[[nodiscard]] std::unique_ptr<Capture> make_desktop_duplication_capture(
    std::uint32_t adapter_index, std::uint32_t output_index,
    std::uint32_t pending_frame_capacity, std::uint32_t& status) noexcept;

[[nodiscard]] std::uint32_t capture_start(Capture& capture) noexcept;
[[nodiscard]] std::uint32_t capture_poll(Capture& capture,
                                         std::uint32_t timeout_ms) noexcept;
[[nodiscard]] std::unique_ptr<Surface> capture_detach(Capture& capture,
                                                       std::uint32_t destination_format,
                                                       std::uint32_t destination_width,
                                                       std::uint32_t destination_height,
                                                       std::uint32_t& status) noexcept;
[[nodiscard]] std::uint32_t capture_discard(Capture& capture) noexcept;
[[nodiscard]] std::uint32_t capture_stop(Capture& capture) noexcept;

[[nodiscard]] std::uint32_t capture_pending_width(const Capture& capture) noexcept;
[[nodiscard]] std::uint32_t capture_pending_height(const Capture& capture) noexcept;
[[nodiscard]] std::uint32_t capture_pending_format(const Capture& capture) noexcept;
[[nodiscard]] bool capture_pending_pointer_visible(const Capture& capture) noexcept;
[[nodiscard]] std::int32_t capture_pending_pointer_x(const Capture& capture) noexcept;
[[nodiscard]] std::int32_t capture_pending_pointer_y(const Capture& capture) noexcept;

[[nodiscard]] std::uint32_t surface_width(const Surface& surface) noexcept;
[[nodiscard]] std::uint32_t surface_height(const Surface& surface) noexcept;
[[nodiscard]] std::uint32_t surface_format(const Surface& surface) noexcept;

[[nodiscard]] std::unique_ptr<Encoder> make_mf_h264_encoder(
    std::uint32_t adapter_index, std::uint32_t width, std::uint32_t height,
    std::uint32_t target_bitrate_bps, std::uint32_t fps,
    std::uint32_t max_queue_depth, std::uint32_t& status) noexcept;

[[nodiscard]] std::uint32_t encoder_encode(Encoder& encoder, const Surface& surface,
                                           std::uint64_t capture_sequence,
                                           std::uint64_t timestamp_ns) noexcept;

[[nodiscard]] std::uint32_t encoder_poll_output(Encoder& encoder,
                                                rust::Slice<std::uint8_t> output_buffer,
                                                std::size_t& output_size,
                                                bool& is_keyframe,
                                                std::uint64_t& capture_sequence,
                                                std::uint64_t& timestamp_ns) noexcept;
[[nodiscard]] std::uint32_t encoder_request_idr(Encoder& encoder) noexcept;
[[nodiscard]] std::uint32_t encoder_update_bitrate(Encoder& encoder, std::uint32_t target_bitrate_bps) noexcept;
[[nodiscard]] std::uint32_t encoder_drain(Encoder& encoder) noexcept;
[[nodiscard]] std::unique_ptr<Renderer> make_d3d11_renderer(
    std::uint32_t width, std::uint32_t height, std::uint32_t& status) noexcept;

[[nodiscard]] bool renderer_pump_messages(Renderer& renderer) noexcept;
[[nodiscard]] std::uint32_t renderer_present(Renderer& renderer, const Surface& surface) noexcept;
[[nodiscard]] bool renderer_is_open(const Renderer& renderer) noexcept;
void renderer_close(Renderer& renderer) noexcept;
[[nodiscard]] std::uint32_t encoder_quiesce(Encoder& encoder) noexcept;
}  // namespace latencydesk::windows_bridge
