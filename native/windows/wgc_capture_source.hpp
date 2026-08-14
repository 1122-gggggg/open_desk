#pragma once

#include "dda_capture_source.hpp"

#include <windows.graphics.directx.direct3d11.interop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>
#include <winrt/base.h>

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>

namespace latencydesk {

struct WgcFrameAvailable final {
  D3D11_TEXTURE2D_DESC description{};
};

enum class WgcPollKind : std::uint8_t {
  Timeout,
  FrameAvailable,
  SizeChanged,
  ItemClosed,
};

struct WgcPollResult final {
  WgcPollKind kind;
  std::optional<WgcFrameAvailable> frame;
};

/// One pre-authorized GraphicsCaptureItem on an existing engine D3D11 device.
///
/// This source never creates a picker or bypasses item authorization. It holds
/// a frame only between `poll` and `detach_owned`/`discard_pending`; the owned
/// texture is returned only after the GPU copy completion query has observed it.
class WgcCaptureSource final {
 public:
  WgcCaptureSource(
      winrt::Windows::Graphics::Capture::GraphicsCaptureItem item,
      ID3D11Device* device);
  WgcCaptureSource(const WgcCaptureSource&) = delete;
  WgcCaptureSource& operator=(const WgcCaptureSource&) = delete;
  ~WgcCaptureSource();

  void start();
  [[nodiscard]] WgcPollResult poll(std::uint64_t timeout_ns);
  [[nodiscard]] D3d11OwnedFrame detach_owned();
  void discard_pending();
  void stop() noexcept;

 private:
  struct CallbackState final {
    std::mutex mutex;
    std::condition_variable ready;
    bool frame_available{};
    bool item_closed{};
    bool stopped{};
  };

  void require_started() const;
  void release_pending();
  void recreate_for(winrt::Windows::Graphics::SizeInt32 size);

  winrt::Windows::Graphics::Capture::GraphicsCaptureItem item_{nullptr};
  Microsoft::WRL::ComPtr<ID3D11Device> device_;
  Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
  Microsoft::WRL::ComPtr<ID3D11Query> copy_completion_query_;
  winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice direct3d_device_{nullptr};
  winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool frame_pool_{nullptr};
  winrt::Windows::Graphics::Capture::GraphicsCaptureSession session_{nullptr};
  winrt::event_token frame_arrived_token_{};
  winrt::event_token item_closed_token_{};
  std::shared_ptr<CallbackState> callbacks_;
  winrt::Windows::Graphics::SizeInt32 content_size_{};
  winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame pending_frame_{nullptr};
  Microsoft::WRL::ComPtr<ID3D11Texture2D> pending_texture_;
  D3D11_TEXTURE2D_DESC pending_description_{};
  bool apartment_initialized_{};
  bool copy_started_{};
  bool copy_completed_{};
};

}  // namespace latencydesk
