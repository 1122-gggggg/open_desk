#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <vector>

namespace latencydesk {

class DdaError final : public std::runtime_error {
 public:
  DdaError(HRESULT status, const char* operation);

  [[nodiscard]] HRESULT status() const noexcept { return status_; }

 private:
  HRESULT status_;
};

struct DdaFrameMetadata final {
  bool protected_content_masked{};
  bool pointer_visible{};
  LONG pointer_x{};
  LONG pointer_y{};
  std::vector<DXGI_OUTDUPL_MOVE_RECT> move_rects;
  std::vector<RECT> dirty_rects;
  std::vector<std::uint8_t> pointer_shape;
};

/// Data-only report for the exact DDA frame retained by this source.
/// Callers must either detach it to an owned texture or discard it before the
/// next poll, because IDXGIOutputDuplication permits only one acquired frame.
struct DdaFrameAvailable final {
  D3D11_TEXTURE2D_DESC description{};
  DdaFrameMetadata metadata;
};

/// Move-only engine-owned D3D11 texture copied from a borrowed capture frame.
class D3d11OwnedFrame final {
 public:
  D3d11OwnedFrame() = default;
  D3d11OwnedFrame(const D3d11OwnedFrame&) = delete;
  D3d11OwnedFrame& operator=(const D3d11OwnedFrame&) = delete;
  D3d11OwnedFrame(D3d11OwnedFrame&&) noexcept = default;
  D3d11OwnedFrame& operator=(D3d11OwnedFrame&&) noexcept = default;

  [[nodiscard]] ID3D11Texture2D* texture() const noexcept { return texture_.Get(); }
  [[nodiscard]] const D3D11_TEXTURE2D_DESC& description() const noexcept {
    return description_;
  }

  friend class DdaCaptureSource;
  friend class WgcCaptureSource;

  Microsoft::WRL::ComPtr<ID3D11Texture2D> texture_;
  D3D11_TEXTURE2D_DESC description_{};
};

/// One D3D11 adapter/output Desktop Duplication session.
///
/// Acquired DDA resources stay private. `detach_owned` proves its GPU copy has
/// completed, releases the DDA frame, then returns only the owned texture.
class DdaCaptureSource final {
 public:
  static constexpr UINT kMaxMetadataBytes = 1U << 20;

  DdaCaptureSource(UINT adapter_index, UINT output_index);
  DdaCaptureSource(const DdaCaptureSource&) = delete;
  DdaCaptureSource& operator=(const DdaCaptureSource&) = delete;
  ~DdaCaptureSource();

  void start();
  [[nodiscard]] std::optional<DdaFrameAvailable> poll(UINT timeout_ms);
  [[nodiscard]] D3d11OwnedFrame detach_owned();
  void discard_pending();
  void stop() noexcept;

  [[nodiscard]] ID3D11Device* device() const noexcept { return device_.Get(); }
  [[nodiscard]] ID3D11DeviceContext* context() const noexcept { return context_.Get(); }

 private:
  void release_pending();
  void require_started() const;
  [[nodiscard]] DdaFrameMetadata read_metadata(const DXGI_OUTDUPL_FRAME_INFO& info) const;

  UINT adapter_index_;
  UINT output_index_;
  Microsoft::WRL::ComPtr<ID3D11Device> device_;
  Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
  Microsoft::WRL::ComPtr<IDXGIOutputDuplication> duplication_;
  Microsoft::WRL::ComPtr<ID3D11Query> copy_completion_query_;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> pending_texture_;
  D3D11_TEXTURE2D_DESC pending_description_{};
  bool copy_started_{};
  bool copy_completed_{};
};

}  // namespace latencydesk
