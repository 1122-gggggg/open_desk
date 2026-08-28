#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d10_1.h>
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
  [[nodiscard]] D3d11OwnedFrame detach_owned(UINT destination_format = 0U,
                                             UINT destination_width = 0U,
                                             UINT destination_height = 0U);
  void discard_pending();
  void stop() noexcept;

  [[nodiscard]] static D3D11_TEXTURE2D_DESC make_nv12_description(UINT width,
                                                                  UINT height) noexcept;
  [[nodiscard]] static D3D11_TEXTURE2D_DESC make_intermediate_description(
      const D3D11_TEXTURE2D_DESC& description) noexcept;

  [[nodiscard]] ID3D11Device* device() const noexcept { return device_.Get(); }
  [[nodiscard]] ID3D11DeviceContext* context() const noexcept { return context_.Get(); }
  [[nodiscard]] bool is_copy_started() const noexcept { return copy_started_; }
  [[nodiscard]] bool is_copy_completed() const noexcept { return copy_completed_; }
  [[nodiscard]] const D3D11_TEXTURE2D_DESC& intermediate_description() const noexcept {
    return intermediate_description_;
  }
  [[nodiscard]] bool is_unusable() const noexcept { return unusable_; }

 private:
  void release_pending();
  void require_started() const;
  [[nodiscard]] DdaFrameMetadata read_metadata(const DXGI_OUTDUPL_FRAME_INFO& info);
  void ensure_video_processor(DXGI_FORMAT input_format, DXGI_FORMAT output_format,
                              UINT input_width, UINT input_height,
                              UINT output_width, UINT output_height);
  void ensure_intermediate_input(const D3D11_TEXTURE2D_DESC& description);
  void ensure_nv12_pool(UINT width, UINT height);
  void destroy_unusable() noexcept;


  UINT adapter_index_;
  UINT output_index_;
  Microsoft::WRL::ComPtr<ID3D11Device> device_;
  Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
  Microsoft::WRL::ComPtr<IDXGIOutputDuplication> duplication_;
  Microsoft::WRL::ComPtr<ID3D11Query> copy_completion_query_;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> pending_texture_;
  D3D11_TEXTURE2D_DESC pending_description_{};
  std::vector<std::uint8_t> metadata_buffer_;
  bool copy_started_{};
  bool copy_completed_{};
  bool unusable_{};
  Microsoft::WRL::ComPtr<ID3D11VideoDevice> video_device_;
  Microsoft::WRL::ComPtr<ID3D11VideoContext> video_context_;
  Microsoft::WRL::ComPtr<ID3D11VideoProcessorEnumerator> video_enumerator_;
  Microsoft::WRL::ComPtr<ID3D11VideoProcessor> video_processor_;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> intermediate_input_texture_;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> nv12_pool_texture_;
  D3D11_TEXTURE2D_DESC intermediate_description_{};
  D3D11_TEXTURE2D_DESC nv12_pool_description_{};
  DXGI_FORMAT video_processor_input_format_{};
  DXGI_FORMAT video_processor_output_format_{};
  UINT video_processor_input_width_{};
  UINT video_processor_input_height_{};
  UINT video_processor_output_width_{};
  UINT video_processor_output_height_{};
};

}  // namespace latencydesk
