#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d3d11.h>
#include <codecapi.h>
#include <strmif.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wrl/client.h>

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>

namespace latencydesk {

enum class MfDecoderStatus : std::uint32_t {
  Ok = 0,
  NoOutput = 1,
  QueueFull = 2,
  Unsupported = 3,
  InvalidState = 4,
  InvalidArgument = 5,
  DeviceLost = 6,
  InternalFailure = 7,
};

struct MfDecodedFrame final {
  Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
  D3D11_TEXTURE2D_DESC description{};
  std::uint64_t frame_id{};
  std::uint64_t timestamp_ns{};
};

class MfH264Decoder final {
 public:
  MfH264Decoder(ID3D11Device* device, UINT width, UINT height, UINT fps,
                UINT max_queue_depth);
  ~MfH264Decoder();

  MfH264Decoder(const MfH264Decoder&) = delete;
  MfH264Decoder& operator=(const MfH264Decoder&) = delete;

  [[nodiscard]] MfDecoderStatus decode(const std::uint8_t* annex_b, std::size_t size,
                                       std::uint64_t frame_id,
                                       std::uint64_t timestamp_ns);
  [[nodiscard]] MfDecoderStatus poll_output(std::optional<MfDecodedFrame>& frame);
  [[nodiscard]] MfDecoderStatus flush() noexcept;
  [[nodiscard]] MfDecoderStatus quiesce() noexcept;
  [[nodiscard]] bool hardware_accelerated() const noexcept;

 private:
  struct PendingMeta final {
    std::uint64_t frame_id{};
    std::uint64_t timestamp_ns{};
  };

  void initialize();
  void configure_output_type();
  [[nodiscard]] MfDecoderStatus copy_output_sample(IMFSample* sample,
                                                    MfDecodedFrame& frame);
  [[nodiscard]] MfDecoderStatus pump_events() noexcept;
  [[nodiscard]] MfDecoderStatus purge_events() noexcept;

  mutable std::mutex mutex_;
  UINT width_{};
  UINT height_{};
  UINT fps_{};
  UINT max_queue_depth_{};
  DWORD input_stream_id_{};
  DWORD output_stream_id_{};
  UINT reset_token_{};
  bool mf_started_{};
  bool started_{};
  bool asynchronous_{};
  bool hardware_accelerated_{};
  UINT need_input_tokens_{};
  UINT have_output_tokens_{};
  HRESULT async_error_{S_OK};
  Microsoft::WRL::ComPtr<ID3D11Device> device_;
  Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
  Microsoft::WRL::ComPtr<IMFDXGIDeviceManager> device_manager_;
  Microsoft::WRL::ComPtr<ID3D11Query> copy_completion_query_;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> copy_pool_[2];
  D3D11_TEXTURE2D_DESC copy_pool_description_{};
  UINT copy_pool_index_{};
  Microsoft::WRL::ComPtr<IMFTransform> transform_;
  Microsoft::WRL::ComPtr<IMFMediaEventGenerator> event_source_;
  std::deque<PendingMeta> pending_;
};

}  // namespace latencydesk
