#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <strmif.h>
#include <codecapi.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wrl/client.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace latencydesk {

enum class MfEncoderStatus : std::uint32_t {
  Ok = 0,
  NoOutput = 1,
  QueueFull = 2,
  Unsupported = 3,
  InvalidState = 4,
  InvalidArgument = 5,
  DeviceLost = 6,
  InternalFailure = 7,
};

struct MfEncodedPacket final {
  std::vector<std::uint8_t> data;
  bool is_keyframe{};
  std::uint64_t capture_sequence{};
  std::uint64_t timestamp_ns{};
};

class MfH264Encoder final {
 public:
  static constexpr std::size_t kMaxOutputPacketBytes = 16 * 1024 * 1024;

  MfH264Encoder(UINT adapter_index,
                UINT width,
                UINT height,
                UINT target_bitrate_bps,
                UINT fps,
                UINT max_queue_depth);
  ~MfH264Encoder();

  MfH264Encoder(const MfH264Encoder&) = delete;
  MfH264Encoder& operator=(const MfH264Encoder&) = delete;

  [[nodiscard]] MfEncoderStatus encode_frame(ID3D11Texture2D* texture,
                                             std::uint64_t capture_sequence,
                                             std::uint64_t timestamp_ns);

  [[nodiscard]] MfEncoderStatus poll_output(std::optional<MfEncodedPacket>& packet);

  [[nodiscard]] MfEncoderStatus request_idr();

  [[nodiscard]] MfEncoderStatus update_bitrate(UINT target_bitrate_bps);

  [[nodiscard]] MfEncoderStatus drain();

  [[nodiscard]] MfEncoderStatus quiesce() noexcept;

  [[nodiscard]] UINT width() const noexcept { return width_; }
  [[nodiscard]] UINT height() const noexcept { return height_; }
  [[nodiscard]] UINT target_bitrate_bps() const noexcept { return target_bitrate_bps_; }
  [[nodiscard]] UINT max_queue_depth() const noexcept { return max_queue_depth_; }
  [[nodiscard]] std::size_t in_flight_count() const noexcept;

 private:
  void initialize();
  void configure_media_types();
  void configure_codec_properties();
  [[nodiscard]] bool convert_to_annex_b(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out);

  UINT adapter_index_;
  UINT width_;
  UINT height_;
  UINT target_bitrate_bps_;
  UINT fps_;
  UINT max_queue_depth_;

  mutable std::mutex mutex_;
  bool initialized_{};
  bool started_{};
  bool mf_started_{};
  bool idr_requested_{};

  Microsoft::WRL::ComPtr<ID3D11Device> device_;
  Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
  Microsoft::WRL::ComPtr<IMFDXGIDeviceManager> device_manager_;
  UINT reset_token_{};

  Microsoft::WRL::ComPtr<IMFTransform> transform_;
  Microsoft::WRL::ComPtr<ICodecAPI> codec_api_;
  DWORD input_stream_id_{};
  DWORD output_stream_id_{};
  bool nalu_lengths_requested_{};

  std::uint64_t current_in_flight_{};
  std::vector<std::uint64_t> in_flight_sequences_;
  std::vector<std::uint64_t> in_flight_timestamps_;
};

}  // namespace latencydesk
