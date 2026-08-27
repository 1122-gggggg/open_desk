#include "mf_h264_decoder.hpp"
#include "mf_h264_encoder.hpp"

#include <windows.h>
#include <d3d11.h>
#include <wrl/client.h>
#include <algorithm>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace {

constexpr UINT kWidth = 1280;
constexpr UINT kHeight = 720;

void check(HRESULT result, const char* operation) {
  if (FAILED(result)) {
    throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                             std::to_string(static_cast<unsigned long>(result)));
  }
}

ComPtr<ID3D11Device> create_device() {
  ComPtr<ID3D11Device> device;
  ComPtr<ID3D11DeviceContext> context;
  D3D_FEATURE_LEVEL level{};
  constexpr D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_1,
                                          D3D_FEATURE_LEVEL_11_0};
  check(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                          D3D11_CREATE_DEVICE_VIDEO_SUPPORT, levels,
                          ARRAYSIZE(levels), D3D11_SDK_VERSION, &device, &level,
                          &context),
        "D3D11CreateDevice");
  return device;
}

ComPtr<ID3D11Texture2D> create_nv12(ID3D11Device* device) {
  std::vector<std::uint8_t> pixels(static_cast<std::size_t>(kWidth) * kHeight * 3 / 2,
                                   std::uint8_t{128});
  std::fill_n(pixels.begin(), static_cast<std::size_t>(kWidth) * kHeight,
              std::uint8_t{32});
  D3D11_TEXTURE2D_DESC description{};
  description.Width = kWidth;
  description.Height = kHeight;
  description.MipLevels = 1;
  description.ArraySize = 1;
  description.Format = DXGI_FORMAT_NV12;
  description.SampleDesc.Count = 1;
  description.Usage = D3D11_USAGE_DEFAULT;
  description.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
  D3D11_SUBRESOURCE_DATA data{};
  data.pSysMem = pixels.data();
  data.SysMemPitch = kWidth;
  data.SysMemSlicePitch = static_cast<UINT>(pixels.size());
  ComPtr<ID3D11Texture2D> texture;
  check(device->CreateTexture2D(&description, &data, &texture),
        "CreateTexture2D(NV12)");
  return texture;
}

latencydesk::MfEncodedPacket encode_one(ID3D11Device* device,
                                        ID3D11Texture2D* texture, UINT fps) {
  latencydesk::MfH264Encoder encoder(device, kWidth, kHeight, 30'000'000, fps, 2);
  if (encoder.request_idr() != latencydesk::MfEncoderStatus::Ok) {
    throw std::runtime_error("encoder request_idr failed");
  }
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  latencydesk::MfEncoderStatus status = latencydesk::MfEncoderStatus::QueueFull;
  while (status == latencydesk::MfEncoderStatus::QueueFull &&
         std::chrono::steady_clock::now() < deadline) {
    status = encoder.encode_frame(texture, 1, 1'000'000);
    if (status == latencydesk::MfEncoderStatus::QueueFull) Sleep(1);
  }
  if (status != latencydesk::MfEncoderStatus::Ok) {
    throw std::runtime_error("encoder input failed, status=" +
                             std::to_string(static_cast<unsigned>(status)));
  }
  std::optional<latencydesk::MfEncodedPacket> packet;
  status = latencydesk::MfEncoderStatus::NoOutput;
  while (status == latencydesk::MfEncoderStatus::NoOutput &&
         std::chrono::steady_clock::now() < deadline) {
    status = encoder.poll_output(packet);
    if (status == latencydesk::MfEncoderStatus::NoOutput) Sleep(1);
  }
  if (status != latencydesk::MfEncoderStatus::Ok || !packet) {
    throw std::runtime_error("encoder output failed, status=" +
                             std::to_string(static_cast<unsigned>(status)));
  }
  return std::move(*packet);
}

}  // namespace

int main(int argc, char** argv) {
  const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(com) && com != RPC_E_CHANGED_MODE) {
    std::cerr << "CoInitializeEx failed, HRESULT="
              << static_cast<unsigned long>(com) << '\n';
    return EXIT_FAILURE;
  }
  UINT fps = 60;
  if (argc == 3 && std::string(argv[1]) == "--fps") {
    const unsigned long parsed = std::stoul(argv[2]);
    if (parsed == 0 || parsed > 240) {
      std::cerr << "fps must be in 1..=240\n";
      return EXIT_FAILURE;
    }
    fps = static_cast<UINT>(parsed);
  } else if (argc != 1) {
    std::cerr << "usage: latencydesk_win_mf_h264_decode_probe [--fps N]\n";
    return EXIT_FAILURE;
  }
  try {
    const ComPtr<ID3D11Device> device = create_device();
    const ComPtr<ID3D11Texture2D> input = create_nv12(device.Get());
    const latencydesk::MfEncodedPacket packet =
        encode_one(device.Get(), input.Get(), fps);
    latencydesk::MfH264Decoder decoder(device.Get(), kWidth, kHeight, fps, 1);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    latencydesk::MfDecoderStatus status = latencydesk::MfDecoderStatus::QueueFull;
    while (status == latencydesk::MfDecoderStatus::QueueFull &&
           std::chrono::steady_clock::now() < deadline) {
      status = decoder.decode(packet.data.data(), packet.data.size(), 1, 1'000'000);
      if (status == latencydesk::MfDecoderStatus::QueueFull) Sleep(1);
    }
    if (status != latencydesk::MfDecoderStatus::Ok) {
      throw std::runtime_error("decoder input failed, status=" +
                               std::to_string(static_cast<unsigned>(status)));
    }
    const latencydesk::MfDecoderStatus overflow =
        decoder.decode(packet.data.data(), packet.data.size(), 99, 99'000'000);
    if (overflow != latencydesk::MfDecoderStatus::QueueFull) {
      throw std::runtime_error("decoder queue/token bound was not enforced");
    }
    Sleep(25);
    if (decoder.flush() != latencydesk::MfDecoderStatus::Ok) {
      throw std::runtime_error("decoder flush failed");
    }
    const auto flush_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    status = latencydesk::MfDecoderStatus::QueueFull;
    while (status == latencydesk::MfDecoderStatus::QueueFull &&
           std::chrono::steady_clock::now() < flush_deadline) {
      status = decoder.decode(packet.data.data(), packet.data.size(), 2, 2'000'000);
      if (status == latencydesk::MfDecoderStatus::QueueFull) Sleep(1);
    }
    if (status != latencydesk::MfDecoderStatus::Ok) {
      throw std::runtime_error("post-flush decoder input failed, status=" +
                               std::to_string(static_cast<unsigned>(status)));
    }
    std::optional<latencydesk::MfDecodedFrame> decoded;
    status = latencydesk::MfDecoderStatus::NoOutput;
    while (status == latencydesk::MfDecoderStatus::NoOutput &&
           std::chrono::steady_clock::now() < flush_deadline) {
      status = decoder.poll_output(decoded);
      if (status == latencydesk::MfDecoderStatus::NoOutput) Sleep(1);
    }
    if (status != latencydesk::MfDecoderStatus::Ok || !decoded ||
        decoded->frame_id != 2 || !decoder.hardware_accelerated()) {
      throw std::runtime_error("post-flush stale-event isolation failed, status=" +
                               std::to_string(static_cast<unsigned>(status)));
    }
    std::cout << "{\"provider\":\"windows_inbox_h264_dxva\","
                 "\"d3d11_aware\":true,\"hardware_accelerated\":true,"
                 "\"imfdxgi_buffer\":true,\"texture\":\"ID3D11Texture2D\","
                 "\"format\":\"NV12\",\"decoded_frames\":1,"
                 "\"flushed_pending_frames\":1,\"queue_bounded\":true,"
                 "\"flush_stale_events\":true,\"fps\":"
              << fps << ",\"au_bytes\":" << packet.data.size() << "}\n";
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    if (SUCCEEDED(com)) CoUninitialize();
    return EXIT_FAILURE;
  }
  if (SUCCEEDED(com)) CoUninitialize();
  return EXIT_SUCCESS;
}
