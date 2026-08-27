#include "mf_h264_encoder.hpp"

#include <windows.h>
#include <d3d11.h>
#include <wrl/client.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

#include <fstream>
using Microsoft::WRL::ComPtr;

namespace {

constexpr UINT kWidth = 1280;
constexpr UINT kHeight = 720;
constexpr UINT kFps = 60;

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
                                   128);
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

bool has_annex_b_start_code(const std::vector<std::uint8_t>& bytes) {
  for (std::size_t index = 0; index + 3 < bytes.size(); ++index) {
    if (bytes[index] == 0 && bytes[index + 1] == 0 &&
        (bytes[index + 2] == 1 ||
         (bytes[index + 2] == 0 && bytes[index + 3] == 1))) {
      return true;
    }
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(com) && com != RPC_E_CHANGED_MODE) {
    std::cerr << "CoInitializeEx failed, HRESULT="
              << static_cast<unsigned long>(com) << '\n';
    return EXIT_FAILURE;
  }
  try {
    const ComPtr<ID3D11Device> device = create_device();
    const ComPtr<ID3D11Texture2D> texture = create_nv12(device.Get());
    latencydesk::MfH264Encoder encoder(device.Get(), kWidth, kHeight, 30'000'000,
                                       kFps, 1);
    if (encoder.request_idr() != latencydesk::MfEncoderStatus::Ok) {
      throw std::runtime_error("request_idr failed");
    }
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    latencydesk::MfEncoderStatus submission = latencydesk::MfEncoderStatus::QueueFull;
    while (submission == latencydesk::MfEncoderStatus::QueueFull &&
           std::chrono::steady_clock::now() < deadline) {
      submission = encoder.encode_frame(texture.Get(), 1, 1'000'000);
      if (submission == latencydesk::MfEncoderStatus::QueueFull) Sleep(1);
    }
    if (submission != latencydesk::MfEncoderStatus::Ok) {
      throw std::runtime_error("async encoder never accepted NeedInput token, status=" +
                               std::to_string(static_cast<unsigned>(submission)));
    }
    const latencydesk::MfEncoderStatus overflow =
        encoder.encode_frame(texture.Get(), 2, 2'000'000);
    if (overflow != latencydesk::MfEncoderStatus::QueueFull) {
      throw std::runtime_error("encoder queue/token bound was not enforced");
    }
    std::optional<latencydesk::MfEncodedPacket> packet;
    latencydesk::MfEncoderStatus output = latencydesk::MfEncoderStatus::NoOutput;
    while (output == latencydesk::MfEncoderStatus::NoOutput &&
           std::chrono::steady_clock::now() < deadline) {
      output = encoder.poll_output(packet);
      if (output == latencydesk::MfEncoderStatus::NoOutput) Sleep(1);
    }
    if (output != latencydesk::MfEncoderStatus::Ok || !packet ||
        packet->capture_sequence != 1 || packet->timestamp_ns != 1'000'000 ||
        !packet->is_keyframe || !has_annex_b_start_code(packet->data)) {
      throw std::runtime_error("async encoder output contract failed, status=" +
                               std::to_string(static_cast<unsigned>(output)));
    }
    if (argc == 3 && std::string_view(argv[1]) == "--dump") {
      std::ofstream dump(argv[2], std::ios::binary | std::ios::trunc);
      if (!dump) throw std::runtime_error("failed to open AU dump");
      dump.write(reinterpret_cast<const char*>(packet->data.data()),
                 static_cast<std::streamsize>(packet->data.size()));
      if (!dump) throw std::runtime_error("failed to write AU dump");
    } else if (argc != 1) {
      throw std::invalid_argument("usage: mf_h264_encoder_async_probe [--dump PATH]");
    }
    const std::size_t output_bytes = packet->data.size();
    packet.reset();
    if (encoder.drain() != latencydesk::MfEncoderStatus::Ok) {
      throw std::runtime_error("bounded DrainComplete failed");
    }
    std::cout << "{\"async_mft\":true,\"input_frames\":1,\"output_access_units\":1,"
                 "\"queue_bounded\":true,\"idr\":true,\"annex_b\":true,"
                 "\"drain_complete\":true,\"output_bytes\":"
              << output_bytes << "}\n";
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    if (SUCCEEDED(com)) CoUninitialize();
    return EXIT_FAILURE;
  }
  if (SUCCEEDED(com)) CoUninitialize();
  return EXIT_SUCCESS;
}
