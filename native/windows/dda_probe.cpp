#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include "dda_capture_source.hpp"
#include <chrono>
#include <exception>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace {

std::uint64_t checksum(const D3D11_MAPPED_SUBRESOURCE& mapped,
                       const D3D11_TEXTURE2D_DESC& description) {
  std::uint64_t hash = 0xcbf29ce484222325ULL;
  const auto* base = static_cast<const std::uint8_t*>(mapped.pData);
  const auto row_bytes = static_cast<std::size_t>(description.Width) * 4U;
  for (UINT row = 0; row < description.Height; ++row) {
    const auto* data = base + static_cast<std::size_t>(row) * mapped.RowPitch;
    for (std::size_t index = 0; index < row_bytes; ++index) {
      hash ^= data[index];
      hash *= 0x100000001b3ULL;
    }
  }
  return hash;
}

struct Options {
  UINT adapter{};
  UINT output{};
  std::uint64_t frames{60};
  UINT timeout_ms{500};
};

Options parse(int argc, wchar_t** argv) {
  Options options;
  for (int index = 1; index < argc; ++index) {
    const std::wstring argument = argv[index];
    auto value = [&]() -> std::wstring {
      if (++index >= argc) {
        throw std::invalid_argument("missing argument value");
      }
      return argv[index];
    };
    if (argument == L"--adapter") options.adapter = std::stoul(value());
    else if (argument == L"--output") options.output = std::stoul(value());
    else if (argument == L"--frames") options.frames = std::stoull(value());
    else if (argument == L"--timeout-ms") options.timeout_ms = std::stoul(value());
    else if (argument == L"--help") {
      std::wcout << L"latencydesk_win_dda_probe [--adapter N] [--output N] [--frames N] [--timeout-ms N]\n";
      std::exit(EXIT_SUCCESS);
    } else throw std::invalid_argument("unknown argument");
  }
  if (options.frames == 0 || options.frames > 100000 || options.timeout_ms > 10000) {
    throw std::invalid_argument("argument out of range");
  }
  return options;
}

}  // namespace

int wmain(int argc, wchar_t** argv) try {
  const Options options = parse(argc, argv);
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

  latencydesk::DdaCaptureSource source(options.adapter, options.output);
  source.start();

  std::uint64_t acquired = 0;
  std::uint64_t timeouts = 0;
  std::uint64_t dirty_rectangles = 0;
  std::uint64_t move_rectangles = 0;
  std::uint64_t protected_masked = 0;
  std::uint64_t aggregate_checksum = 0;
  std::uint64_t total_copy_us = 0;

  while (acquired < options.frames) {
    const auto frame = source.poll(options.timeout_ms);
    if (!frame.has_value()) {
      ++timeouts;
      continue;
    }

    dirty_rectangles += frame->metadata.dirty_rects.size();
    move_rectangles += frame->metadata.move_rects.size();
    if (frame->metadata.protected_content_masked) ++protected_masked;

    const auto copy_begin = std::chrono::steady_clock::now();
    const auto owned = source.detach_owned();
    D3D11_TEXTURE2D_DESC staging_description = owned.description();
    staging_description.Usage = D3D11_USAGE_STAGING;
    staging_description.BindFlags = 0;
    staging_description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    staging_description.MiscFlags = 0;
    ComPtr<ID3D11Texture2D> staging;
    HRESULT status = source.device()->CreateTexture2D(&staging_description, nullptr, &staging);
    if (FAILED(status)) throw latencydesk::DdaError(status, "Create staging texture");
    source.context()->CopyResource(staging.Get(), owned.texture());
    D3D11_MAPPED_SUBRESOURCE mapped{};
    status = source.context()->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(status)) throw latencydesk::DdaError(status, "Map staging");
    aggregate_checksum ^= checksum(mapped, staging_description);
    source.context()->Unmap(staging.Get(), 0);
    total_copy_us += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - copy_begin)
            .count());
    ++acquired;
  }

  std::cout << "{\"backend\":\"dxgi_desktop_duplication\",\"frames\":"
            << acquired << ",\"timeouts\":" << timeouts
            << ",\"dirty_rectangles\":" << dirty_rectangles
            << ",\"move_rectangles\":" << move_rectangles
            << ",\"protected_content_masked_frames\":" << protected_masked
            << ",\"forced_gpu_then_cpu_copy\":true,\"total_copy_us\":"
            << total_copy_us << ",\"aggregate_checksum\":" << aggregate_checksum
            << "}\n";
  return EXIT_SUCCESS;
} catch (const latencydesk::DdaError& error) {
  if (error.status() == DXGI_ERROR_ACCESS_LOST) {
    std::cerr << "{\"error\":\"DXGI_ERROR_ACCESS_LOST\",\"recreate_required\":true}\n";
    return 3;
  }
  std::cerr << error.what() << '\n';
  return EXIT_FAILURE;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return EXIT_FAILURE;
}
