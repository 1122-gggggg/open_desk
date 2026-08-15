#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>
#include <wrl/client.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>
#include <winrt/base.h>

#include "capture_color_contract.hpp"
#include "capture_detach.hpp"
#include "callback_gate.hpp"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <exception>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;
namespace Capture = winrt::Windows::Graphics::Capture;
namespace Direct3D11 = winrt::Windows::Graphics::DirectX::Direct3D11;
namespace WinRTDirectX = winrt::Windows::Graphics::DirectX;
namespace {
constexpr std::uint64_t kCompletionTimeoutSeconds = 30;

constexpr std::size_t kOwnedPoolSlots = 3;

void check(HRESULT result, const char* operation) {
  if (FAILED(result)) {
    throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                             std::to_string(static_cast<unsigned long>(result)));
  }
}

enum class Backend { kDesktopDuplication, kWindowsGraphicsCapture };

struct Options {
  Backend backend{Backend::kDesktopDuplication};
  UINT adapter{};
  UINT output{};
  std::uint64_t frames{300};
  std::uint64_t duration_seconds{};
  UINT timeout_ms{500};
  std::uint64_t max_timeouts{120};
  std::uint64_t max_wall_seconds{};
  bool wgc_monitor_interop{};
};

const char* backend_name(Backend backend) {
  return backend == Backend::kDesktopDuplication ? "dxgi_desktop_duplication"
                                                  : "windows_graphics_capture";
}

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
    if (argument == L"--backend") {
      const std::wstring backend = value();
      if (backend == L"dda") options.backend = Backend::kDesktopDuplication;
      else if (backend == L"wgc") options.backend = Backend::kWindowsGraphicsCapture;
      else throw std::invalid_argument("backend must be dda or wgc");
    } else if (argument == L"--adapter") options.adapter = std::stoul(value());
    else if (argument == L"--output") options.output = std::stoul(value());
    else if (argument == L"--frames") options.frames = std::stoull(value());
    else if (argument == L"--duration-seconds") options.duration_seconds = std::stoull(value());
    else if (argument == L"--timeout-ms") options.timeout_ms = std::stoul(value());
    else if (argument == L"--max-timeouts") options.max_timeouts = std::stoull(value());
    else if (argument == L"--max-wall-seconds") options.max_wall_seconds = std::stoull(value());
    else if (argument == L"--wgc-monitor-interop") options.wgc_monitor_interop = true;
    else if (argument == L"--help") {
      std::wcout << L"latencydesk_win_capture_benchmark "
                    L"[--backend dda|wgc] [--adapter N] [--output N] "
                    L"[--frames N | --duration-seconds N] [--timeout-ms N] "
                    L"[--max-timeouts N] [--max-wall-seconds N] "
                    L"[--wgc-monitor-interop]\n";
      std::exit(EXIT_SUCCESS);
    } else {
      throw std::invalid_argument("unknown argument");
    }
  }
  if ((options.frames == 0 && options.duration_seconds == 0) || options.timeout_ms == 0 ||
      options.timeout_ms > 10'000 || options.max_timeouts == 0) {
    throw std::invalid_argument("invalid capture limits");
  }
  if (options.backend == Backend::kWindowsGraphicsCapture && !options.wgc_monitor_interop) {
    throw std::invalid_argument(
        "WGC monitor benchmarking requires explicit --wgc-monitor-interop authorization");
  }
  return options;
}

class Clock final {
 public:
  Clock() { check(QueryPerformanceFrequency(&frequency_) ? S_OK : E_FAIL, "QueryPerformanceFrequency"); }

  std::uint64_t now() const {
    LARGE_INTEGER value{};
    check(QueryPerformanceCounter(&value) ? S_OK : E_FAIL, "QueryPerformanceCounter");
    return static_cast<std::uint64_t>(value.QuadPart);
  }

  std::uint64_t microseconds(std::uint64_t ticks) const {
    return static_cast<std::uint64_t>(
        std::llround(static_cast<long double>(ticks) * 1'000'000.0L /
                     static_cast<long double>(frequency_.QuadPart)));
  }

  std::uint64_t seconds_to_ticks(std::uint64_t seconds) const {
    return seconds * static_cast<std::uint64_t>(frequency_.QuadPart);
  }

 private:
  LARGE_INTEGER frequency_{};
};

std::uint64_t percentile(std::vector<std::uint64_t> values, std::uint64_t numerator) {
  if (values.empty()) return 0;
  std::sort(values.begin(), values.end());
  const std::size_t index = static_cast<std::size_t>(
      (values.size() * numerator + 99U) / 100U - 1U);
  return values[index];
}

struct Metrics {
  std::uint64_t acquired{};
  std::uint64_t submitted{};
  std::uint64_t completed{};
  std::uint64_t dropped_pool_full{};
  std::uint64_t timeouts{};
  std::uint64_t protected_content_masked{};
  std::uint64_t max_in_flight{};
  std::vector<std::uint64_t> availability_to_submit_ticks;
  std::vector<std::uint64_t> lease_hold_ticks;
  std::vector<std::uint64_t> availability_to_completion_ticks;
};

struct OwnedSlot {
  ComPtr<ID3D11Texture2D> bgra;
  ComPtr<ID3D11Texture2D> nv12;
  ComPtr<ID3D11VideoProcessorInputView> input_view;
  ComPtr<ID3D11VideoProcessorOutputView> output_view;
  ComPtr<ID3D11Query> completion_query;
  bool in_flight{};
  std::uint64_t available_ticks{};
};

class OwnedNv12Pool final {
 public:
  OwnedNv12Pool(ID3D11Device* device,
                ID3D11DeviceContext* context,
                D3D_FEATURE_LEVEL feature_level,
                const D3D11_TEXTURE2D_DESC& capture_desc,
                Metrics* metrics,
                const Clock* clock)
      : device_(device), context_(context), metrics_(metrics), clock_(clock) {
    if (feature_level < D3D_FEATURE_LEVEL_11_0) {
      throw std::runtime_error("D3D11 query completion proof requires feature level 11_0 or newer");
    }
    if (capture_desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM || capture_desc.Width == 0 ||
        capture_desc.Height == 0 || capture_desc.Width % 2 != 0 || capture_desc.Height % 2 != 0) {
      throw std::runtime_error("benchmark supports only even-sized SDR BGRA capture surfaces");
    }
    capture_desc_ = capture_desc;
    capture_desc_.MipLevels = 1;
    capture_desc_.ArraySize = 1;
    capture_desc_.SampleDesc.Count = 1;
    capture_desc_.SampleDesc.Quality = 0;
    capture_desc_.Usage = D3D11_USAGE_DEFAULT;
    capture_desc_.BindFlags = D3D11_BIND_RENDER_TARGET;
    capture_desc_.CPUAccessFlags = 0;
    capture_desc_.MiscFlags = 0;

    check(device_->QueryInterface(IID_PPV_ARGS(&video_device_)), "Query ID3D11VideoDevice");
    check(context_->QueryInterface(IID_PPV_ARGS(&video_context_)), "Query ID3D11VideoContext");

    D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
    content.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
    content.InputWidth = capture_desc_.Width;
    content.InputHeight = capture_desc_.Height;
    content.OutputWidth = capture_desc_.Width;
    content.OutputHeight = capture_desc_.Height;
    content.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
    check(video_device_->CreateVideoProcessorEnumerator(&content, &enumerator_),
          "CreateVideoProcessorEnumerator");
    latencydesk::check_video_processor_format_support(enumerator_.Get());
    check(video_device_->CreateVideoProcessor(enumerator_.Get(), 0, &processor_),
          "CreateVideoProcessor");
    latencydesk::configure_video_processor_sdr_color_space(
        video_context_.Get(), processor_.Get(), capture_desc_.Width, capture_desc_.Height);
    slots_.reserve(kOwnedPoolSlots);
    for (std::size_t index = 0; index < kOwnedPoolSlots; ++index) {
      slots_.push_back(create_slot());
    }
  }
  [[nodiscard]] bool matches(const D3D11_TEXTURE2D_DESC& capture_desc) const {
    return capture_desc.Format == DXGI_FORMAT_B8G8R8A8_UNORM &&
           capture_desc.Width == capture_desc_.Width &&
           capture_desc.Height == capture_desc_.Height &&
           capture_desc.MipLevels == 1 && capture_desc.ArraySize == 1 &&
           capture_desc.SampleDesc.Count == 1;
  }


  void collect_completed() {
    for (std::size_t index = 0; index < slots_.size(); ++index) {
      OwnedSlot& slot = slots_[index];
      if (!slot.in_flight) continue;
      const HRESULT result = context_->GetData(slot.completion_query.Get(), nullptr, 0,
                                               D3D11_ASYNC_GETDATA_DONOTFLUSH);
      if (result == S_FALSE) continue;
      check(result, "GetData completion query");
      complete_slot(index);
    }
  }

  [[nodiscard]] std::optional<std::size_t> reserve_slot() {
    collect_completed();
    const auto slot_index = next_available_slot();
    if (!slot_index) {
      ++metrics_->dropped_pool_full;
      return std::nullopt;
    }
    return slot_index;
  }

  void submit(std::size_t slot_index,
              ID3D11Texture2D* capture_surface,
              std::uint64_t available_ticks) {
    if (slot_index >= slots_.size() || slots_[slot_index].in_flight) {
      throw std::logic_error("capture submission slot");
    }
    OwnedSlot& slot = slots_[slot_index];
    context_->CopyResource(slot.bgra.Get(), capture_surface);
    D3D11_VIDEO_PROCESSOR_STREAM stream{};
    stream.Enable = TRUE;
    stream.pInputSurface = slot.input_view.Get();
    check(video_context_->VideoProcessorBlt(processor_.Get(), slot.output_view.Get(), 0, 1, &stream),
          "VideoProcessorBlt");
    context_->End(slot.completion_query.Get());
    context_->Flush();
    slot.available_ticks = available_ticks;
    slot.in_flight = true;
    ++metrics_->submitted;
    metrics_->availability_to_submit_ticks.push_back(clock_->now() - available_ticks);
    metrics_->max_in_flight = (std::max)(metrics_->max_in_flight, in_flight_count());
  }

  void wait_for_completion(std::size_t slot_index, std::uint64_t timeout_ticks) {
    if (slot_index >= slots_.size()) throw std::out_of_range("completion slot");
    const std::uint64_t deadline = clock_->now() + timeout_ticks;
    while (slots_[slot_index].in_flight) {
      const HRESULT result = context_->GetData(slots_[slot_index].completion_query.Get(), nullptr, 0,
                                               D3D11_ASYNC_GETDATA_DONOTFLUSH);
      if (result == S_FALSE) {
        if (clock_->now() >= deadline) {
          throw std::runtime_error("capture lease completion timeout");
        }
        Sleep(1);
        continue;
      }
      check(result, "GetData completion query");
      complete_slot(slot_index);
    }
  }

  void drain(std::uint64_t timeout_ticks) {
    const std::uint64_t deadline = clock_->now() + timeout_ticks;
    while (in_flight_count() != 0) {
      collect_completed();
      if (in_flight_count() == 0) return;
      if (clock_->now() >= deadline) {
        throw std::runtime_error("owned NV12 pool completion timeout");
      }
      Sleep(1);
    }
  }

  std::uint64_t checksum_last_completed() {
    if (last_completed_slot_ >= slots_.size()) {
      throw std::runtime_error("no completed NV12 surface available for checksum");
    }
    D3D11_TEXTURE2D_DESC staging_desc{};
    slots_[last_completed_slot_].nv12->GetDesc(&staging_desc);
    staging_desc.Usage = D3D11_USAGE_STAGING;
    staging_desc.BindFlags = 0;
    staging_desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    staging_desc.MiscFlags = 0;
    ComPtr<ID3D11Texture2D> staging;
    check(device_->CreateTexture2D(&staging_desc, nullptr, &staging), "Create checksum staging texture");
    context_->CopyResource(staging.Get(), slots_[last_completed_slot_].nv12.Get());
    context_->Flush();
    D3D11_MAPPED_SUBRESOURCE mapped{};
    check(context_->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped), "Map checksum staging texture");
    std::uint64_t checksum = 0xcbf29ce484222325ULL;
    const auto* bytes = static_cast<const std::uint8_t*>(mapped.pData);
    const UINT rows = staging_desc.Height + staging_desc.Height / 2;
    for (UINT row = 0; row < rows; ++row) {
      const auto* line = bytes + static_cast<std::size_t>(row) * mapped.RowPitch;
      for (UINT column = 0; column < staging_desc.Width; ++column) {
        checksum ^= line[column];
        checksum *= 0x100000001b3ULL;
      }
    }
    context_->Unmap(staging.Get(), 0);
    return checksum;
  }

 private:
  OwnedSlot create_slot() {
    OwnedSlot slot;
    check(device_->CreateTexture2D(&capture_desc_, nullptr, &slot.bgra), "Create owned BGRA texture");

    D3D11_TEXTURE2D_DESC nv12_desc = capture_desc_;
    nv12_desc.Format = DXGI_FORMAT_NV12;
    nv12_desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    check(device_->CreateTexture2D(&nv12_desc, nullptr, &slot.nv12), "Create owned NV12 texture");

    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input_desc{};
    input_desc.FourCC = 0;
    input_desc.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
    input_desc.Texture2D.MipSlice = 0;
    check(video_device_->CreateVideoProcessorInputView(slot.bgra.Get(), enumerator_.Get(), &input_desc,
                                                        &slot.input_view),
          "CreateVideoProcessorInputView");

    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output_desc{};
    output_desc.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
    output_desc.Texture2D.MipSlice = 0;
    check(video_device_->CreateVideoProcessorOutputView(slot.nv12.Get(), enumerator_.Get(), &output_desc,
                                                         &slot.output_view),
          "CreateVideoProcessorOutputView");

    D3D11_QUERY_DESC query_desc{};
    query_desc.Query = D3D11_QUERY_EVENT;
    check(device_->CreateQuery(&query_desc, &slot.completion_query), "Create completion query");
    return slot;
  }

  void complete_slot(std::size_t index) {
    OwnedSlot& slot = slots_[index];
    slot.in_flight = false;
    ++metrics_->completed;
    metrics_->availability_to_completion_ticks.push_back(clock_->now() - slot.available_ticks);
    last_completed_slot_ = index;
  }

  [[nodiscard]] std::optional<std::size_t> next_available_slot() {
    for (std::size_t offset = 0; offset < slots_.size(); ++offset) {
      const std::size_t index = (next_slot_ + offset) % slots_.size();
      if (!slots_[index].in_flight) {
        next_slot_ = (index + 1) % slots_.size();
        return index;
      }
    }
    return std::nullopt;
  }

  std::uint64_t in_flight_count() const {
    return static_cast<std::uint64_t>(std::count_if(
        slots_.begin(), slots_.end(), [](const OwnedSlot& slot) { return slot.in_flight; }));
  }

  ID3D11Device* device_{};
  ID3D11DeviceContext* context_{};
  Metrics* metrics_{};
  const Clock* clock_{};
  D3D11_TEXTURE2D_DESC capture_desc_{};
  ComPtr<ID3D11VideoDevice> video_device_;
  ComPtr<ID3D11VideoContext> video_context_;
  ComPtr<ID3D11VideoProcessorEnumerator> enumerator_;
  ComPtr<ID3D11VideoProcessor> processor_;
  std::vector<OwnedSlot> slots_;
  std::size_t next_slot_{};
  std::size_t last_completed_slot_{kOwnedPoolSlots};
};

struct DeviceBundle {
  ComPtr<IDXGIAdapter1> adapter;
  ComPtr<IDXGIOutput> output;
  DXGI_OUTPUT_DESC output_desc{};
  DXGI_COLOR_SPACE_TYPE display_color_space{DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709};
  ComPtr<ID3D11Device> device;
  ComPtr<ID3D11DeviceContext> context;
  D3D_FEATURE_LEVEL feature_level{};
};

DeviceBundle create_device(UINT adapter_index, UINT output_index) {
  DeviceBundle bundle;
  ComPtr<IDXGIFactory1> factory;
  check(CreateDXGIFactory1(IID_PPV_ARGS(&factory)), "CreateDXGIFactory1");
  check(factory->EnumAdapters1(adapter_index, &bundle.adapter), "EnumAdapters1");
  check(bundle.adapter->EnumOutputs(output_index, &bundle.output), "EnumOutputs");
  check(bundle.output->GetDesc(&bundle.output_desc), "IDXGIOutput::GetDesc");
  latencydesk::validate_output_rotation(bundle.output_desc.Rotation);
  bundle.display_color_space = latencydesk::query_output_color_space(bundle.output.Get());
  latencydesk::validate_display_color_space(bundle.display_color_space);
  UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
#ifndef NDEBUG
  flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif
  check(D3D11CreateDevice(bundle.adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, nullptr, 0,
                          D3D11_SDK_VERSION, &bundle.device, &bundle.feature_level, &bundle.context),
        "D3D11CreateDevice");
  return bundle;
}

bool should_stop(const Metrics& metrics, const Clock& clock, std::uint64_t begin_ticks,
                 const Options& options) {
  if (options.duration_seconds != 0) {
    return clock.now() - begin_ticks >= clock.seconds_to_ticks(options.duration_seconds);
  }
  return metrics.acquired >= options.frames;
}

std::uint64_t wall_deadline(const Clock& clock, std::uint64_t begin_ticks, const Options& options) {
  const std::uint64_t seconds = options.max_wall_seconds != 0
                                    ? options.max_wall_seconds
                                    : (options.duration_seconds != 0 ? options.duration_seconds + 60U
                                                                      : 600U);
  return begin_ticks + clock.seconds_to_ticks(seconds);
}

std::uint64_t run_desktop_duplication(const DeviceBundle& device,
                                      const Options& options,
                                      const Clock& clock,
                                      Metrics* metrics,
                                      std::unique_ptr<OwnedNv12Pool>* pool) {
  ComPtr<IDXGIOutput1> output1;
  check(device.output.As(&output1), "Query IDXGIOutput1");
  ComPtr<IDXGIOutputDuplication> duplication;
  check(output1->DuplicateOutput(device.device.Get(), &duplication), "DuplicateOutput");
  latencydesk::validate_duplication(duplication.Get());
  const std::uint64_t begin_ticks = clock.now();
  const std::uint64_t deadline = wall_deadline(clock, begin_ticks, options);
  while (!should_stop(*metrics, clock, begin_ticks, options)) {
    if (clock.now() >= deadline) throw std::runtime_error("capture wall-clock deadline exceeded");
    if (*pool) (*pool)->collect_completed();
    DXGI_OUTDUPL_FRAME_INFO info{};
    ComPtr<IDXGIResource> resource;
    const HRESULT result = duplication->AcquireNextFrame(options.timeout_ms, &info, &resource);
    if (result == DXGI_ERROR_WAIT_TIMEOUT) {
      ++metrics->timeouts;
      if (metrics->timeouts > options.max_timeouts) {
        throw std::runtime_error("DDA timeout budget exhausted before capture target");
      }
      continue;
    }
    if (result == DXGI_ERROR_ACCESS_LOST) {
      throw std::runtime_error("DXGI_ERROR_ACCESS_LOST; recreate the capture backend");
    }
    check(result, "AcquireNextFrame");
    if (info.ProtectedContentMaskedOut != FALSE) ++metrics->protected_content_masked;
    const std::uint64_t lease_begin = clock.now();
    struct Lease final {
      IDXGIOutputDuplication* duplication{};
      latencydesk::CaptureDetachState detach;
      bool acquired{true};
      ~Lease() {
        if (!acquired) return;
        if (!detach.release_permitted()) std::terminate();
        static_cast<void>(duplication->ReleaseFrame());
      }
      void native_work_started() noexcept { detach.native_work_started(); }
      void completion_proven() noexcept { detach.completion_proven(); }
      void release() {
        if (!detach.release_permitted()) std::terminate();
        const HRESULT result = duplication->ReleaseFrame();
        acquired = false;
        check(result, "ReleaseFrame");
      }
    } lease{duplication.Get()};

    ComPtr<ID3D11Texture2D> captured;
    check(resource.As(&captured), "Query DDA texture");
    D3D11_TEXTURE2D_DESC capture_desc{};
    captured->GetDesc(&capture_desc);
    if (!*pool) {
      *pool = std::make_unique<OwnedNv12Pool>(device.device.Get(), device.context.Get(),
                                              device.feature_level, capture_desc, metrics, &clock);
    } else if (!(*pool)->matches(capture_desc)) {
      throw std::runtime_error("DDA capture geometry changed; restart the benchmark");
    }
    const auto submitted_slot = (*pool)->reserve_slot();
    ++metrics->acquired;
    if (submitted_slot) {
      lease.native_work_started();
      (*pool)->submit(*submitted_slot, captured.Get(), lease_begin);
      (*pool)->wait_for_completion(*submitted_slot,
                                   clock.seconds_to_ticks(kCompletionTimeoutSeconds));
      lease.completion_proven();
    }
    metrics->lease_hold_ticks.push_back(clock.now() - lease_begin);
    lease.release();
  }
  (*pool)->drain(clock.seconds_to_ticks(kCompletionTimeoutSeconds));
  return clock.now() - begin_ticks;
}

Direct3D11::IDirect3DDevice wrap_device(ID3D11Device* device) {
  ComPtr<IDXGIDevice> dxgi_device;
  check(device->QueryInterface(IID_PPV_ARGS(&dxgi_device)), "Query IDXGIDevice");
  winrt::com_ptr<IInspectable> inspectable;
  check(CreateDirect3D11DeviceFromDXGIDevice(dxgi_device.Get(), inspectable.put()),
        "CreateDirect3D11DeviceFromDXGIDevice");
  return inspectable.as<Direct3D11::IDirect3DDevice>();
}

Capture::GraphicsCaptureItem create_monitor_item(HMONITOR monitor) {
  auto interop = winrt::get_activation_factory<Capture::GraphicsCaptureItem, IGraphicsCaptureItemInterop>();
  Capture::GraphicsCaptureItem item{nullptr};
  check(interop->CreateForMonitor(monitor, winrt::guid_of<Capture::GraphicsCaptureItem>(), winrt::put_abi(item)),
        "IGraphicsCaptureItemInterop::CreateForMonitor");
  return item;
}

ComPtr<ID3D11Texture2D> unwrap_surface(const Direct3D11::IDirect3DSurface& surface) {
  auto access = surface.as<Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
  ComPtr<ID3D11Texture2D> texture;
  check(access->GetInterface(IID_PPV_ARGS(&texture)), "IDirect3DDxgiInterfaceAccess::GetInterface");
  return texture;
}

std::uint64_t run_windows_graphics_capture(const DeviceBundle& device,
                                           const Options& options,
                                           const Clock& clock,
                                           Metrics* metrics,
                                           std::unique_ptr<OwnedNv12Pool>* pool) {
  if (!Capture::GraphicsCaptureSession::IsSupported()) {
    throw std::runtime_error("Windows Graphics Capture is not supported on this device");
  }
  const auto item = create_monitor_item(device.output_desc.Monitor);
  const auto size = item.Size();
  if (size.Width <= 0 || size.Height <= 0) throw std::runtime_error("WGC item has invalid size");
  const auto graphics_device = wrap_device(device.device.Get());
  auto frame_pool = Capture::Direct3D11CaptureFramePool::CreateFreeThreaded(
      graphics_device, WinRTDirectX::DirectXPixelFormat::B8G8R8A8UIntNormalized,
      static_cast<int>(kOwnedPoolSlots), size);
  auto session = frame_pool.CreateCaptureSession(item);
  latencydesk::CallbackGate callback_gate;

  std::mutex mutex;
  std::string callback_error;
  std::atomic<bool> finished{false};
  HANDLE complete_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (complete_event == nullptr) throw std::runtime_error("CreateEventW failed");
  const std::uint64_t begin_ticks = clock.now();
  const std::uint64_t deadline = wall_deadline(clock, begin_ticks, options);
  const auto token = frame_pool.FrameArrived([&](const auto& sender, const auto&) {
    const auto callback_lease = callback_gate.try_enter();
    if (!callback_lease) return;
    std::scoped_lock lock(mutex);
    if (finished.load(std::memory_order_relaxed)) return;
    Capture::Direct3D11CaptureFrame frame{nullptr};
    latencydesk::CaptureDetachState detach;
    try {
      frame = sender.TryGetNextFrame();
      const std::uint64_t lease_begin = clock.now();
      const ComPtr<ID3D11Texture2D> captured = unwrap_surface(frame.Surface());
      D3D11_TEXTURE2D_DESC capture_desc{};
      captured->GetDesc(&capture_desc);
      if (!*pool) {
        *pool = std::make_unique<OwnedNv12Pool>(device.device.Get(), device.context.Get(),
                                                device.feature_level, capture_desc, metrics, &clock);
      } else if (!(*pool)->matches(capture_desc)) {
        throw std::runtime_error("WGC capture geometry changed; restart the benchmark");
      }
      const auto submitted_slot = (*pool)->reserve_slot();
      ++metrics->acquired;
      if (submitted_slot) {
        detach.native_work_started();
        (*pool)->submit(*submitted_slot, captured.Get(), lease_begin);
        (*pool)->wait_for_completion(*submitted_slot,
                                     clock.seconds_to_ticks(kCompletionTimeoutSeconds));
        detach.completion_proven();
      }
      metrics->lease_hold_ticks.push_back(clock.now() - lease_begin);
      if (should_stop(*metrics, clock, begin_ticks, options)) {
        finished.store(true, std::memory_order_relaxed);
        SetEvent(complete_event);
      }
    } catch (const std::exception& error) {
      if (!detach.release_permitted()) std::terminate();
      callback_error = error.what();
      finished.store(true, std::memory_order_relaxed);
      SetEvent(complete_event);
    }
  });
  session.StartCapture();

  while (!finished.load(std::memory_order_relaxed)) {
    if (WaitForSingleObject(complete_event, 50) == WAIT_OBJECT_0) break;
    if (options.duration_seconds != 0 &&
        clock.now() - begin_ticks >= clock.seconds_to_ticks(options.duration_seconds)) {
      std::scoped_lock lock(mutex);
      finished.store(true, std::memory_order_relaxed);
      break;
    }
    if (clock.now() >= deadline) {
      std::scoped_lock lock(mutex);
      callback_error = "WGC wall-clock deadline exceeded";
      finished.store(true, std::memory_order_relaxed);
      break;
    }
  }

  {
    std::scoped_lock lock(mutex);
    finished.store(true, std::memory_order_relaxed);
  }
  callback_gate.close();
  frame_pool.FrameArrived(token);
  callback_gate.wait_for_drain();
  session.Close();
  std::string error;
  {
    std::scoped_lock lock(mutex);
    error = callback_error;
  }
  frame_pool.Close();
  CloseHandle(complete_event);
  if (!error.empty()) throw std::runtime_error(error);
  if (!*pool || metrics->acquired == 0) throw std::runtime_error("WGC produced no capture frames");
  (*pool)->drain(clock.seconds_to_ticks(kCompletionTimeoutSeconds));
  return clock.now() - begin_ticks;
}

void emit_report(Backend backend,
                 const Options& options,
                 const DeviceBundle& device,
                 const Clock& clock,
                 const Metrics& metrics,
                 OwnedNv12Pool& pool,
                 std::uint64_t elapsed_ticks) {
  const auto p50 = clock.microseconds(percentile(metrics.availability_to_submit_ticks, 50));
  const auto p95 = clock.microseconds(percentile(metrics.availability_to_submit_ticks, 95));
  const auto p99 = clock.microseconds(percentile(metrics.availability_to_submit_ticks, 99));
  const auto lease_p99 = clock.microseconds(percentile(metrics.lease_hold_ticks, 99));
  const auto completion_p99 = clock.microseconds(percentile(metrics.availability_to_completion_ticks, 99));
  const bool promotion_gate = options.duration_seconds >= 1800 && metrics.acquired > 0 &&
                              metrics.acquired == metrics.submitted &&
                              metrics.submitted == metrics.completed &&
                              metrics.dropped_pool_full == 0 && metrics.max_in_flight <= kOwnedPoolSlots;
  std::cout << "{\"experiment\":\"EXP-01\",\"backend\":\"" << backend_name(backend)
            << "\",\"adapter\":" << options.adapter << ",\"output\":" << options.output
            << ",\"rotation\":\"" << latencydesk::rotation_to_string(device.output_desc.Rotation) << "\""
            << ",\"display_color_space\":\"" << latencydesk::color_space_to_string(device.display_color_space) << "\""
            << ",\"owned_pool_slots\":" << kOwnedPoolSlots
            << ",\"owned_pool_format\":\"NV12\",\"same_adapter\":true"
            << ",\"copy_path\":\"CopyResource BGRA then D3D11 VideoProcessorBlt NV12\""
            << ",\"input_colorspace\":\"RGB_Full_0_255\""
            << ",\"output_colorspace\":\"NV12_Studio_BT709\""
            << ",\"capture_lease_release_proof\":\"D3D11_QUERY_EVENT completion before frame release\""
            << ",\"acquired_frames\":" << metrics.acquired;
  if (backend == Backend::kDesktopDuplication) {
    std::cout << ",\"protected_content_masked_frames\":" << metrics.protected_content_masked;
  }
  std::cout << ",\"submitted_frames\":" << metrics.submitted
            << ",\"completed_frames\":" << metrics.completed
            << ",\"pool_full_drops\":" << metrics.dropped_pool_full
            << ",\"timeouts\":" << metrics.timeouts
            << ",\"max_in_flight\":" << metrics.max_in_flight
            << ",\"capture_available_to_owned_nv12_submit_us\":{\"p50\":" << p50
            << ",\"p95\":" << p95 << ",\"p99\":" << p99 << "}"
            << ",\"encoder_submit_measured\":false"
            << ",\"lease_hold_us_p99\":" << lease_p99
            << ",\"availability_to_completion_observed_us_p99\":" << completion_p99
            << ",\"elapsed_ms\":" << clock.microseconds(elapsed_ticks) / 1000
            << ",\"nv12_checksum_last_completed\":" << pool.checksum_last_completed()
            << ",\"ownership_gate_passed\":" << std::boolalpha << promotion_gate
            << ",\"backend_ranking_eligible\":false"
            << ",\"note\":\"This ownership probe has no encoder submit timestamp. WGC monitor interop is explicit benchmark authorization, not product consent. P99 backend ranking requires matched 30-minute target-hardware capture-to-encoder runs.\"}\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) try {
  const Options options = parse(argc, argv);
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  winrt::init_apartment(winrt::apartment_type::multi_threaded);
  const Clock clock;
  const DeviceBundle device = create_device(options.adapter, options.output);
  Metrics metrics;
  std::unique_ptr<OwnedNv12Pool> pool;
  const std::uint64_t elapsed_ticks = options.backend == Backend::kDesktopDuplication
                                          ? run_desktop_duplication(device, options, clock, &metrics, &pool)
                                          : run_windows_graphics_capture(device, options, clock, &metrics, &pool);
  if (!pool || metrics.completed == 0) throw std::runtime_error("benchmark completed without an owned NV12 frame");
  emit_report(options.backend, options, device, clock, metrics, *pool, elapsed_ticks);
  return EXIT_SUCCESS;
} catch (const winrt::hresult_error& error) {
  std::wcerr << error.message().c_str() << L'\n';
  return EXIT_FAILURE;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return EXIT_FAILURE;
}
