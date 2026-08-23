#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_5.h>
#include <wrl/client.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace {

constexpr UINT kWidth = 640;
constexpr UINT kHeight = 360;
constexpr UINT kBackBufferCount = 2;
constexpr UINT kMaxFrames = 10'000;
constexpr DWORD kCompletionTimeoutMs = 2'000;

struct Options final {
  UINT frames = 1;
  UINT sync_interval = 0;
  bool allow_tearing = false;
};

struct ParsedOptions final {
  Options options;
  bool show_help = false;
};

struct Metrics final {
  UINT present_submissions = 0;
  UINT gpu_queue_completions = 0;
};

[[nodiscard]] std::string format_hresult(const HRESULT result) {
  std::ostringstream stream;
  stream << "0x" << std::uppercase << std::hex
         << static_cast<std::uint32_t>(result);
  return stream.str();
}

void check(const HRESULT result, const char* operation) {
  if (FAILED(result)) {
    throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                             format_hresult(result));
  }
}

void check_win32(const BOOL result, const char* operation) {
  if (result == FALSE) {
    throw std::runtime_error(std::string(operation) + " failed, GetLastError=" +
                             std::to_string(GetLastError()));
  }
}

[[nodiscard]] UINT parse_uint(const wchar_t* raw, const char* option) {
  if (*raw == L'\0') {
    throw std::runtime_error(std::string(option) + " requires an unsigned integer");
  }
  std::uint64_t value = 0;
  for (const wchar_t* cursor = raw; *cursor != L'\0'; ++cursor) {
    if (*cursor < L'0' || *cursor > L'9') {
      throw std::runtime_error(std::string(option) + " requires an unsigned integer");
    }
    value = value * 10 + static_cast<std::uint64_t>(*cursor - L'0');
    if (value > std::numeric_limits<UINT>::max()) {
      throw std::runtime_error(std::string(option) + " is out of range");
    }
  }
  return static_cast<UINT>(value);
}

void print_usage() {
  std::cout
      << "Usage: latencydesk_win_d3d11_present_probe [--frames N] "
         "[--sync-interval 0|1] [--allow-tearing]\n"
         "Runs a visible synthetic NV12 -> D3D11 video processor -> "
         "flip-model swap-chain probe.\n"
         "It records Present submission and a D3D11 GPU queue completion; "
         "it does not measure scanout latency.\n";
}

[[nodiscard]] ParsedOptions parse_options(const int argc, wchar_t* argv[]) {
  ParsedOptions parsed;
  for (int index = 1; index < argc; ++index) {
    const std::wstring_view argument(argv[index]);
    if (argument == L"--help") {
      parsed.show_help = true;
      continue;
    }
    if (argument == L"--frames") {
      if (++index == argc) {
        throw std::runtime_error("--frames requires a value");
      }
      parsed.options.frames = parse_uint(argv[index], "--frames");
      continue;
    }
    if (argument == L"--sync-interval") {
      if (++index == argc) {
        throw std::runtime_error("--sync-interval requires a value");
      }
      parsed.options.sync_interval = parse_uint(argv[index], "--sync-interval");
      continue;
    }
    if (argument == L"--allow-tearing") {
      parsed.options.allow_tearing = true;
      continue;
    }
    throw std::runtime_error("unknown option");
  }
  if (parsed.show_help) {
    return parsed;
  }
  if (parsed.options.frames == 0 || parsed.options.frames > kMaxFrames) {
    throw std::runtime_error("--frames must be in the range [1, 10000]");
  }
  if (parsed.options.sync_interval > 1) {
    throw std::runtime_error("--sync-interval must be 0 or 1");
  }
  if (parsed.options.allow_tearing && parsed.options.sync_interval != 0) {
    throw std::runtime_error("--allow-tearing requires --sync-interval 0");
  }
  return parsed;
}

void enable_per_monitor_dpi() {
  if (SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) !=
      FALSE) {
    return;
  }
  const DWORD error = GetLastError();
  if (error != ERROR_ACCESS_DENIED) {
    throw std::runtime_error(
        "SetProcessDpiAwarenessContext failed, GetLastError=" +
        std::to_string(error));
  }
  if (GetThreadDpiAwarenessContext() !=
      DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) {
    throw std::runtime_error(
        "process DPI awareness is already configured without per-monitor-v2");
  }
}

LRESULT CALLBACK window_proc(const HWND window, const UINT message,
                             const WPARAM wparam, const LPARAM lparam) {
  switch (message) {
    case WM_CLOSE:
      DestroyWindow(window);
      return 0;
    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(window, message, wparam, lparam);
  }
}

class ProbeWindow final {
 public:
  ProbeWindow() {
    WNDCLASSW window_class{};
    window_class.lpfnWndProc = window_proc;
    window_class.hInstance = GetModuleHandleW(nullptr);
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.lpszClassName = kClassName;
    const ATOM atom = RegisterClassW(&window_class);
    if (atom == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
      check_win32(FALSE, "RegisterClassW");
    }

    RECT client_rect{0, 0, static_cast<LONG>(kWidth), static_cast<LONG>(kHeight)};
    check_win32(AdjustWindowRectEx(&client_rect, kStyle, FALSE, 0),
                "AdjustWindowRectEx");
    window_ = CreateWindowExW(0, kClassName, L"LatencyDesk D3D11 Present Probe",
                              kStyle, CW_USEDEFAULT, CW_USEDEFAULT,
                              client_rect.right - client_rect.left,
                              client_rect.bottom - client_rect.top, nullptr, nullptr,
                              window_class.hInstance, nullptr);
    if (window_ == nullptr) {
      check_win32(FALSE, "CreateWindowExW");
    }
  }

  ProbeWindow(const ProbeWindow&) = delete;
  ProbeWindow& operator=(const ProbeWindow&) = delete;

  ~ProbeWindow() {
    if (window_ != nullptr) {
      DestroyWindow(window_);
    }
  }

  void show() const {
    ShowWindow(window_, SW_SHOW);
    UpdateWindow(window_);
  }

  [[nodiscard]] HWND get() const noexcept { return window_; }

 private:
  static constexpr wchar_t kClassName[] = L"LatencyDeskPresentProbe";
  static constexpr DWORD kStyle = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;

  HWND window_ = nullptr;
};

[[nodiscard]] bool pump_messages() {
  MSG message{};
  while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
    if (message.message == WM_QUIT) {
      return false;
    }
    TranslateMessage(&message);
    DispatchMessageW(&message);
  }
  return true;
}

class WaitableHandle final {
 public:
  WaitableHandle() = default;
  WaitableHandle(const WaitableHandle&) = delete;
  WaitableHandle& operator=(const WaitableHandle&) = delete;

  ~WaitableHandle() {
    if (value_ != nullptr) {
      CloseHandle(value_);
    }
  }

  void reset(const HANDLE value) {
    if (value == nullptr || value == INVALID_HANDLE_VALUE) {
      throw std::runtime_error("GetFrameLatencyWaitableObject failed");
    }
    if (value_ != nullptr) {
      CloseHandle(value_);
    }
    value_ = value;
  }

  [[nodiscard]] HANDLE get() const noexcept { return value_; }

 private:
  HANDLE value_ = nullptr;
};

[[nodiscard]] std::vector<std::uint8_t> synthetic_nv12() {
  const std::size_t luma_bytes = static_cast<std::size_t>(kWidth) * kHeight;
  std::vector<std::uint8_t> pixels(luma_bytes + luma_bytes / 2);
  for (UINT y = 0; y < kHeight; ++y) {
    for (UINT x = 0; x < kWidth; ++x) {
      const UINT checker = ((x / 64) + (y / 64)) % 2;
      pixels[static_cast<std::size_t>(y) * kWidth + x] =
          static_cast<std::uint8_t>(checker == 0 ? 64 : 192);
    }
  }
  std::uint8_t* const chroma = pixels.data() + luma_bytes;
  for (UINT y = 0; y < kHeight / 2; ++y) {
    for (UINT x = 0; x < kWidth; x += 2) {
      const UINT checker = ((x / 64) + (y / 32)) % 2;
      chroma[static_cast<std::size_t>(y) * kWidth + x] =
          static_cast<std::uint8_t>(checker == 0 ? 90 : 166);
      chroma[static_cast<std::size_t>(y) * kWidth + x + 1] =
          static_cast<std::uint8_t>(checker == 0 ? 240 : 16);
    }
  }
  return pixels;
}

[[nodiscard]] const char* feature_level_name(const D3D_FEATURE_LEVEL level) {
  switch (level) {
    case D3D_FEATURE_LEVEL_11_1:
      return "11_1";
    case D3D_FEATURE_LEVEL_11_0:
      return "11_0";
    default:
      return "unsupported";
  }
}

class Presenter final {
 public:
  Presenter(const HWND window, const Options options) : options_(options) {
    create_device();
    create_swap_chain(window);
    create_video_processor();
    create_completion_query();
  }

  Presenter(const Presenter&) = delete;
  Presenter& operator=(const Presenter&) = delete;

  void present_one() {
    wait_for_frame_slot();
    if (!pump_messages()) {
      throw std::runtime_error("presentation window closed");
    }
    const UINT back_buffer_index = swap_chain3_->GetCurrentBackBufferIndex();
    if (back_buffer_index >= output_views_.size()) {
      throw std::runtime_error("GetCurrentBackBufferIndex returned an invalid index");
    }

    D3D11_VIDEO_PROCESSOR_STREAM stream{};
    stream.Enable = TRUE;
    stream.OutputIndex = 0;
    stream.InputFrameOrField = 0;
    stream.pInputSurface = input_view_.Get();
    check(video_context_->VideoProcessorBlt(video_processor_.Get(),
                                            output_views_[back_buffer_index].Get(), 0,
                                            1, &stream),
          "VideoProcessorBlt");
    context_->End(completion_query_.Get());

    const UINT present_flags =
        options_.allow_tearing ? DXGI_PRESENT_ALLOW_TEARING : 0;
    const HRESULT present_result =
        swap_chain_->Present(options_.sync_interval, present_flags);
    if (present_result == DXGI_STATUS_OCCLUDED) {
      throw std::runtime_error("Present reported DXGI_STATUS_OCCLUDED");
    }
    check(present_result, "Present");
    ++metrics_.present_submissions;
    wait_for_gpu_completion();
    ++metrics_.gpu_queue_completions;
  }

  [[nodiscard]] const Metrics& metrics() const noexcept { return metrics_; }
  [[nodiscard]] bool tearing_supported() const noexcept {
    return tearing_supported_;
  }
  [[nodiscard]] D3D_FEATURE_LEVEL feature_level() const noexcept {
    return feature_level_;
  }
  [[nodiscard]] LUID adapter_luid() const noexcept { return adapter_luid_; }

 private:
  void create_device() {
    constexpr std::array<D3D_FEATURE_LEVEL, 2> kRequiredLevels{
        D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    check(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                            kRequiredLevels.data(),
                            static_cast<UINT>(kRequiredLevels.size()),
                            D3D11_SDK_VERSION, &device_, &feature_level_,
                            &context_),
          "D3D11CreateDevice");
    if (feature_level_ < D3D_FEATURE_LEVEL_11_0) {
      throw std::runtime_error("D3D11 feature level 11_0 is required");
    }
    check(device_.As(&video_device_), "Query ID3D11VideoDevice");
    check(context_.As(&video_context_), "Query ID3D11VideoContext");
  }

  void create_swap_chain(const HWND window) {
    ComPtr<IDXGIDevice> dxgi_device;
    check(device_.As(&dxgi_device), "Query IDXGIDevice");
    ComPtr<IDXGIAdapter> adapter;
    check(dxgi_device->GetAdapter(&adapter), "GetAdapter");
    DXGI_ADAPTER_DESC adapter_description{};
    check(adapter->GetDesc(&adapter_description), "IDXGIAdapter::GetDesc");
    adapter_luid_ = adapter_description.AdapterLuid;

    ComPtr<IDXGIFactory2> factory;
    check(adapter->GetParent(IID_PPV_ARGS(&factory)), "GetParent factory");
    check(factory->MakeWindowAssociation(window, DXGI_MWA_NO_ALT_ENTER),
          "MakeWindowAssociation");

    ComPtr<IDXGIFactory5> factory5;
    if (SUCCEEDED(factory.As(&factory5))) {
      BOOL allow_tearing = FALSE;
      if (SUCCEEDED(factory5->CheckFeatureSupport(
              DXGI_FEATURE_PRESENT_ALLOW_TEARING, &allow_tearing,
              sizeof(allow_tearing)))) {
        tearing_supported_ = allow_tearing == TRUE;
      }
    }
    if (options_.allow_tearing && !tearing_supported_) {
      throw std::runtime_error("--allow-tearing is unsupported by this system");
    }

    DXGI_SWAP_CHAIN_DESC1 description{};
    description.Width = kWidth;
    description.Height = kHeight;
    description.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    description.SampleDesc.Count = 1;
    description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    description.BufferCount = kBackBufferCount;
    description.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    description.Scaling = DXGI_SCALING_STRETCH;
    description.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
    description.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
    if (options_.allow_tearing) {
      description.Flags |= DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING;
    }
    check(factory->CreateSwapChainForHwnd(device_.Get(), window, &description,
                                          nullptr, nullptr, &swap_chain_),
          "CreateSwapChainForHwnd");
    ComPtr<IDXGISwapChain2> swap_chain2;
    check(swap_chain_.As(&swap_chain2), "Query IDXGISwapChain2");
    check(swap_chain2->SetMaximumFrameLatency(1), "SetMaximumFrameLatency");
    frame_latency_waitable_.reset(swap_chain2->GetFrameLatencyWaitableObject());
    check(swap_chain_.As(&swap_chain3_), "Query IDXGISwapChain3");
  }

  void create_video_processor() {
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC content_description{};
    content_description.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
    content_description.InputFrameRate.Numerator = 60;
    content_description.InputFrameRate.Denominator = 1;
    content_description.InputWidth = kWidth;
    content_description.InputHeight = kHeight;
    content_description.OutputFrameRate.Numerator = 60;
    content_description.OutputFrameRate.Denominator = 1;
    content_description.OutputWidth = kWidth;
    content_description.OutputHeight = kHeight;
    content_description.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
    check(video_device_->CreateVideoProcessorEnumerator(&content_description,
                                                         &video_enumerator_),
          "CreateVideoProcessorEnumerator");

    UINT input_support = 0;
    check(video_enumerator_->CheckVideoProcessorFormat(DXGI_FORMAT_NV12,
                                                        &input_support),
          "CheckVideoProcessorFormat NV12");
    if ((input_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT) == 0) {
      throw std::runtime_error("video processor does not support NV12 input");
    }
    UINT output_support = 0;
    check(video_enumerator_->CheckVideoProcessorFormat(
              DXGI_FORMAT_B8G8R8A8_UNORM, &output_support),
          "CheckVideoProcessorFormat BGRA");
    if ((output_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT) == 0) {
      throw std::runtime_error("video processor does not support BGRA output");
    }
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE input_color_space{};
    input_color_space.YCbCr_Matrix = 1;
    input_color_space.Nominal_Range =
        D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;
    video_context_->VideoProcessorSetStreamColorSpace(video_processor_.Get(), 0,
                                                       &input_color_space);
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE output_color_space{};
    output_color_space.RGB_Range = 0;
    video_context_->VideoProcessorSetOutputColorSpace(video_processor_.Get(),
                                                       &output_color_space);
    video_context_->VideoProcessorSetStreamFrameFormat(
        video_processor_.Get(), 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
    const RECT rect{0, 0, static_cast<LONG>(kWidth), static_cast<LONG>(kHeight)};
    video_context_->VideoProcessorSetStreamSourceRect(video_processor_.Get(), 0,
                                                       TRUE, &rect);
    video_context_->VideoProcessorSetStreamDestRect(video_processor_.Get(), 0,
                                                     TRUE, &rect);

    const std::vector<std::uint8_t> source_pixels = synthetic_nv12();
    D3D11_TEXTURE2D_DESC source_description{};
    source_description.Width = kWidth;
    source_description.Height = kHeight;
    source_description.MipLevels = 1;
    source_description.ArraySize = 1;
    source_description.Format = DXGI_FORMAT_NV12;
    source_description.SampleDesc.Count = 1;
    source_description.Usage = D3D11_USAGE_DEFAULT;
    D3D11_SUBRESOURCE_DATA source_data{};
    source_data.pSysMem = source_pixels.data();
    source_data.SysMemPitch = kWidth;
    source_data.SysMemSlicePitch = static_cast<UINT>(source_pixels.size());
    ComPtr<ID3D11Texture2D> source_texture;
    check(device_->CreateTexture2D(&source_description, &source_data,
                                   &source_texture),
          "CreateTexture2D NV12 source");

    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input_view_description{};
    input_view_description.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
    check(video_device_->CreateVideoProcessorInputView(
              source_texture.Get(), video_enumerator_.Get(), &input_view_description,
              &input_view_),
          "CreateVideoProcessorInputView");

    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output_view_description{};
    output_view_description.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
    for (UINT index = 0; index < kBackBufferCount; ++index) {
      ComPtr<ID3D11Texture2D> back_buffer;
      check(swap_chain_->GetBuffer(index, IID_PPV_ARGS(&back_buffer)),
            "GetBuffer");
      check(video_device_->CreateVideoProcessorOutputView(
                back_buffer.Get(), video_enumerator_.Get(),
                &output_view_description, &output_views_[index]),
            "CreateVideoProcessorOutputView");
    }
  }

  void create_completion_query() {
    D3D11_QUERY_DESC description{};
    description.Query = D3D11_QUERY_EVENT;
    check(device_->CreateQuery(&description, &completion_query_),
          "CreateQuery D3D11_QUERY_EVENT");
  }

  void wait_for_frame_slot() const {
    const DWORD result =
        WaitForSingleObject(frame_latency_waitable_.get(), kCompletionTimeoutMs);
    if (result == WAIT_OBJECT_0) {
      return;
    }
    if (result == WAIT_TIMEOUT) {
      throw std::runtime_error("frame latency wait timed out");
    }
    throw std::runtime_error(
        "WaitForSingleObject failed, GetLastError=" +
        std::to_string(GetLastError()));
  }

  void wait_for_gpu_completion() const {
    const ULONGLONG deadline = GetTickCount64() + kCompletionTimeoutMs;
    for (;;) {
      BOOL complete = FALSE;
      const HRESULT result =
          context_->GetData(completion_query_.Get(), &complete, sizeof(complete), 0);
      if (result == S_OK) {
        if (complete == FALSE) {
          throw std::runtime_error("D3D11_QUERY_EVENT returned an incomplete result");
        }
        return;
      }
      if (result != S_FALSE) {
        check(result, "GetData D3D11_QUERY_EVENT");
      }
      if (!pump_messages()) {
        throw std::runtime_error("presentation window closed");
      }
      if (GetTickCount64() >= deadline) {
        throw std::runtime_error("GPU completion query timed out");
      }
      Sleep(1);
    }
  }

  Options options_;
  Metrics metrics_;
  bool tearing_supported_ = false;
  D3D_FEATURE_LEVEL feature_level_{};
  LUID adapter_luid_{};
  ComPtr<ID3D11Device> device_;
  ComPtr<ID3D11DeviceContext> context_;
  ComPtr<ID3D11VideoDevice> video_device_;
  ComPtr<ID3D11VideoContext> video_context_;
  ComPtr<IDXGISwapChain1> swap_chain_;
  ComPtr<IDXGISwapChain3> swap_chain3_;
  ComPtr<ID3D11VideoProcessorEnumerator> video_enumerator_;
  ComPtr<ID3D11VideoProcessor> video_processor_;
  ComPtr<ID3D11VideoProcessorInputView> input_view_;
  std::array<ComPtr<ID3D11VideoProcessorOutputView>, kBackBufferCount>
      output_views_;
  ComPtr<ID3D11Query> completion_query_;
  WaitableHandle frame_latency_waitable_;
};

void print_result(const Options& options, const Presenter& presenter) {
  const Metrics& metrics = presenter.metrics();
  const LUID adapter_luid = presenter.adapter_luid();
  std::cout << std::boolalpha
            << "{\"backend\":\"d3d11_video_processor_flip_discard\","
               "\"source_format\":\"nv12\","
               "\"output_format\":\"bgra8\","
               "\"decode_performed\":false,"
               "\"synthetic_source_cpu_initialized\":true,"
               "\"per_frame_cpu_copy\":false,"
               "\"window_visible\":true,"
               "\"frames_requested\":"
            << options.frames << ",\"present_submissions\":"
            << metrics.present_submissions << ",\"gpu_queue_completions\":"
            << metrics.gpu_queue_completions
            << ",\"source_release_proof\":\"d3d11_query_event\","
               "\"frame_latency_waitable_object\":true,"
               "\"max_frame_latency\":1,\"sync_interval\":"
            << options.sync_interval << ",\"allow_tearing_requested\":"
            << options.allow_tearing << ",\"allow_tearing_supported\":"
            << presenter.tearing_supported() << ",\"feature_level\":\""
            << feature_level_name(presenter.feature_level())
            << "\",\"adapter_luid_low\":" << adapter_luid.LowPart
            << ",\"adapter_luid_high\":" << adapter_luid.HighPart
            << ",\"actual_scanout_latency_measured\":false}\n";
}

}  // namespace

int wmain(const int argc, wchar_t* argv[]) try {
  const ParsedOptions parsed = parse_options(argc, argv);
  if (parsed.show_help) {
    print_usage();
    return EXIT_SUCCESS;
  }

  enable_per_monitor_dpi();
  ProbeWindow window;
  window.show();
  Presenter presenter(window.get(), parsed.options);
  for (UINT frame = 0; frame < parsed.options.frames; ++frame) {
    if (!pump_messages()) {
      throw std::runtime_error("presentation window closed");
    }
    presenter.present_one();
  }
  print_result(parsed.options, presenter);
  return EXIT_SUCCESS;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return EXIT_FAILURE;
}
