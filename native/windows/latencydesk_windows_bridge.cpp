#include "latencydesk_windows_bridge.h"

#include "dda_capture_source.hpp"
#include "input_event_queue.hpp"
#include "mf_h264_encoder.hpp"

#include <windows.h>
#include <windowsx.h>
#include <werapi.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>


namespace latencydesk::windows_bridge {
BridgeStatus status_from_hresult(long status) noexcept {
  switch (static_cast<HRESULT>(status)) {
    case S_OK:
      return BridgeStatus::Ok;
    case DXGI_ERROR_WAIT_TIMEOUT:
      return BridgeStatus::NoFrame;
    case DXGI_ERROR_ACCESS_LOST:
      return BridgeStatus::AccessLost;
    case DXGI_ERROR_DEVICE_REMOVED:
    case DXGI_ERROR_DEVICE_RESET:
      return BridgeStatus::DeviceLost;
    case DXGI_ERROR_SESSION_DISCONNECTED:
      return BridgeStatus::SessionChanged;
    case E_ACCESSDENIED:
      return BridgeStatus::PermissionDenied;
    case E_INVALIDARG:
      return BridgeStatus::InvalidArgument;
    case DXGI_ERROR_INVALID_CALL:
      return BridgeStatus::InvalidState;
    case DXGI_ERROR_UNSUPPORTED:
      return BridgeStatus::Unsupported;
    default:
      return BridgeStatus::InternalFailure;
  }
}

BridgeStatus status_from_wer_hresult(long status) noexcept {
  const HRESULT hr = static_cast<HRESULT>(status);
  if (SUCCEEDED(hr) || hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) {
    return BridgeStatus::Ok;
  }
  if (hr == E_ACCESSDENIED) return BridgeStatus::PermissionDenied;
  if (hr == E_INVALIDARG) return BridgeStatus::InvalidArgument;
  if (hr == HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)) {
    return BridgeStatus::Unsupported;
  }
  return BridgeStatus::InternalFailure;
}

namespace {
[[nodiscard]] std::optional<std::wstring> current_executable_leaf_name() noexcept {
  std::array<wchar_t, 32'768> image_path{};
  const auto length = GetModuleFileNameW(
      nullptr, image_path.data(), static_cast<DWORD>(image_path.size()));
  if (length == 0 || length >= image_path.size()) return std::nullopt;

  const std::wstring_view path(image_path.data(), length);
  const auto separator = path.find_last_of(L"\\/");
  const auto executable_name = path.substr(separator == std::wstring_view::npos ? 0 : separator + 1);
  if (executable_name.empty()) return std::nullopt;
  return std::wstring(executable_name);
}

std::mutex process_security_mutex;
bool process_wer_excluded{};

template <typename Operation>
[[nodiscard]] std::uint32_t invoke_status(Operation&& operation) noexcept {
  try {
    return status_code(std::forward<Operation>(operation)());
  } catch (const latencydesk::DdaError& error) {
    return status_code(status_from_hresult(error.status()));
  } catch (const std::bad_alloc&) {
    return status_code(BridgeStatus::QueueFull);
  } catch (const std::invalid_argument&) {
    return status_code(BridgeStatus::InvalidArgument);
  } catch (const std::logic_error&) {
    return status_code(BridgeStatus::InvalidState);
  } catch (...) {
    return status_code(BridgeStatus::InternalFailure);
  }
}

struct PendingFrame final {
  D3D11_TEXTURE2D_DESC description{};
  latencydesk::DdaFrameMetadata metadata;
};

}  // namespace

class SurfaceImpl final {
 public:
  SurfaceImpl(latencydesk::D3d11OwnedFrame frame, latencydesk::DdaFrameMetadata metadata)
      : frame_(std::move(frame)), metadata_(std::move(metadata)) {}

  [[nodiscard]] std::uint32_t width() const noexcept {
    return frame_.description().Width;
  }

  [[nodiscard]] std::uint32_t height() const noexcept {
    return frame_.description().Height;
  }

  [[nodiscard]] std::uint32_t format() const noexcept {
    return static_cast<std::uint32_t>(frame_.description().Format);
  }

  [[nodiscard]] ID3D11Texture2D* texture() const noexcept {
    return frame_.texture();
  }
 private:
  latencydesk::D3d11OwnedFrame frame_;
  latencydesk::DdaFrameMetadata metadata_;
};

Surface::Surface(std::unique_ptr<SurfaceImpl> impl) : impl_(std::move(impl)) {}

Surface::~Surface() = default;

std::uint32_t Surface::width() const noexcept { return impl_->width(); }

std::uint32_t Surface::height() const noexcept { return impl_->height(); }

std::uint32_t Surface::format() const noexcept { return impl_->format(); }

class EncoderImpl final {
 public:
  EncoderImpl(std::uint32_t adapter_index, std::uint32_t width, std::uint32_t height,
              std::uint32_t target_bitrate_bps, std::uint32_t fps, std::uint32_t max_queue_depth)
      : encoder_(adapter_index, width, height, target_bitrate_bps, fps, max_queue_depth) {}

  [[nodiscard]] BridgeStatus encode(const Surface& surface, std::uint64_t capture_sequence, std::uint64_t timestamp_ns) {
    std::scoped_lock lock(mutex_);
    if (surface.impl_ == nullptr || surface.impl_->texture() == nullptr) {
      return BridgeStatus::InvalidArgument;
    }
    auto status = encoder_.encode_frame(surface.impl_->texture(), capture_sequence, timestamp_ns);
    return map_mf_status(status);
  }

  [[nodiscard]] BridgeStatus poll_output(std::uint8_t* output_buffer, std::size_t buffer_capacity,
                                         std::size_t& output_size, bool& is_keyframe,
                                         std::uint64_t& capture_sequence, std::uint64_t& timestamp_ns) {
    std::scoped_lock lock(mutex_);
    std::optional<latencydesk::MfEncodedPacket> packet;
    auto status = encoder_.poll_output(packet);
    if (status == latencydesk::MfEncoderStatus::Ok && packet.has_value()) {
      if (packet->data.size() > buffer_capacity) {
        return BridgeStatus::InvalidArgument;
      }
      std::memcpy(output_buffer, packet->data.data(), packet->data.size());
      output_size = packet->data.size();
      is_keyframe = packet->is_keyframe;
      capture_sequence = packet->capture_sequence;
      timestamp_ns = packet->timestamp_ns;
      return BridgeStatus::Ok;
    }
    return map_mf_status(status);
  }

  [[nodiscard]] BridgeStatus request_idr() {
    std::scoped_lock lock(mutex_);
    return map_mf_status(encoder_.request_idr());
  }

  [[nodiscard]] BridgeStatus update_bitrate(std::uint32_t target_bitrate_bps) {
    std::scoped_lock lock(mutex_);
    return map_mf_status(encoder_.update_bitrate(target_bitrate_bps));
  }

  [[nodiscard]] BridgeStatus drain() {
    std::scoped_lock lock(mutex_);
    return map_mf_status(encoder_.drain());
  }

  [[nodiscard]] BridgeStatus quiesce() noexcept {
    std::scoped_lock lock(mutex_);
    return map_mf_status(encoder_.quiesce());
  }

 private:
  static BridgeStatus map_mf_status(latencydesk::MfEncoderStatus status) noexcept {
    switch (status) {
      case latencydesk::MfEncoderStatus::Ok:
        return BridgeStatus::Ok;
      case latencydesk::MfEncoderStatus::NoOutput:
        return BridgeStatus::NoFrame;
      case latencydesk::MfEncoderStatus::QueueFull:
        return BridgeStatus::QueueFull;
      case latencydesk::MfEncoderStatus::Unsupported:
        return BridgeStatus::Unsupported;
      case latencydesk::MfEncoderStatus::InvalidState:
        return BridgeStatus::InvalidState;
      case latencydesk::MfEncoderStatus::InvalidArgument:
        return BridgeStatus::InvalidArgument;
      case latencydesk::MfEncoderStatus::DeviceLost:
        return BridgeStatus::DeviceLost;
      default:
        return BridgeStatus::InternalFailure;
    }
  }

  std::mutex mutex_;
  latencydesk::MfH264Encoder encoder_;
};

Encoder::Encoder(std::uint32_t adapter_index, std::uint32_t width, std::uint32_t height,
                 std::uint32_t target_bitrate_bps, std::uint32_t fps, std::uint32_t max_queue_depth)
    : impl_(std::make_unique<EncoderImpl>(adapter_index, width, height, target_bitrate_bps, fps, max_queue_depth)) {}

Encoder::~Encoder() = default;

BridgeStatus Encoder::encode(const Surface& surface, std::uint64_t capture_sequence, std::uint64_t timestamp_ns) {
  return impl_->encode(surface, capture_sequence, timestamp_ns);
}

BridgeStatus Encoder::poll_output(std::uint8_t* output_buffer, std::size_t buffer_capacity,
                                  std::size_t& output_size, bool& is_keyframe,
                                  std::uint64_t& capture_sequence, std::uint64_t& timestamp_ns) {
  return impl_->poll_output(output_buffer, buffer_capacity, output_size, is_keyframe, capture_sequence, timestamp_ns);
}

BridgeStatus Encoder::request_idr() { return impl_->request_idr(); }
BridgeStatus Encoder::update_bitrate(std::uint32_t target_bitrate_bps) { return impl_->update_bitrate(target_bitrate_bps); }
BridgeStatus Encoder::drain() { return impl_->drain(); }
BridgeStatus Encoder::quiesce() noexcept { return impl_->quiesce(); }

class RendererImpl final {
 public:
  static constexpr std::size_t kInputEventBytes = 20;

  RendererImpl(std::uint32_t width, std::uint32_t height)
      : width_(width == 0 ? 1920 : width), height_(height == 0 ? 1080 : height), open_(true) {
    initialize();
  }

  ~RendererImpl() {
    close();
  }

  [[nodiscard]] bool pump_messages() {
    MSG msg{};
    while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
      if (msg.message == WM_QUIT) {
        open_ = false;
        return false;
      }
      TranslateMessage(&msg);
      DispatchMessageW(&msg);
    }
    return open_ && (window_ != nullptr) && IsWindow(window_);
  }

  [[nodiscard]] BridgeStatus present(const Surface& surface) {
    if (!open_ || !swap_chain_ || !context_) {
      return BridgeStatus::InvalidState;
    }
    if (surface.impl_ == nullptr || surface.impl_->texture() == nullptr) {
      return BridgeStatus::InvalidArgument;
    }
    Microsoft::WRL::ComPtr<ID3D11Texture2D> back_buffer;
    HRESULT hr = swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
    if (FAILED(hr) || !back_buffer) {
      return BridgeStatus::DeviceLost;
    }
    context_->CopyResource(back_buffer.Get(), surface.impl_->texture());
    hr = swap_chain_->Present(1, 0);
    if (FAILED(hr)) {
      if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) {
        return BridgeStatus::DeviceLost;
      }
      return BridgeStatus::InternalFailure;
    }
    return BridgeStatus::Ok;
  }

  [[nodiscard]] BridgeStatus present_nv12(rust::Slice<const std::uint8_t> pixels) {
    if (!open_ || !swap_chain_ || !context_ || !device_) {
      return BridgeStatus::InvalidState;
    }
    const std::size_t luma_size = static_cast<std::size_t>(width_) * height_;
    const std::size_t expected_size = luma_size + luma_size / 2;
    if (pixels.data() == nullptr || pixels.size() < expected_size) {
      return BridgeStatus::InvalidArgument;
    }

    if (!dynamic_bgra_texture_) {
      D3D11_TEXTURE2D_DESC desc{};
      desc.Width = width_;
      desc.Height = height_;
      desc.MipLevels = 1;
      desc.ArraySize = 1;
      desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
      desc.SampleDesc.Count = 1;
      desc.SampleDesc.Quality = 0;
      desc.Usage = D3D11_USAGE_DYNAMIC;
      desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
      desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
      HRESULT hr = device_->CreateTexture2D(&desc, nullptr, &dynamic_bgra_texture_);
      if (FAILED(hr)) {
        return BridgeStatus::DeviceLost;
      }
    }

    D3D11_MAPPED_SUBRESOURCE mapped{};
    HRESULT hr = context_->Map(dynamic_bgra_texture_.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (FAILED(hr)) {
      return BridgeStatus::DeviceLost;
    }

    const std::uint8_t* src_y = pixels.data();
    const std::uint8_t* src_uv = pixels.data() + luma_size;
    std::uint8_t* dst = static_cast<std::uint8_t*>(mapped.pData);

    for (UINT y = 0; y < height_; ++y) {
      const UINT uv_y = y / 2;
      const std::uint8_t* row_y = src_y + y * width_;
      const std::uint8_t* row_uv = src_uv + uv_y * width_;
      std::uint8_t* row_dst = dst + y * mapped.RowPitch;

      for (UINT x = 0; x < width_; ++x) {
        const int y_val = static_cast<int>(row_y[x]);
        const UINT uv_x = (x / 2) * 2;
        const int u_val = static_cast<int>(row_uv[uv_x]) - 128;
        const int v_val = static_cast<int>(row_uv[uv_x + 1]) - 128;

        const int r = std::clamp(y_val + static_cast<int>(1.402f * v_val), 0, 255);
        const int g = std::clamp(y_val - static_cast<int>(0.344136f * u_val + 0.714136f * v_val), 0, 255);
        const int b = std::clamp(y_val + static_cast<int>(1.772f * u_val), 0, 255);

        const std::size_t px = x * 4;
        row_dst[px] = static_cast<std::uint8_t>(b);
        row_dst[px + 1] = static_cast<std::uint8_t>(g);
        row_dst[px + 2] = static_cast<std::uint8_t>(r);
        row_dst[px + 3] = 255;
      }
    }

    context_->Unmap(dynamic_bgra_texture_.Get(), 0);

    Microsoft::WRL::ComPtr<ID3D11Texture2D> back_buffer;
    hr = swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
    if (FAILED(hr) || !back_buffer) {
      return BridgeStatus::DeviceLost;
    }

    context_->CopyResource(back_buffer.Get(), dynamic_bgra_texture_.Get());
    hr = swap_chain_->Present(1, 0);
    if (FAILED(hr)) {
      if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) {
        return BridgeStatus::DeviceLost;
      }
      return BridgeStatus::InternalFailure;
    }
    return BridgeStatus::Ok;
  }

  [[nodiscard]] std::uint32_t poll_inputs(rust::Slice<std::uint8_t> out) {
    if (out.data() == nullptr || out.size() < kInputEventBytes) {
      return 0;
    }
    const std::size_t max_events = out.size() / kInputEventBytes;
    std::uint32_t written = 0;
    QueuedInput ev{};
    while (written < max_events && input_queue_.pop(ev)) {
      std::uint8_t* dst = out.data() + static_cast<std::size_t>(written) * kInputEventBytes;
      dst[0] = ev.kind;
      dst[1] = ev.button;
      dst[2] = ev.pressed;
      dst[3] = 0;
      std::memcpy(dst + 4, &ev.x, 4);
      std::memcpy(dst + 8, &ev.y, 4);
      std::memcpy(dst + 12, &ev.wheel, 4);
      std::memcpy(dst + 16, &ev.vk, 4);
      ++written;
    }
    return written;
  }

  [[nodiscard]] bool is_open() const noexcept {
    return open_ && (window_ != nullptr) && IsWindow(window_);
  }

  void close() noexcept {
    open_ = false;
    swap_chain_ = nullptr;
    context_ = nullptr;
    device_ = nullptr;
    if (window_ != nullptr) {
      SetWindowLongPtrW(window_, GWLP_USERDATA, 0);
      DestroyWindow(window_);
      window_ = nullptr;
    }
  }

 private:
  static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    RendererImpl* self = nullptr;
    if (msg == WM_NCCREATE) {
      auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
      self = static_cast<RendererImpl*>(create->lpCreateParams);
      SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
      self = reinterpret_cast<RendererImpl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self != nullptr) {
      self->on_message(msg, wparam, lparam);
    }
    if (msg == WM_ERASEBKGND) {
      return 1;
    }
    if (msg == WM_PAINT) {
      PAINTSTRUCT paint{};
      BeginPaint(hwnd, &paint);
      EndPaint(hwnd, &paint);
      return 0;
    }
    if (msg == WM_DESTROY) {
      PostQuitMessage(0);
      return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
  }

  void on_message(UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
      case WM_MOUSEMOVE: {
        int x = GET_X_LPARAM(lparam);
        int y = GET_Y_LPARAM(lparam);
        map_client(x, y);
        push_input(QueuedInput{kInputKindMouseMove, 0, 0, x, y, 0, 0});
        break;
      }
      case WM_LBUTTONDOWN:
      case WM_LBUTTONUP:
      case WM_RBUTTONDOWN:
      case WM_RBUTTONUP:
      case WM_MBUTTONDOWN:
      case WM_MBUTTONUP: {
        const bool pressed =
            msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN || msg == WM_MBUTTONDOWN;
        std::uint8_t button = 1;
        if (msg == WM_RBUTTONDOWN || msg == WM_RBUTTONUP) {
          button = 2;
        } else if (msg == WM_MBUTTONDOWN || msg == WM_MBUTTONUP) {
          button = 3;
        }
        int x = GET_X_LPARAM(lparam);
        int y = GET_Y_LPARAM(lparam);
        map_client(x, y);
        const std::uint8_t button_mask =
            static_cast<std::uint8_t>(1U << static_cast<unsigned>(button - 1));
        if (pressed) {
          pressed_buttons_ = static_cast<std::uint8_t>(pressed_buttons_ | button_mask);
          if (GetCapture() != window_) {
            SetCapture(window_);
          }
        } else {
          pressed_buttons_ =
              static_cast<std::uint8_t>(pressed_buttons_ & ~button_mask);
          if (pressed_buttons_ == 0) {
            release_owned_capture();
          }
        }
        push_input(QueuedInput{kInputKindButton, button, static_cast<std::uint8_t>(pressed ? 1 : 0), x, y, 0, 0});
        break;
      }
      case WM_MOUSEWHEEL: {
        const int delta = GET_WHEEL_DELTA_WPARAM(wparam);
        int ticks = delta / WHEEL_DELTA;
        if (ticks == 0) {
          ticks = delta > 0 ? 1 : -1;
        }
        POINT pt{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
        ScreenToClient(window_, &pt);
        int x = pt.x;
        int y = pt.y;
        map_client(x, y);
        push_input(QueuedInput{kInputKindWheel, 0, 0, x, y, ticks, 0});
        break;
      }
      case WM_KEYDOWN:
      case WM_SYSKEYDOWN: {
        if ((lparam & (1 << 30)) != 0) {
          break;
        }
        push_input(QueuedInput{kInputKindKey, 0, 1, 0, 0, 0, static_cast<std::uint32_t>(wparam)});
        break;
      }
      case WM_KEYUP:
      case WM_SYSKEYUP:
        push_input(QueuedInput{kInputKindKey, 0, 0, 0, 0, 0, static_cast<std::uint32_t>(wparam)});
        break;
      case WM_KILLFOCUS:
      case WM_CANCELMODE:
        queue_release_all();
        break;
      case WM_ACTIVATEAPP:
        if (wparam == FALSE) {
          queue_release_all();
        }
        break;
      case WM_CAPTURECHANGED:
        if (!releasing_capture_ && reinterpret_cast<HWND>(lparam) != window_) {
          pressed_buttons_ = 0;
          push_input(QueuedInput{.kind = kInputKindReleaseAll});
        }
        break;
      case WM_CLOSE:
        open_ = false;
        break;
      default:
        break;
    }
  }

  void map_client(int& x, int& y) const {
    if (window_ == nullptr) {
      return;
    }
    RECT rc{};
    GetClientRect(window_, &rc);
    const int client_w = rc.right - rc.left;
    const int client_h = rc.bottom - rc.top;
    if (client_w > 0 && client_h > 0 && width_ > 0 && height_ > 0) {
      x = static_cast<int>((static_cast<std::int64_t>(x) * width_) / client_w);
      y = static_cast<int>((static_cast<std::int64_t>(y) * height_) / client_h);
    }
  }

  void push_input(const QueuedInput& ev) {
    input_queue_.push(ev);
  }

  void release_owned_capture() {
    if (GetCapture() != window_) {
      return;
    }
    releasing_capture_ = true;
    ReleaseCapture();
    releasing_capture_ = false;
  }

  void queue_release_all() {
    pressed_buttons_ = 0;
    release_owned_capture();
    push_input(QueuedInput{.kind = kInputKindReleaseAll});
  }

  void initialize() {
    WNDCLASSW wc{};
    wc.style = CS_OWNDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    wc.hbrBackground = nullptr;
    wc.lpszClassName = L"LatencyDeskRendererWindowClassV2";
    RegisterClassW(&wc);
    const DWORD window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VISIBLE;
    RECT client_rect{0, 0, static_cast<LONG>(width_), static_cast<LONG>(height_)};
    AdjustWindowRectEx(&client_rect, window_style, FALSE, 0);

    window_ = CreateWindowExW(
        0, L"LatencyDeskRendererWindowClassV2", L"LatencyDesk Remote Desktop",
        window_style, CW_USEDEFAULT, CW_USEDEFAULT,
        client_rect.right - client_rect.left, client_rect.bottom - client_rect.top,
        nullptr, nullptr, wc.hInstance, this);
    if (window_ == nullptr) {
      throw std::runtime_error("failed to create Win32 presentation window");
    }

    ShowWindow(window_, SW_SHOWNORMAL);
    SetForegroundWindow(window_);
    BringWindowToTop(window_);
    SetWindowPos(window_, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    UpdateWindow(window_);

    Microsoft::WRL::ComPtr<IDXGIFactory2> factory;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
      throw std::runtime_error("CreateDXGIFactory1 failed");
    }

    constexpr D3D_FEATURE_LEVEL feature_levels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
    };
    D3D_FEATURE_LEVEL selected_level{};
    hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                           D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                           feature_levels, ARRAYSIZE(feature_levels),
                           D3D11_SDK_VERSION, &device_, &selected_level, &context_);

    if (FAILED(hr)) {
      throw std::runtime_error("D3D11CreateDevice failed for presentation renderer");
    }

    DXGI_SWAP_CHAIN_DESC1 desc{};
    desc.Width = width_;
    desc.Height = height_;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.Stereo = FALSE;
    desc.SampleDesc.Count = 1;
    desc.SampleDesc.Quality = 0;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 3;
    desc.Scaling = DXGI_SCALING_STRETCH;
    desc.SwapEffect = DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    desc.AlphaMode = DXGI_ALPHA_MODE_UNSPECIFIED;

    hr = factory->CreateSwapChainForHwnd(device_.Get(), window_, &desc, nullptr, nullptr, &swap_chain_);
    if (FAILED(hr)) {
      throw std::runtime_error("CreateSwapChainForHwnd failed");
    }
  }

  std::uint32_t width_;
  std::uint32_t height_;
  bool open_{};
  bool releasing_capture_{};
  std::uint8_t pressed_buttons_{};
  HWND window_{};
  Microsoft::WRL::ComPtr<ID3D11Device> device_;
  Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
  Microsoft::WRL::ComPtr<IDXGISwapChain1> swap_chain_;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> dynamic_bgra_texture_;
  InputEventQueue input_queue_;
};


Renderer::Renderer(std::uint32_t width, std::uint32_t height)
    : impl_(std::make_unique<RendererImpl>(width, height)) {}

Renderer::~Renderer() = default;

bool Renderer::pump_messages() { return impl_->pump_messages(); }
BridgeStatus Renderer::present(const Surface& surface) { return impl_->present(surface); }
BridgeStatus Renderer::present_nv12(rust::Slice<const std::uint8_t> pixels) { return impl_->present_nv12(pixels); }
std::uint32_t Renderer::poll_inputs(rust::Slice<std::uint8_t> out) { return impl_->poll_inputs(out); }
bool Renderer::is_open() const noexcept { return impl_->is_open(); }
void Renderer::close() noexcept { impl_->close(); }


class CaptureImpl final {
 public:
  CaptureImpl(std::uint32_t adapter_index, std::uint32_t output_index)
      : source_(adapter_index, output_index) {}

  [[nodiscard]] BridgeStatus start() {
    std::scoped_lock lock(mutex_);
    if (started_) return BridgeStatus::InvalidState;
    source_.start();
    started_ = true;
    return BridgeStatus::Ok;
  }

  [[nodiscard]] BridgeStatus poll(std::uint32_t timeout_ms) {
    std::scoped_lock lock(mutex_);
    if (!started_) return BridgeStatus::InvalidState;
    if (pending_.has_value()) return BridgeStatus::QueueFull;

    auto frame = source_.poll(timeout_ms);
    if (!frame.has_value()) return BridgeStatus::NoFrame;
    if (frame->metadata.protected_content_masked) {
      source_.discard_pending();
      return BridgeStatus::ProtectedContent;
    }

    pending_.emplace(PendingFrame{
        .description = frame->description,
        .metadata = std::move(frame->metadata),
    });
    return BridgeStatus::Ok;
  }

  [[nodiscard]] std::unique_ptr<Surface> detach(std::uint32_t destination_format = 0U,
                                                std::uint32_t destination_width = 0U,
                                                std::uint32_t destination_height = 0U) {
    std::scoped_lock lock(mutex_);
    if (!started_ || !pending_.has_value()) {
      throw std::logic_error("desktop duplication frame is not pending");
    }

    try {
      auto frame = source_.detach_owned(destination_format, destination_width, destination_height);
      auto metadata = std::move(pending_->metadata);
      pending_.reset();
      auto surface_impl = std::make_unique<SurfaceImpl>(std::move(frame), std::move(metadata));
      return std::unique_ptr<Surface>(new Surface(std::move(surface_impl)));
    } catch (...) {
      pending_.reset();
      throw;
    }
  }

  [[nodiscard]] BridgeStatus discard() {
    std::scoped_lock lock(mutex_);
    if (!started_) return BridgeStatus::InvalidState;
    if (!pending_.has_value()) return BridgeStatus::Ok;
    source_.discard_pending();
    pending_.reset();
    return BridgeStatus::Ok;
  }

  [[nodiscard]] BridgeStatus stop() {
    std::scoped_lock lock(mutex_);
    source_.stop();
    pending_.reset();
    started_ = false;
    return BridgeStatus::Ok;
  }

  [[nodiscard]] std::uint32_t pending_width() const noexcept {
    std::scoped_lock lock(mutex_);
    return pending_.has_value() ? pending_->description.Width : 0U;
  }

  [[nodiscard]] std::uint32_t pending_height() const noexcept {
    std::scoped_lock lock(mutex_);
    return pending_.has_value() ? pending_->description.Height : 0U;
  }

  [[nodiscard]] std::uint32_t pending_format() const noexcept {
    std::scoped_lock lock(mutex_);
    return pending_.has_value() ? static_cast<std::uint32_t>(pending_->description.Format)
                                : 0U;
  }

  [[nodiscard]] bool pending_pointer_visible() const noexcept {
    std::scoped_lock lock(mutex_);
    return pending_.has_value() && pending_->metadata.pointer_visible;
  }

  [[nodiscard]] std::int32_t pending_pointer_x() const noexcept {
    std::scoped_lock lock(mutex_);
    return pending_.has_value() ? pending_->metadata.pointer_x : 0;
  }

  [[nodiscard]] std::int32_t pending_pointer_y() const noexcept {
    std::scoped_lock lock(mutex_);
    return pending_.has_value() ? pending_->metadata.pointer_y : 0;
  }

 private:
  mutable std::mutex mutex_;
  latencydesk::DdaCaptureSource source_;
  std::optional<PendingFrame> pending_;
  bool started_{};
};

Capture::Capture(std::uint32_t adapter_index, std::uint32_t output_index)
    : impl_(std::make_unique<CaptureImpl>(adapter_index, output_index)) {}

Capture::~Capture() = default;

BridgeStatus Capture::start() { return impl_->start(); }

BridgeStatus Capture::poll(std::uint32_t timeout_ms) { return impl_->poll(timeout_ms); }

std::unique_ptr<Surface> Capture::detach(std::uint32_t destination_format,
                                        std::uint32_t destination_width,
                                        std::uint32_t destination_height) {
  return impl_->detach(destination_format, destination_width, destination_height);
}

BridgeStatus Capture::discard() { return impl_->discard(); }

BridgeStatus Capture::stop() { return impl_->stop(); }

std::uint32_t Capture::pending_width() const noexcept { return impl_->pending_width(); }

std::uint32_t Capture::pending_height() const noexcept { return impl_->pending_height(); }

std::uint32_t Capture::pending_format() const noexcept { return impl_->pending_format(); }

bool Capture::pending_pointer_visible() const noexcept {
  return impl_->pending_pointer_visible();
}

std::int32_t Capture::pending_pointer_x() const noexcept {
  return impl_->pending_pointer_x();
}

std::int32_t Capture::pending_pointer_y() const noexcept {
  return impl_->pending_pointer_y();
}

std::uint32_t bridge_abi_version() noexcept { return kBridgeAbiVersion; }

std::uint32_t prepare_current_process_wer_exclusion() noexcept {
  std::scoped_lock lock(process_security_mutex);
  if (process_wer_excluded) return status_code(BridgeStatus::Ok);

  try {
    const auto executable_name = current_executable_leaf_name();
    if (!executable_name.has_value()) return status_code(BridgeStatus::InternalFailure);

    const auto status = status_from_wer_hresult(
        WerAddExcludedApplication(executable_name->c_str(), FALSE));
    if (status == BridgeStatus::Ok) process_wer_excluded = true;
    return status_code(status);
  } catch (...) {
    return status_code(BridgeStatus::InternalFailure);
  }
}

std::unique_ptr<Capture> make_desktop_duplication_capture(
    std::uint32_t adapter_index, std::uint32_t output_index,
    std::uint32_t pending_frame_capacity, std::uint32_t& status) noexcept {
  status = status_code(BridgeStatus::InvalidArgument);
  if (!valid_capture_queue_capacity(pending_frame_capacity)) return nullptr;

  const auto security_status = prepare_current_process_wer_exclusion();
  if (security_status != status_code(BridgeStatus::Ok)) {
    status = security_status;
    return nullptr;
  }

  try {
    auto capture = std::make_unique<Capture>(adapter_index, output_index);
    status = status_code(BridgeStatus::Ok);
    return capture;
  } catch (const std::bad_alloc&) {
    status = status_code(BridgeStatus::QueueFull);
  } catch (...) {
    status = status_code(BridgeStatus::InternalFailure);
  }
  return nullptr;
}

std::uint32_t capture_start(Capture& capture) noexcept {
  return invoke_status([&capture] { return capture.start(); });
}

std::uint32_t capture_poll(Capture& capture, std::uint32_t timeout_ms) noexcept {
  return invoke_status([&capture, timeout_ms] { return capture.poll(timeout_ms); });
}

std::unique_ptr<Surface> capture_detach(Capture& capture,
                                        std::uint32_t destination_format,
                                        std::uint32_t destination_width,
                                        std::uint32_t destination_height,
                                        std::uint32_t& status) noexcept {
  status = status_code(BridgeStatus::InternalFailure);
  try {
    auto surface = capture.detach(destination_format, destination_width, destination_height);
    status = status_code(BridgeStatus::Ok);
    return surface;
  } catch (const latencydesk::DdaError& error) {
    status = status_code(status_from_hresult(error.status()));
  } catch (const std::bad_alloc&) {
    status = status_code(BridgeStatus::QueueFull);
  } catch (const std::invalid_argument&) {
    status = status_code(BridgeStatus::InvalidArgument);
  } catch (const std::logic_error&) {
    status = status_code(BridgeStatus::InvalidState);
  } catch (...) {
    status = status_code(BridgeStatus::InternalFailure);
  }
  return nullptr;
}

std::uint32_t capture_discard(Capture& capture) noexcept {
  return invoke_status([&capture] { return capture.discard(); });
}

std::uint32_t capture_stop(Capture& capture) noexcept {
  return invoke_status([&capture] { return capture.stop(); });
}

std::uint32_t capture_pending_width(const Capture& capture) noexcept {
  return capture.pending_width();
}

std::uint32_t capture_pending_height(const Capture& capture) noexcept {
  return capture.pending_height();
}

std::uint32_t capture_pending_format(const Capture& capture) noexcept {
  return capture.pending_format();
}

bool capture_pending_pointer_visible(const Capture& capture) noexcept {
  return capture.pending_pointer_visible();
}

std::int32_t capture_pending_pointer_x(const Capture& capture) noexcept {
  return capture.pending_pointer_x();
}

std::int32_t capture_pending_pointer_y(const Capture& capture) noexcept {
  return capture.pending_pointer_y();
}

std::uint32_t surface_width(const Surface& surface) noexcept { return surface.width(); }

std::uint32_t surface_height(const Surface& surface) noexcept { return surface.height(); }

std::uint32_t surface_format(const Surface& surface) noexcept { return surface.format(); }

std::unique_ptr<Encoder> make_mf_h264_encoder(
    std::uint32_t adapter_index, std::uint32_t width, std::uint32_t height,
    std::uint32_t target_bitrate_bps, std::uint32_t fps,
    std::uint32_t max_queue_depth, std::uint32_t& status) noexcept {
  try {
    status = status_code(BridgeStatus::Ok);
    return std::make_unique<Encoder>(adapter_index, width, height, target_bitrate_bps, fps, max_queue_depth);
  } catch (const std::invalid_argument&) {
    status = status_code(BridgeStatus::InvalidArgument);
  } catch (const std::bad_alloc&) {
    status = status_code(BridgeStatus::QueueFull);
  } catch (const std::runtime_error&) {
    status = status_code(BridgeStatus::Unsupported);
  } catch (...) {
    status = status_code(BridgeStatus::InternalFailure);
  }
  return nullptr;
}

std::uint32_t encoder_encode(Encoder& encoder, const Surface& surface,
                             std::uint64_t capture_sequence,
                             std::uint64_t timestamp_ns) noexcept {
  return invoke_status([&] { return encoder.encode(surface, capture_sequence, timestamp_ns); });
}

std::uint32_t encoder_poll_output(Encoder& encoder,
                                  rust::Slice<std::uint8_t> output_buffer,
                                  std::size_t& output_size,
                                  bool& is_keyframe,
                                  std::uint64_t& capture_sequence,
                                  std::uint64_t& timestamp_ns) noexcept {
  return invoke_status([&] {
    return encoder.poll_output(output_buffer.data(), output_buffer.size(), output_size, is_keyframe, capture_sequence, timestamp_ns);
  });
}

std::uint32_t encoder_request_idr(Encoder& encoder) noexcept {
  return invoke_status([&] { return encoder.request_idr(); });
}

std::uint32_t encoder_update_bitrate(Encoder& encoder, std::uint32_t target_bitrate_bps) noexcept {
  return invoke_status([&] { return encoder.update_bitrate(target_bitrate_bps); });
}

std::uint32_t encoder_drain(Encoder& encoder) noexcept {
  return invoke_status([&] { return encoder.drain(); });
}

std::uint32_t encoder_quiesce(Encoder& encoder) noexcept {
  return invoke_status([&] { return encoder.quiesce(); });
}
std::unique_ptr<Renderer> make_d3d11_renderer(
    std::uint32_t width, std::uint32_t height, std::uint32_t& status) noexcept {
  try {
    status = status_code(BridgeStatus::Ok);
    return std::make_unique<Renderer>(width, height);
  } catch (const std::invalid_argument&) {
    status = status_code(BridgeStatus::InvalidArgument);
  } catch (const std::bad_alloc&) {
    status = status_code(BridgeStatus::QueueFull);
  } catch (const std::runtime_error&) {
    status = status_code(BridgeStatus::Unsupported);
  } catch (...) {
    status = status_code(BridgeStatus::InternalFailure);
  }
  return nullptr;
}

bool renderer_pump_messages(Renderer& renderer) noexcept {
  return renderer.pump_messages();
}

std::uint32_t renderer_present(Renderer& renderer, const Surface& surface) noexcept {
  return invoke_status([&] { return renderer.present(surface); });
}

std::uint32_t renderer_present_nv12(Renderer& renderer, rust::Slice<const std::uint8_t> pixels) noexcept {
  return invoke_status([&] { return renderer.present_nv12(pixels); });
}

std::uint32_t renderer_poll_inputs(Renderer& renderer, rust::Slice<std::uint8_t> out) noexcept {
  try {
    return renderer.poll_inputs(out);
  } catch (...) {
    return 0;
  }
}


bool renderer_is_open(const Renderer& renderer) noexcept {
  return renderer.is_open();
}

void renderer_close(Renderer& renderer) noexcept {
  renderer.close();
}

std::uint32_t gdi_desktop_metrics(std::uint32_t& width, std::uint32_t& height,
                                  std::int32_t& origin_x, std::int32_t& origin_y) noexcept {
  const int virtual_width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
  const int virtual_height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  if (virtual_width <= 0 || virtual_height <= 0) {
    return status_code(BridgeStatus::InternalFailure);
  }
  width = static_cast<std::uint32_t>(virtual_width);
  height = static_cast<std::uint32_t>(virtual_height);
  origin_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
  origin_y = GetSystemMetrics(SM_YVIRTUALSCREEN);
  return status_code(BridgeStatus::Ok);
}

std::uint32_t gdi_capture_desktop_bgra(rust::Slice<std::uint8_t> pixels, std::uint32_t& width,
                                       std::uint32_t& height, std::uint32_t& stride) noexcept {
  try {
    const int origin_x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    const int origin_y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int virtual_width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    const int virtual_height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (virtual_width <= 0 || virtual_height <= 0) {
      return status_code(BridgeStatus::InternalFailure);
    }
    width = static_cast<std::uint32_t>(virtual_width);
    height = static_cast<std::uint32_t>(virtual_height);
    stride = width * 4U;
    const std::size_t required =
        static_cast<std::size_t>(virtual_width) * static_cast<std::size_t>(virtual_height) * 4U;
    if (pixels.data() == nullptr || pixels.size() < required) {
      return status_code(BridgeStatus::InvalidArgument);
    }

    HDC screen_dc = GetDC(nullptr);
    if (screen_dc == nullptr) {
      return status_code(BridgeStatus::PermissionDenied);
    }
    HDC memory_dc = CreateCompatibleDC(screen_dc);
    if (memory_dc == nullptr) {
      ReleaseDC(nullptr, screen_dc);
      return status_code(BridgeStatus::InternalFailure);
    }

    BITMAPINFO info{};
    info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = virtual_width;
    info.bmiHeader.biHeight = -virtual_height;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HBITMAP bitmap =
        CreateDIBSection(memory_dc, &info, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (bitmap == nullptr || bits == nullptr) {
      if (bitmap != nullptr) {
        DeleteObject(bitmap);
      }
      DeleteDC(memory_dc);
      ReleaseDC(nullptr, screen_dc);
      return status_code(BridgeStatus::InternalFailure);
    }

    HGDIOBJ previous = SelectObject(memory_dc, bitmap);
    const BOOL copied =
        BitBlt(memory_dc, 0, 0, virtual_width, virtual_height, screen_dc, origin_x, origin_y,
               SRCCOPY | CAPTUREBLT);
    if (copied) {
      GdiFlush();
      std::memcpy(pixels.data(), bits, required);
    }
    SelectObject(memory_dc, previous);
    DeleteObject(bitmap);
    DeleteDC(memory_dc);
    ReleaseDC(nullptr, screen_dc);
    return copied ? status_code(BridgeStatus::Ok) : status_code(BridgeStatus::InternalFailure);
  } catch (...) {
    return status_code(BridgeStatus::InternalFailure);
  }
}

std::uint32_t send_win32_input(std::uint32_t kind, std::int32_t dx, std::int32_t dy,
                               std::uint32_t mouse_data, std::uint32_t flags,
                               std::uint16_t vk_code, std::uint16_t scan_code, std::uint32_t time,
                               std::uint64_t extra_info) noexcept {
  INPUT event{};
  if (kind == INPUT_MOUSE) {
    event.type = INPUT_MOUSE;
    event.mi.dx = dx;
    event.mi.dy = dy;
    event.mi.mouseData = mouse_data;
    event.mi.dwFlags = flags;
    event.mi.time = time;
    event.mi.dwExtraInfo = static_cast<ULONG_PTR>(extra_info);
  } else if (kind == INPUT_KEYBOARD) {
    event.type = INPUT_KEYBOARD;
    event.ki.wVk = vk_code;
    event.ki.wScan = scan_code;
    event.ki.dwFlags = flags;
    event.ki.time = time;
    event.ki.dwExtraInfo = static_cast<ULONG_PTR>(extra_info);
  } else {
    return status_code(BridgeStatus::InvalidArgument);
  }
  const UINT injected = SendInput(1, &event, sizeof(event));
  if (injected != 1U) {
    return status_code(BridgeStatus::InternalFailure);
  }
  return status_code(BridgeStatus::Ok);
}

}  // namespace latencydesk::windows_bridge
