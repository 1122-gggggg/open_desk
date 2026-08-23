#include "wgc_capture_source.hpp"

#include "capture_detach.hpp"

#include <chrono>
#include <exception>
#include <stdexcept>

namespace latencydesk {
namespace {

void check_hresult(HRESULT status, const char* operation) {
  if (FAILED(status)) throw DdaError(status, operation);
}

void wait_for_completion(ID3D11DeviceContext* context, ID3D11Query* query) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (true) {
    const HRESULT status =
        context->GetData(query, nullptr, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH);
    if (status == S_OK) return;
    if (status != S_FALSE) check_hresult(status, "GetData copy completion query");
    if (std::chrono::steady_clock::now() >= deadline) {
      throw std::runtime_error("owned WGC copy completion timeout");
    }
    Sleep(1);
  }
}

}  // namespace

WgcCaptureSource::WgcCaptureSource(
    winrt::Windows::Graphics::Capture::GraphicsCaptureItem item,
    ID3D11Device* device)
    : item_(std::move(item)), device_(device), callbacks_(std::make_shared<CallbackState>()) {
  if (item_ == nullptr || device_ == nullptr) {
    throw std::invalid_argument("WGC source requires an authorized item and D3D11 device");
  }
}

WgcCaptureSource::~WgcCaptureSource() { stop(); }

void WgcCaptureSource::start() {
  if (frame_pool_ != nullptr) throw std::logic_error("WGC source already started");
  callbacks_ = std::make_shared<CallbackState>();
  winrt::init_apartment(winrt::apartment_type::multi_threaded);
  apartment_initialized_ = true;
  try {
    device_->GetImmediateContext(&context_);
    if (context_ == nullptr) throw std::runtime_error("GetImmediateContext returned null");
    Microsoft::WRL::ComPtr<IDXGIDevice> dxgi_device;
    check_hresult(device_.As(&dxgi_device), "Query IDXGIDevice");
    winrt::com_ptr<::IInspectable> inspectable;
    winrt::check_hresult(
        CreateDirect3D11DeviceFromDXGIDevice(dxgi_device.Get(), inspectable.put()));
    direct3d_device_ = inspectable.as<
        winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice>();

    D3D11_QUERY_DESC query_description{};
    query_description.Query = D3D11_QUERY_EVENT;
    check_hresult(device_->CreateQuery(&query_description, &copy_completion_query_),
                  "Create copy completion query");

    recreate_for(item_.Size());
    session_ = frame_pool_.CreateCaptureSession(item_);
    const auto callbacks = callbacks_;
    frame_arrived_token_ = frame_pool_.FrameArrived([callbacks](auto&&, auto&&) {
      std::lock_guard lock(callbacks->mutex);
      if (!callbacks->stopped) {
        callbacks->frame_available = true;
        callbacks->ready.notify_one();
      }
    });
    item_closed_token_ = item_.Closed([callbacks](auto&&, auto&&) {
      std::lock_guard lock(callbacks->mutex);
      callbacks->item_closed = true;
      callbacks->ready.notify_all();
    });
    session_.StartCapture();
  } catch (...) {
    stop();
    throw;
  }
}

WgcPollResult WgcCaptureSource::poll(std::uint64_t timeout_ns) {
  require_started();
  if (pending_frame_ != nullptr) {
    throw std::logic_error("WGC frame must be detached or discarded before polling again");
  }
  const auto timeout = std::chrono::nanoseconds(timeout_ns);
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (true) {
    {
      std::unique_lock lock(callbacks_->mutex);
      if (callbacks_->item_closed) return {.kind = WgcPollKind::ItemClosed};
      if (!callbacks_->frame_available) {
        if (!callbacks_->ready.wait_until(lock, deadline, [this] {
              return callbacks_->frame_available || callbacks_->item_closed || callbacks_->stopped;
            })) {
          return {.kind = WgcPollKind::Timeout};
        }
      }
      if (callbacks_->item_closed || callbacks_->stopped) {
        return {.kind = WgcPollKind::ItemClosed};
      }
      callbacks_->frame_available = false;
    }

    auto frame = frame_pool_.TryGetNextFrame();
    if (frame == nullptr) {
      if (std::chrono::steady_clock::now() >= deadline) return {.kind = WgcPollKind::Timeout};
      continue;
    }
    const auto size = frame.ContentSize();
    if (size.Width != content_size_.Width || size.Height != content_size_.Height) {
      frame = nullptr;
      recreate_for(size);
      return {.kind = WgcPollKind::SizeChanged};
    }

    auto access = frame.Surface().as<
        ::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
    Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
    check_hresult(access->GetInterface(IID_PPV_ARGS(&texture)), "Get WGC frame texture");
    texture->GetDesc(&pending_description_);
    pending_texture_ = std::move(texture);
    pending_frame_ = std::move(frame);
    return {
        .kind = WgcPollKind::FrameAvailable,
        .frame = WgcFrameAvailable{.description = pending_description_},
    };
  }
}

D3d11OwnedFrame WgcCaptureSource::detach_owned() {
  require_started();
  if (pending_frame_ == nullptr || pending_texture_ == nullptr) {
    throw std::logic_error("no WGC frame is pending");
  }

  D3D11_TEXTURE2D_DESC owned_description = pending_description_;
  owned_description.Usage = D3D11_USAGE_DEFAULT;
  owned_description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
  owned_description.CPUAccessFlags = 0;
  owned_description.MiscFlags = 0;
  D3d11OwnedFrame owned;
  check_hresult(device_->CreateTexture2D(&owned_description, nullptr, &owned.texture_),
                "Create owned texture");
  CaptureDetachState detach;
  detach.native_work_started();
  copy_started_ = true;
  context_->CopyResource(owned.texture_.Get(), pending_texture_.Get());
  context_->End(copy_completion_query_.Get());
  context_->Flush();
  wait_for_completion(context_.Get(), copy_completion_query_.Get());
  detach.completion_proven();
  copy_completed_ = true;
  if (!detach.release_permitted()) std::terminate();
  release_pending();
  owned.description_ = owned_description;
  return owned;
}

void WgcCaptureSource::discard_pending() {
  require_started();
  if (pending_frame_ == nullptr) return;
  if (copy_started_ && !copy_completed_) std::terminate();
  release_pending();
}

void WgcCaptureSource::stop() noexcept {
  {
    std::lock_guard lock(callbacks_->mutex);
    callbacks_->stopped = true;
    callbacks_->ready.notify_all();
  }
  if (pending_frame_ != nullptr) {
    if (copy_started_ && !copy_completed_) std::terminate();
    pending_texture_.Reset();
    pending_frame_ = nullptr;
  }
  copy_started_ = false;
  copy_completed_ = false;
  try {
    if (frame_pool_ != nullptr && frame_arrived_token_.value != 0) {
      frame_pool_.FrameArrived(frame_arrived_token_);
    }
    if (item_ != nullptr && item_closed_token_.value != 0) item_.Closed(item_closed_token_);
    if (session_ != nullptr) session_.Close();
    if (frame_pool_ != nullptr) frame_pool_.Close();
  } catch (...) {
  }
  frame_arrived_token_ = {};
  item_closed_token_ = {};
  session_ = nullptr;
  frame_pool_ = nullptr;
  direct3d_device_ = nullptr;
  copy_completion_query_.Reset();
  context_.Reset();
  if (apartment_initialized_) {
    winrt::uninit_apartment();
    apartment_initialized_ = false;
  }
}

void WgcCaptureSource::require_started() const {
  if (frame_pool_ == nullptr || session_ == nullptr || device_ == nullptr ||
      context_ == nullptr || copy_completion_query_ == nullptr) {
    throw std::logic_error("WGC source is not started");
  }
}

void WgcCaptureSource::release_pending() {
  if (copy_started_ && !copy_completed_) std::terminate();
  pending_texture_.Reset();
  pending_frame_ = nullptr;
  copy_started_ = false;
  copy_completed_ = false;
}

void WgcCaptureSource::recreate_for(winrt::Windows::Graphics::SizeInt32 size) {
  if (size.Width <= 0 || size.Height <= 0) {
    throw std::runtime_error("WGC reported an empty capture size");
  }
  using winrt::Windows::Graphics::DirectX::DirectXPixelFormat;
  if (frame_pool_ == nullptr) {
    frame_pool_ = winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool::CreateFreeThreaded(
        direct3d_device_, DirectXPixelFormat::B8G8R8A8UIntNormalized, 2, size);
  } else {
    frame_pool_.Recreate(direct3d_device_, DirectXPixelFormat::B8G8R8A8UIntNormalized, 2, size);
  }
  content_size_ = size;
}

}  // namespace latencydesk
