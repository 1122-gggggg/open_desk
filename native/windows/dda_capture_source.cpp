#include "dda_capture_source.hpp"

#include "capture_detach.hpp"

#include <chrono>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

[[noreturn]] void throw_hresult(HRESULT status, const char* operation) {
  throw DdaError(status, operation);
}

void check(HRESULT status, const char* operation) {
  if (FAILED(status)) throw_hresult(status, operation);
}

void wait_for_completion(ID3D11DeviceContext* context, ID3D11Query* query) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (true) {
    const HRESULT status =
        context->GetData(query, nullptr, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH);
    if (status == S_OK) return;
    if (status != S_FALSE) check(status, "GetData copy completion query");
    if (std::chrono::steady_clock::now() >= deadline) {
      throw std::runtime_error("owned DDA copy completion timeout");
    }
    Sleep(1);
  }
}

template <typename T, typename Fetch>
std::vector<T> read_rectangles(Fetch&& fetch, UINT maximum_bytes, const char* operation) {
  UINT required_bytes = 0;
  const HRESULT probe = fetch(0, nullptr, &required_bytes);
  if (probe != DXGI_ERROR_MORE_DATA && FAILED(probe)) check(probe, operation);
  if (required_bytes == 0) return {};
  if (required_bytes > maximum_bytes || required_bytes % sizeof(T) != 0) {
    throw std::runtime_error("DDA metadata exceeds the configured bound");
  }

  std::vector<T> values(required_bytes / sizeof(T));
  UINT returned_bytes = 0;
  check(fetch(required_bytes, values.data(), &returned_bytes), operation);
  if (returned_bytes > required_bytes || returned_bytes % sizeof(T) != 0) {
    throw std::runtime_error("DDA metadata size changed while acquiring a frame");
  }
  values.resize(returned_bytes / sizeof(T));
  return values;
}

}  // namespace

DdaError::DdaError(HRESULT status, const char* operation)
    : std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                         std::to_string(static_cast<unsigned long>(status))),
      status_(status) {}

DdaCaptureSource::DdaCaptureSource(UINT adapter_index, UINT output_index)
    : adapter_index_(adapter_index), output_index_(output_index) {}

DdaCaptureSource::~DdaCaptureSource() { stop(); }

void DdaCaptureSource::start() {
  if (duplication_ != nullptr) throw std::logic_error("DDA source already started");

  Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
  check(CreateDXGIFactory1(IID_PPV_ARGS(&factory)), "CreateDXGIFactory1");
  Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
  check(factory->EnumAdapters1(adapter_index_, &adapter), "EnumAdapters1");
  Microsoft::WRL::ComPtr<IDXGIOutput> output;
  check(adapter->EnumOutputs(output_index_, &output), "EnumOutputs");
  Microsoft::WRL::ComPtr<IDXGIOutput1> output1;
  check(output.As(&output1), "Query IDXGIOutput1");

  UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
#ifndef NDEBUG
  flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif
  D3D_FEATURE_LEVEL feature_level{};
  check(D3D11CreateDevice(adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags,
                          nullptr, 0, D3D11_SDK_VERSION, &device_, &feature_level,
                          &context_),
        "D3D11CreateDevice");
  check(output1->DuplicateOutput(device_.Get(), &duplication_), "DuplicateOutput");

  D3D11_QUERY_DESC description{};
  description.Query = D3D11_QUERY_EVENT;
  check(device_->CreateQuery(&description, &copy_completion_query_),
        "Create copy completion query");
}

std::optional<DdaFrameAvailable> DdaCaptureSource::poll(UINT timeout_ms) {
  require_started();
  if (pending_texture_ != nullptr) {
    throw std::logic_error("DDA frame must be detached or discarded before polling again");
  }

  DXGI_OUTDUPL_FRAME_INFO info{};
  Microsoft::WRL::ComPtr<IDXGIResource> resource;
  const HRESULT status = duplication_->AcquireNextFrame(timeout_ms, &info, &resource);
  if (status == DXGI_ERROR_WAIT_TIMEOUT) return std::nullopt;
  check(status, "AcquireNextFrame");

  Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
  try {
    check(resource.As(&texture), "Query captured texture");
    texture->GetDesc(&pending_description_);
    DdaFrameAvailable frame{
        .description = pending_description_,
        .metadata = read_metadata(info),
    };
    pending_texture_ = std::move(texture);
    return frame;
  } catch (...) {
    const HRESULT release_status = duplication_->ReleaseFrame();
    if (FAILED(release_status)) std::terminate();
    throw;
  }
}

D3d11OwnedFrame DdaCaptureSource::detach_owned() {
  require_started();
  if (pending_texture_ == nullptr) throw std::logic_error("no DDA frame is pending");

  D3D11_TEXTURE2D_DESC owned_description = pending_description_;
  owned_description.Usage = D3D11_USAGE_DEFAULT;
  owned_description.BindFlags = D3D11_BIND_SHADER_RESOURCE;
  owned_description.CPUAccessFlags = 0;
  owned_description.MiscFlags = 0;

  D3d11OwnedFrame owned;
  check(device_->CreateTexture2D(&owned_description, nullptr, &owned.texture_),
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

void DdaCaptureSource::discard_pending() {
  require_started();
  if (pending_texture_ == nullptr) return;
  if (copy_started_ && !copy_completed_) std::terminate();
  release_pending();
}

void DdaCaptureSource::stop() noexcept {
  if (pending_texture_ != nullptr) {
    if (copy_started_ && !copy_completed_) std::terminate();
    const HRESULT status = duplication_->ReleaseFrame();
    if (FAILED(status)) std::terminate();
  }
  pending_texture_.Reset();
  copy_started_ = false;
  copy_completed_ = false;
  copy_completion_query_.Reset();
  duplication_.Reset();
  context_.Reset();
  device_.Reset();
}

void DdaCaptureSource::release_pending() {
  if (copy_started_ && !copy_completed_) std::terminate();
  check(duplication_->ReleaseFrame(), "ReleaseFrame");
  pending_texture_.Reset();
  copy_started_ = false;
  copy_completed_ = false;
}

void DdaCaptureSource::require_started() const {
  if (duplication_ == nullptr || device_ == nullptr || context_ == nullptr ||
      copy_completion_query_ == nullptr) {
    throw std::logic_error("DDA source is not started");
  }
}

DdaFrameMetadata DdaCaptureSource::read_metadata(const DXGI_OUTDUPL_FRAME_INFO& info) const {
  DdaFrameMetadata metadata{
      .protected_content_masked = info.ProtectedContentMaskedOut != FALSE,
      .pointer_visible = info.PointerPosition.Visible != FALSE,
      .pointer_x = info.PointerPosition.Position.x,
      .pointer_y = info.PointerPosition.Position.y,
  };
  metadata.move_rects = read_rectangles<DXGI_OUTDUPL_MOVE_RECT>(
      [this](UINT bytes, DXGI_OUTDUPL_MOVE_RECT* output, UINT* required) {
        return duplication_->GetFrameMoveRects(bytes, output, required);
      },
      kMaxMetadataBytes, "GetFrameMoveRects");
  metadata.dirty_rects = read_rectangles<RECT>(
      [this](UINT bytes, RECT* output, UINT* required) {
        return duplication_->GetFrameDirtyRects(bytes, output, required);
      },
      kMaxMetadataBytes, "GetFrameDirtyRects");
  if (info.PointerShapeBufferSize == 0) return metadata;
  if (info.PointerShapeBufferSize > kMaxMetadataBytes) {
    throw std::runtime_error("DDA pointer shape exceeds the configured bound");
  }
  metadata.pointer_shape.resize(info.PointerShapeBufferSize);
  UINT required_bytes = 0;
  DXGI_OUTDUPL_POINTER_SHAPE_INFO shape_info{};
  check(duplication_->GetFramePointerShape(
            static_cast<UINT>(metadata.pointer_shape.size()), metadata.pointer_shape.data(),
            &required_bytes, &shape_info),
        "GetFramePointerShape");
  if (required_bytes > metadata.pointer_shape.size()) {
    throw std::runtime_error("DDA pointer shape size changed while acquiring a frame");
  }
  metadata.pointer_shape.resize(required_bytes);
  return metadata;
}

}  // namespace latencydesk
