#include "dda_capture_source.hpp"

#include "capture_detach.hpp"

#include <chrono>
#include <exception>
#include <stdexcept>
#include <string>
#include <vector>

namespace latencydesk {
namespace {


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
  unusable_ = false;
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

  if (resource == nullptr) {
    const HRESULT release_status = duplication_->ReleaseFrame();
    if (FAILED(release_status)) std::terminate();
    return std::nullopt;
  }
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

D3D11_TEXTURE2D_DESC DdaCaptureSource::make_nv12_description(UINT width,
                                                            UINT height) noexcept {
  D3D11_TEXTURE2D_DESC nv12_desc{};
  nv12_desc.Width = width;
  nv12_desc.Height = height;
  nv12_desc.MipLevels = 1;
  nv12_desc.ArraySize = 1;
  nv12_desc.Format = DXGI_FORMAT_NV12;
  nv12_desc.SampleDesc.Count = 1;
  nv12_desc.SampleDesc.Quality = 0;
  nv12_desc.Usage = D3D11_USAGE_DEFAULT;
  nv12_desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
  nv12_desc.CPUAccessFlags = 0;
  nv12_desc.MiscFlags = 0;
  return nv12_desc;
}
D3D11_TEXTURE2D_DESC DdaCaptureSource::make_intermediate_description(
    const D3D11_TEXTURE2D_DESC& description) noexcept {
  D3D11_TEXTURE2D_DESC desc = description;
  desc.Usage = D3D11_USAGE_DEFAULT;
  if (description.Format == DXGI_FORMAT_NV12 ||
      description.Format == DXGI_FORMAT_P010 ||
      description.Format == DXGI_FORMAT_P016 ||
      description.Format == DXGI_FORMAT_YUY2 ||
      description.Format == DXGI_FORMAT_AYUV ||
      description.Format == DXGI_FORMAT_420_OPAQUE) {
    desc.BindFlags = D3D11_BIND_DECODER;
  } else {
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
  }
  desc.CPUAccessFlags = 0;
  desc.MiscFlags = 0;
  desc.MipLevels = 1;
  desc.ArraySize = 1;
  desc.SampleDesc.Count = 1;
  desc.SampleDesc.Quality = 0;
  return desc;
}

D3d11OwnedFrame DdaCaptureSource::detach_owned(UINT destination_format,
                                               UINT destination_width,
                                               UINT destination_height) {
  require_started();
  if (pending_texture_ == nullptr) throw std::logic_error("no DDA frame is pending");

  if (destination_width == 0) destination_width = pending_description_.Width;
  if (destination_height == 0) destination_height = pending_description_.Height;
  if (destination_format == 0) destination_format = pending_description_.Format;

  DXGI_FORMAT target_format = static_cast<DXGI_FORMAT>(destination_format);
  if (destination_format == 0x3231564E) {  // FourCC 'NV12'
    target_format = DXGI_FORMAT_NV12;
  } else if (destination_format == 0x41524742) {  // FourCC 'BGRA'
    target_format = DXGI_FORMAT_B8G8R8A8_UNORM;
  } else if (destination_format == 0x41424752) {  // FourCC 'RGBA'
    target_format = DXGI_FORMAT_R8G8B8A8_UNORM;
  }

  if (destination_width != pending_description_.Width ||
      destination_height != pending_description_.Height) {
    try {
      release_pending();
    } catch (...) {
    }
    throw std::invalid_argument("dimension mismatch for DDA frame detach");
  }

  try {
    if (target_format == pending_description_.Format) {
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

    if (target_format == DXGI_FORMAT_NV12) {
      if (destination_width % 2 != 0 || destination_height % 2 != 0) {
        throw std::invalid_argument("NV12 conversion requires even dimensions");
      }

      ensure_video_processor(pending_description_.Format, target_format,
                             destination_width, destination_height);

      const D3D11_TEXTURE2D_DESC nv12_desc =
          make_nv12_description(destination_width, destination_height);

      D3d11OwnedFrame owned;
      check(device_->CreateTexture2D(&nv12_desc, nullptr, &owned.texture_),
            "Create owned NV12 texture");

      D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output_view_desc{};
      output_view_desc.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
      output_view_desc.Texture2D.MipSlice = 0;
      Microsoft::WRL::ComPtr<ID3D11VideoProcessorOutputView> output_view;
      check(video_device_->CreateVideoProcessorOutputView(
                owned.texture_.Get(), video_enumerator_.Get(), &output_view_desc, &output_view),
            "CreateVideoProcessorOutputView");

      Microsoft::WRL::ComPtr<ID3D11VideoProcessorInputView> input_view;
      D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input_view_desc{};
      input_view_desc.FourCC = 0;
      input_view_desc.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
      input_view_desc.Texture2D.MipSlice = 0;

      HRESULT hr_in = video_device_->CreateVideoProcessorInputView(
          pending_texture_.Get(), video_enumerator_.Get(), &input_view_desc, &input_view);
      if (FAILED(hr_in)) {
        ensure_intermediate_input(pending_description_);
        CaptureDetachState detach;
        detach.native_work_started();
        copy_started_ = true;
        context_->CopyResource(intermediate_input_texture_.Get(), pending_texture_.Get());
        check(video_device_->CreateVideoProcessorInputView(
                  intermediate_input_texture_.Get(), video_enumerator_.Get(), &input_view_desc, &input_view),
              "CreateVideoProcessorInputView intermediate");
        D3D11_VIDEO_PROCESSOR_STREAM stream{};
        stream.Enable = TRUE;
        stream.pInputSurface = input_view.Get();
        check(video_context_->VideoProcessorBlt(
                  video_processor_.Get(), output_view.Get(), 0, 1, &stream),
              "VideoProcessorBlt");
        context_->End(copy_completion_query_.Get());
        context_->Flush();
        wait_for_completion(context_.Get(), copy_completion_query_.Get());
        detach.completion_proven();
        copy_completed_ = true;
        if (!detach.release_permitted()) std::terminate();
        release_pending();
        owned.description_ = nv12_desc;
        return owned;
      } else {
        CaptureDetachState detach;
        detach.native_work_started();
        copy_started_ = true;
        D3D11_VIDEO_PROCESSOR_STREAM stream{};
        stream.Enable = TRUE;
        stream.pInputSurface = input_view.Get();
        check(video_context_->VideoProcessorBlt(
                  video_processor_.Get(), output_view.Get(), 0, 1, &stream),
              "VideoProcessorBlt");
        context_->End(copy_completion_query_.Get());
        context_->Flush();
        wait_for_completion(context_.Get(), copy_completion_query_.Get());
        detach.completion_proven();
        copy_completed_ = true;
        if (!detach.release_permitted()) std::terminate();
        release_pending();
        owned.description_ = nv12_desc;
        return owned;
      }
    }

    throw DdaError(DXGI_ERROR_UNSUPPORTED, "unsupported conversion format");
  } catch (...) {
    if (copy_started_ && !copy_completed_) {
      bool proof_obtained = false;
      try {
        if (context_ != nullptr && copy_completion_query_ != nullptr) {
          context_->End(copy_completion_query_.Get());
          context_->Flush();
          wait_for_completion(context_.Get(), copy_completion_query_.Get());
          proof_obtained = true;
        }
      } catch (...) {
        proof_obtained = false;
      }

      if (proof_obtained) {
        copy_completed_ = true;
        try {
          release_pending();
        } catch (...) {
          destroy_unusable();
        }
      } else {
        destroy_unusable();
      }
    } else {
      try {
        release_pending();
      } catch (...) {
        destroy_unusable();
      }
    }
    throw;
  }
}

void DdaCaptureSource::discard_pending() {
  require_started();
  if (pending_texture_ == nullptr) return;
  if (copy_started_ && !copy_completed_) std::terminate();
  release_pending();
}

void DdaCaptureSource::destroy_unusable() noexcept {
  unusable_ = true;
  pending_texture_.Reset();
  intermediate_input_texture_.Reset();
  video_processor_.Reset();
  video_enumerator_.Reset();
  video_context_.Reset();
  video_device_.Reset();
  video_processor_input_format_ = DXGI_FORMAT_UNKNOWN;
  video_processor_output_format_ = DXGI_FORMAT_UNKNOWN;
  video_processor_width_ = 0;
  video_processor_height_ = 0;
  copy_started_ = false;
  copy_completed_ = false;
  copy_completion_query_.Reset();
  duplication_.Reset();
  context_.Reset();
  device_.Reset();
}

void DdaCaptureSource::stop() noexcept {
  if (!unusable_ && duplication_ != nullptr && pending_texture_ != nullptr) {
    if (copy_started_ && !copy_completed_) std::terminate();
    const HRESULT status = duplication_->ReleaseFrame();
    if (FAILED(status)) std::terminate();
  }
  destroy_unusable();
}

void DdaCaptureSource::release_pending() {
  if (copy_started_ && !copy_completed_) std::terminate();
  check(duplication_->ReleaseFrame(), "ReleaseFrame");
  pending_texture_.Reset();
  copy_started_ = false;
  copy_completed_ = false;
}

void DdaCaptureSource::ensure_video_processor(DXGI_FORMAT input_format,
                                              DXGI_FORMAT output_format,
                                              UINT width,
                                              UINT height) {
  if (!video_device_ || !video_context_) {
    check(device_.As(&video_device_), "Query ID3D11VideoDevice");
    check(context_.As(&video_context_), "Query ID3D11VideoContext");
  }

  if (video_processor_ != nullptr &&
      video_processor_input_format_ == input_format &&
      video_processor_output_format_ == output_format &&
      video_processor_width_ == width &&
      video_processor_height_ == height) {
    return;
  }

  video_processor_.Reset();
  video_enumerator_.Reset();

  D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
  content.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
  content.InputWidth = width;
  content.InputHeight = height;
  content.OutputWidth = width;
  content.OutputHeight = height;
  content.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;

  check(video_device_->CreateVideoProcessorEnumerator(&content, &video_enumerator_),
        "CreateVideoProcessorEnumerator");

  UINT input_support = 0;
  check(video_enumerator_->CheckVideoProcessorFormat(input_format, &input_support),
        "CheckVideoProcessorFormat input");
  if ((input_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT) == 0) {
    throw DdaError(DXGI_ERROR_UNSUPPORTED, "VideoProcessor input format unsupported");
  }

  UINT output_support = 0;
  check(video_enumerator_->CheckVideoProcessorFormat(output_format, &output_support),
        "CheckVideoProcessorFormat output");
  if ((output_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT) == 0) {
    throw DdaError(DXGI_ERROR_UNSUPPORTED, "VideoProcessor output format unsupported");
  }

  check(video_device_->CreateVideoProcessor(video_enumerator_.Get(), 0, &video_processor_),
        "CreateVideoProcessor");

  video_context_->VideoProcessorSetStreamFrameFormat(
      video_processor_.Get(), 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
  const RECT rect{0, 0, static_cast<LONG>(width), static_cast<LONG>(height)};
  video_context_->VideoProcessorSetStreamSourceRect(video_processor_.Get(), 0, TRUE, &rect);
  video_context_->VideoProcessorSetStreamDestRect(video_processor_.Get(), 0, TRUE, &rect);

  video_processor_input_format_ = input_format;
  video_processor_output_format_ = output_format;
  video_processor_width_ = width;
  video_processor_height_ = height;
}

void DdaCaptureSource::ensure_intermediate_input(const D3D11_TEXTURE2D_DESC& description) {
  if (intermediate_input_texture_ != nullptr &&
      intermediate_description_.Width == description.Width &&
      intermediate_description_.Height == description.Height &&
      intermediate_description_.Format == description.Format) {
    return;
  }
  intermediate_input_texture_.Reset();
  intermediate_description_ = make_intermediate_description(description);

  check(device_->CreateTexture2D(&intermediate_description_, nullptr, &intermediate_input_texture_),
        "Create intermediate input texture");
}

void DdaCaptureSource::require_started() const {
  if (unusable_) {
    throw std::logic_error("DDA source is unusable");
  }
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
