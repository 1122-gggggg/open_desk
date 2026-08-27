#include "mf_h264_decoder.hpp"

#include <mferror.h>
#include <wmcodecdsp.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>

namespace latencydesk {
namespace {

void check(HRESULT hr, const char* operation) {
  if (FAILED(hr)) {
    throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                             std::to_string(static_cast<unsigned long>(hr)));
  }
}

MfDecoderStatus status_from_hresult(HRESULT hr) noexcept {
  if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) return MfDecoderStatus::NoOutput;
  if (hr == MF_E_NOTACCEPTING) return MfDecoderStatus::QueueFull;
  if (hr == E_INVALIDARG || hr == MF_E_INVALIDMEDIATYPE) {
    return MfDecoderStatus::InvalidArgument;
  }
  if (hr == MF_E_UNSUPPORTED_D3D_TYPE || hr == MF_E_TOPO_CODEC_NOT_FOUND ||
      hr == E_NOTIMPL) {
    return MfDecoderStatus::Unsupported;
  }
  if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET) {
    return MfDecoderStatus::DeviceLost;
  }
  return MfDecoderStatus::InternalFailure;
}

HRESULT wait_for_copy(ID3D11DeviceContext* context, ID3D11Query* query) noexcept {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (std::chrono::steady_clock::now() < deadline) {
    const HRESULT result =
        context->GetData(query, nullptr, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH);
    if (result == S_OK) return S_OK;
    if (result != S_FALSE) return result;
    Sleep(1);
  }
  return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
}

}  // namespace

MfH264Decoder::MfH264Decoder(ID3D11Device* device, UINT width, UINT height,
                             UINT fps, UINT max_queue_depth)
    : width_(width),
      height_(height),
      fps_(fps),
      max_queue_depth_((std::min)(4U, (std::max)(1U, max_queue_depth))),
      device_(device) {
  if (device == nullptr || width == 0 || height == 0 || fps == 0 ||
      width % 2 != 0 || height % 2 != 0) {
    throw std::invalid_argument(
        "MF H.264 decoder requires even dimensions and a nonzero frame rate");
  }
  initialize();
}

MfH264Decoder::~MfH264Decoder() {
  static_cast<void>(quiesce());
  event_source_ = nullptr;
  if (transform_) {
    transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
    transform_ = nullptr;
  }
  device_manager_ = nullptr;
  copy_completion_query_ = nullptr;
  context_ = nullptr;
  device_ = nullptr;
  if (mf_started_) {
    MFShutdown();
    mf_started_ = false;
  }
}

void MfH264Decoder::initialize() {
  check(MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET), "MFStartup decoder");
  mf_started_ = true;
  device_->GetImmediateContext(&context_);
  if (!context_) throw std::runtime_error("D3D11 immediate context unavailable");

  Microsoft::WRL::ComPtr<ID3D10Multithread> multithread;
  check(device_.As(&multithread), "ID3D10Multithread decoder");
  static_cast<void>(multithread->SetMultithreadProtected(TRUE));
  D3D11_QUERY_DESC query_description{};
  query_description.Query = D3D11_QUERY_EVENT;
  check(device_->CreateQuery(&query_description, &copy_completion_query_),
        "Create decoder copy completion query");

  check(MFCreateDXGIDeviceManager(&reset_token_, &device_manager_),
        "MFCreateDXGIDeviceManager decoder");
  check(device_manager_->ResetDevice(device_.Get(), reset_token_),
        "IMFDXGIDeviceManager::ResetDevice decoder");

  auto configure_candidate =
      [this](Microsoft::WRL::ComPtr<IMFTransform> candidate) -> HRESULT {
    if (!candidate) return E_POINTER;
    Microsoft::WRL::ComPtr<IMFAttributes> attributes;
    HRESULT result = candidate->GetAttributes(&attributes);
    if (FAILED(result) || !attributes) return FAILED(result) ? result : E_NOINTERFACE;
    UINT32 aware = FALSE;
    result = attributes->GetUINT32(MF_SA_D3D11_AWARE, &aware);
    if (FAILED(result) || aware == FALSE) {
      return FAILED(result) ? result : MF_E_UNSUPPORTED_D3D_TYPE;
    }
    result = attributes->SetUINT32(MF_LOW_LATENCY, TRUE);
    if (FAILED(result)) return result;
    result = attributes->SetUINT32(CODECAPI_AVDecVideoAcceleration_H264, TRUE);
    if (FAILED(result)) return result;
    UINT32 asynchronous = FALSE;
    if (SUCCEEDED(attributes->GetUINT32(MF_TRANSFORM_ASYNC, &asynchronous)) &&
        asynchronous != FALSE) {
      result = attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
      if (FAILED(result)) return result;
    }
    result = candidate->ProcessMessage(
        MFT_MESSAGE_SET_D3D_MANAGER,
        reinterpret_cast<ULONG_PTR>(device_manager_.Get()));
    if (FAILED(result)) return result;
    asynchronous_ = asynchronous != FALSE;
    transform_ = std::move(candidate);
    return S_OK;
  };

  HRESULT activation_result = E_FAIL;
  Microsoft::WRL::ComPtr<IMFTransform> inbox;
  activation_result = CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr,
                                       CLSCTX_INPROC_SERVER,
                                       IID_PPV_ARGS(&inbox));
  if (SUCCEEDED(activation_result)) {
    activation_result = configure_candidate(std::move(inbox));
  }

  if (!transform_) {
    MFT_REGISTER_TYPE_INFO input{MFMediaType_Video, MFVideoFormat_H264};
    MFT_REGISTER_TYPE_INFO output{MFMediaType_Video, MFVideoFormat_NV12};
    IMFActivate** activations = nullptr;
    UINT32 count = 0;
    activation_result = MFTEnumEx(
        MFT_CATEGORY_VIDEO_DECODER,
        MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_ASYNCMFT |
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
        &input, &output, &activations, &count);
    if (SUCCEEDED(activation_result)) {
      for (UINT32 index = 0; index < count && !transform_; ++index) {
        Microsoft::WRL::ComPtr<IMFTransform> candidate;
        activation_result =
            activations[index]->ActivateObject(IID_PPV_ARGS(&candidate));
        if (SUCCEEDED(activation_result)) {
          activation_result = configure_candidate(std::move(candidate));
        }
      }
    }
    if (activations != nullptr) {
      for (UINT32 index = 0; index < count; ++index) activations[index]->Release();
      CoTaskMemFree(activations);
    }
  }
  if (!transform_) {
    check(activation_result,
          "no inbox/DXVA H.264 decoder accepted the D3D11 device");
  }
  if (asynchronous_) {
    check(transform_->QueryInterface(IID_PPV_ARGS(&event_source_)),
          "decoder QueryInterface(IMFMediaEventGenerator)");
  }

  DWORD input_count = 0;
  DWORD output_count = 0;
  check(transform_->GetStreamCount(&input_count, &output_count),
        "GetStreamCount decoder");
  HRESULT ids = transform_->GetStreamIDs(1, &input_stream_id_, 1, &output_stream_id_);
  if (ids == E_NOTIMPL) {
    input_stream_id_ = 0;
    output_stream_id_ = 0;
  } else {
    check(ids, "GetStreamIDs decoder");
  }

  Microsoft::WRL::ComPtr<IMFMediaType> input_type;
  check(MFCreateMediaType(&input_type), "MFCreateMediaType decoder input");
  check(input_type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video),
        "decoder input major type");
  check(input_type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264),
        "decoder input H264 subtype");
  check(MFSetAttributeSize(input_type.Get(), MF_MT_FRAME_SIZE, width_, height_),
        "decoder input frame size");
  check(MFSetAttributeRatio(input_type.Get(), MF_MT_FRAME_RATE, fps_, 1),
        "decoder input frame rate");
  check(MFSetAttributeRatio(input_type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1),
        "decoder input pixel aspect");
  check(input_type->SetUINT32(
            MF_MT_INTERLACE_MODE, MFVideoInterlace_MixedInterlaceOrProgressive),
        "decoder mixed/progressive input");
  check(transform_->SetInputType(input_stream_id_, input_type.Get(), 0),
        "SetInputType decoder");
  configure_output_type();

  check(transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0),
        "decoder begin streaming");
  check(transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
        "decoder start stream");
  started_ = true;
}

void MfH264Decoder::configure_output_type() {
  for (DWORD index = 0;; ++index) {
    Microsoft::WRL::ComPtr<IMFMediaType> type;
    const HRESULT hr = transform_->GetOutputAvailableType(output_stream_id_, index, &type);
    if (hr == MF_E_NO_MORE_TYPES) break;
    check(hr, "GetOutputAvailableType decoder");
    GUID subtype{};
    if (SUCCEEDED(type->GetGUID(MF_MT_SUBTYPE, &subtype)) && subtype == MFVideoFormat_NV12 &&
        SUCCEEDED(transform_->SetOutputType(output_stream_id_, type.Get(), 0))) {
      UINT32 output_width = 0;
      UINT32 output_height = 0;
      if (SUCCEEDED(MFGetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, &output_width,
                                      &output_height)) &&
          output_width != 0 && output_height != 0) {
        width_ = output_width;
        height_ = output_height;
      }
      return;
    }
  }
  throw std::runtime_error("hardware H.264 decoder exposes no D3D11 NV12 output");
}

MfDecoderStatus MfH264Decoder::pump_events() noexcept {
  if (!asynchronous_) return MfDecoderStatus::Ok;
  if (!event_source_) return MfDecoderStatus::InvalidState;
  constexpr UINT kMaxEventsPerPump = 8;
  for (UINT processed = 0; processed < kMaxEventsPerPump; ++processed) {
    Microsoft::WRL::ComPtr<IMFMediaEvent> event;
    const HRESULT result = event_source_->GetEvent(MF_EVENT_FLAG_NO_WAIT, &event);
    if (result == MF_E_NO_EVENTS_AVAILABLE) break;
    if (FAILED(result) || !event) {
      async_error_ = FAILED(result) ? result : E_UNEXPECTED;
      return status_from_hresult(async_error_);
    }
    HRESULT event_status = S_OK;
    if (FAILED(event->GetStatus(&event_status)) || FAILED(event_status)) {
      async_error_ = FAILED(event_status) ? event_status : E_FAIL;
      return status_from_hresult(async_error_);
    }
    MediaEventType type = MEUnknown;
    if (FAILED(event->GetType(&type))) {
      async_error_ = E_UNEXPECTED;
      return MfDecoderStatus::InternalFailure;
    }
    switch (type) {
      case METransformNeedInput: {
        UINT32 stream_id = 0;
        if (FAILED(event->GetUINT32(MF_EVENT_MFT_INPUT_STREAM_ID, &stream_id)) ||
            stream_id != input_stream_id_) {
          async_error_ = MF_E_INVALIDSTREAMNUMBER;
          return MfDecoderStatus::InvalidState;
        }
        need_input_tokens_ =
            (std::min)(need_input_tokens_ + 1, max_queue_depth_);
        break;
      }
      case METransformHaveOutput:
        have_output_tokens_ =
            (std::min)(have_output_tokens_ + 1, max_queue_depth_);
        break;
      case METransformDrainComplete:
      case METransformMarker:
        break;
      case MEError:
        async_error_ = FAILED(event_status) ? event_status : E_FAIL;
        return status_from_hresult(async_error_);
      default:
        async_error_ = E_UNEXPECTED;
        return MfDecoderStatus::InternalFailure;
    }
  }
  if (FAILED(async_error_)) return status_from_hresult(async_error_);
  return MfDecoderStatus::Ok;
}

MfDecoderStatus MfH264Decoder::purge_events() noexcept {
  if (!asynchronous_) return MfDecoderStatus::Ok;
  if (!event_source_) return MfDecoderStatus::InvalidState;
  constexpr UINT kMaxEventsToPurge = 32;
  for (UINT purged = 0; purged < kMaxEventsToPurge; ++purged) {
    Microsoft::WRL::ComPtr<IMFMediaEvent> event;
    const HRESULT result = event_source_->GetEvent(MF_EVENT_FLAG_NO_WAIT, &event);
    if (result == MF_E_NO_EVENTS_AVAILABLE) return MfDecoderStatus::Ok;
    if (FAILED(result)) return status_from_hresult(result);
  }
  Microsoft::WRL::ComPtr<IMFMediaEvent> overflow;
  const HRESULT result =
      event_source_->GetEvent(MF_EVENT_FLAG_NO_WAIT, &overflow);
  if (result == MF_E_NO_EVENTS_AVAILABLE) return MfDecoderStatus::Ok;
  return FAILED(result) ? status_from_hresult(result)
                        : MfDecoderStatus::QueueFull;
}

MfDecoderStatus MfH264Decoder::decode(const std::uint8_t* annex_b, std::size_t size,
                                      std::uint64_t frame_id,
                                      std::uint64_t timestamp_ns) {
  std::scoped_lock lock(mutex_);
  if (!started_ || !transform_) return MfDecoderStatus::InvalidState;
  if (annex_b == nullptr || size == 0 || size > 16U * 1024U * 1024U || frame_id == 0) {
    return MfDecoderStatus::InvalidArgument;
  }
  const MfDecoderStatus events = pump_events();
  if (events != MfDecoderStatus::Ok) return events;
  if ((asynchronous_ && need_input_tokens_ == 0) ||
      pending_.size() >= max_queue_depth_) {
    return MfDecoderStatus::QueueFull;
  }

  Microsoft::WRL::ComPtr<IMFMediaBuffer> buffer;
  HRESULT hr = MFCreateMemoryBuffer(static_cast<DWORD>(size), &buffer);
  if (FAILED(hr)) return status_from_hresult(hr);
  BYTE* destination = nullptr;
  DWORD capacity = 0;
  hr = buffer->Lock(&destination, &capacity, nullptr);
  if (FAILED(hr)) return status_from_hresult(hr);
  if (capacity < size) {
    buffer->Unlock();
    return MfDecoderStatus::InvalidArgument;
  }
  std::memcpy(destination, annex_b, size);
  buffer->Unlock();
  hr = buffer->SetCurrentLength(static_cast<DWORD>(size));
  if (FAILED(hr)) return status_from_hresult(hr);

  Microsoft::WRL::ComPtr<IMFSample> sample;
  hr = MFCreateSample(&sample);
  if (FAILED(hr)) return status_from_hresult(hr);
  hr = sample->AddBuffer(buffer.Get());
  if (FAILED(hr)) return status_from_hresult(hr);
  sample->SetSampleTime(static_cast<LONGLONG>(timestamp_ns / 100));
  hr = transform_->ProcessInput(input_stream_id_, sample.Get(), 0);
  if (FAILED(hr)) return status_from_hresult(hr);
  if (asynchronous_) --need_input_tokens_;
  pending_.push_back(PendingMeta{frame_id, timestamp_ns});
  return MfDecoderStatus::Ok;
}

MfDecoderStatus MfH264Decoder::copy_output_sample(IMFSample* sample,
                                                  MfDecodedFrame& frame) {
  if (sample == nullptr || !device_ || !context_) {
    return MfDecoderStatus::InvalidState;
  }
  Microsoft::WRL::ComPtr<IMFMediaBuffer> buffer;
  HRESULT hr = sample->ConvertToContiguousBuffer(&buffer);
  if (FAILED(hr)) return status_from_hresult(hr);
  Microsoft::WRL::ComPtr<IMFDXGIBuffer> dxgi_buffer;
  hr = buffer.As(&dxgi_buffer);
  if (FAILED(hr) || !dxgi_buffer) return MfDecoderStatus::Unsupported;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> decoded;
  hr = dxgi_buffer->GetResource(IID_PPV_ARGS(&decoded));
  if (FAILED(hr) || !decoded) return status_from_hresult(hr);
  UINT subresource = 0;
  hr = dxgi_buffer->GetSubresourceIndex(&subresource);
  if (FAILED(hr)) return status_from_hresult(hr);

  D3D11_TEXTURE2D_DESC source{};
  decoded->GetDesc(&source);
  if (source.Format != DXGI_FORMAT_NV12 || source.Width == 0 ||
      source.Height == 0) {
    return MfDecoderStatus::Unsupported;
  }
  Microsoft::WRL::ComPtr<ID3D11Device> output_device;
  decoded->GetDevice(&output_device);
  if (!output_device || output_device.Get() != device_.Get()) {
    return MfDecoderStatus::Unsupported;
  }

  D3D11_TEXTURE2D_DESC owned = source;
  owned.Width = source.Width;
  owned.Height = source.Height;
  owned.MipLevels = 1;
  owned.ArraySize = 1;
  owned.Format = DXGI_FORMAT_NV12;
  owned.Usage = D3D11_USAGE_DEFAULT;
  owned.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
  owned.CPUAccessFlags = 0;
  owned.MiscFlags = 0;
  Microsoft::WRL::ComPtr<ID3D11Texture2D> texture;
  hr = device_->CreateTexture2D(&owned, nullptr, &texture);
  if (FAILED(hr)) return status_from_hresult(hr);
  context_->CopySubresourceRegion(texture.Get(), 0, 0, 0, 0, decoded.Get(),
                                  subresource, nullptr);
  context_->End(copy_completion_query_.Get());
  context_->Flush();
  hr = wait_for_copy(context_.Get(), copy_completion_query_.Get());
  if (FAILED(hr)) return status_from_hresult(hr);
  hardware_accelerated_ = true;
  frame.texture = std::move(texture);
  frame.description = owned;
  return MfDecoderStatus::Ok;
}

MfDecoderStatus MfH264Decoder::poll_output(std::optional<MfDecodedFrame>& frame) {
  std::scoped_lock lock(mutex_);
  frame.reset();
  if (!started_ || !transform_) return MfDecoderStatus::InvalidState;
  const MfDecoderStatus events = pump_events();
  if (events != MfDecoderStatus::Ok) return events;
  if (asynchronous_ && have_output_tokens_ == 0) {
    return MfDecoderStatus::NoOutput;
  }

  MFT_OUTPUT_STREAM_INFO stream_info{};
  HRESULT hr = transform_->GetOutputStreamInfo(output_stream_id_, &stream_info);
  if (FAILED(hr)) return status_from_hresult(hr);
  if ((stream_info.dwFlags &
       (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES |
        MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES)) == 0) {
    return MfDecoderStatus::Unsupported;
  }

  MFT_OUTPUT_DATA_BUFFER output{};
  output.dwStreamID = output_stream_id_;
  DWORD status = 0;
  hr = transform_->ProcessOutput(0, 1, &output, &status);
  if (output.pEvents != nullptr) {
    output.pEvents->Release();
    output.pEvents = nullptr;
  }
  if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
    if (asynchronous_ && have_output_tokens_ != 0) --have_output_tokens_;
    try {
      configure_output_type();
    } catch (...) {
      return MfDecoderStatus::Unsupported;
    }
    return MfDecoderStatus::NoOutput;
  }
  if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) {
    if (asynchronous_ && have_output_tokens_ != 0) --have_output_tokens_;
    return MfDecoderStatus::NoOutput;
  }
  if (FAILED(hr)) return status_from_hresult(hr);
  if (asynchronous_) --have_output_tokens_;

  Microsoft::WRL::ComPtr<IMFSample> sample;
  sample.Attach(output.pSample);
  if (!sample) return MfDecoderStatus::InternalFailure;
  MfDecodedFrame decoded{};
  const MfDecoderStatus copy_status = copy_output_sample(sample.Get(), decoded);
  if (copy_status != MfDecoderStatus::Ok) return copy_status;
  if (pending_.empty()) return MfDecoderStatus::InvalidState;
  decoded.frame_id = pending_.front().frame_id;
  decoded.timestamp_ns = pending_.front().timestamp_ns;
  pending_.pop_front();
  frame = std::move(decoded);
  return MfDecoderStatus::Ok;
}

MfDecoderStatus MfH264Decoder::flush() noexcept {
  std::scoped_lock lock(mutex_);
  if (!transform_ || !started_) return MfDecoderStatus::InvalidState;
  HRESULT result = transform_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
  if (FAILED(result)) return status_from_hresult(result);
  const MfDecoderStatus purged = purge_events();
  if (purged != MfDecoderStatus::Ok) return purged;
  pending_.clear();
  need_input_tokens_ = 0;
  have_output_tokens_ = 0;
  async_error_ = S_OK;
  result = transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
  return FAILED(result) ? status_from_hresult(result) : MfDecoderStatus::Ok;
}

MfDecoderStatus MfH264Decoder::quiesce() noexcept {
  std::scoped_lock lock(mutex_);
  MfDecoderStatus status = MfDecoderStatus::Ok;
  if (transform_) {
    const HRESULT result =
        transform_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
    if (FAILED(result)) status = status_from_hresult(result);
    const MfDecoderStatus purged = purge_events();
    if (status == MfDecoderStatus::Ok) status = purged;
  }
  pending_.clear();
  need_input_tokens_ = 0;
  have_output_tokens_ = 0;
  async_error_ = S_OK;
  started_ = false;
  return status;
}

bool MfH264Decoder::hardware_accelerated() const noexcept {
  std::scoped_lock lock(mutex_);
  return hardware_accelerated_;
}

}  // namespace latencydesk
