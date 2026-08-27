#include "mf_h264_encoder.hpp"

#include <mfapi.h>
#include <mferror.h>
#include <wmcodecdsp.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <stdexcept>

namespace latencydesk {
namespace {

void check_hresult(HRESULT hr, const char* operation) {
  if (FAILED(hr)) {
    throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                             std::to_string(static_cast<unsigned long>(hr)));
  }
}

MfEncoderStatus status_from_hresult(HRESULT hr) noexcept {
  switch (hr) {
    case S_OK:
      return MfEncoderStatus::Ok;
    case MF_E_TRANSFORM_NEED_MORE_INPUT:
      return MfEncoderStatus::NoOutput;
    case DXGI_ERROR_DEVICE_REMOVED:
    case DXGI_ERROR_DEVICE_RESET:
      return MfEncoderStatus::DeviceLost;
    case E_INVALIDARG:
      return MfEncoderStatus::InvalidArgument;
    case MF_E_NOT_FOUND:
    case MF_E_TOPO_CODEC_NOT_FOUND:
      return MfEncoderStatus::Unsupported;
    case MF_E_TRANSFORM_TYPE_NOT_SET:
    case MF_E_INVALIDREQUEST:
      return MfEncoderStatus::InvalidState;
    default:
      return MfEncoderStatus::InternalFailure;
  }
}

DWORD mft_alignment_mask(DWORD alignment_bytes) {
  const DWORD required = alignment_bytes == 0 ? 1 : alignment_bytes;
  if (required > 512 || (required & (required - 1)) != 0) return 0;
  return required - 1;
}

void check_codec_api_result(HRESULT hr, const char* name, const char* operation) {
  if (hr != S_OK) {
    throw std::runtime_error(std::string(name) + " " + operation + " failed, HRESULT=" +
                             std::to_string(static_cast<unsigned long>(hr)));
  }
}

void log_skipped_codec_property(const char* name, const char* reason, HRESULT hr) {
  const std::string message = std::string("MfH264Encoder: optional codec property ") + name + " " +
                              reason + ", HRESULT=" +
                              std::to_string(static_cast<unsigned long>(hr)) + "\n";
  OutputDebugStringA(message.c_str());
}

void set_required_codec_property(ICodecAPI* api, const GUID& guid, VARIANT* value,
                                 const char* name) {
  const HRESULT set_result = api->SetValue(&guid, value);
  if (set_result == S_OK) return;

  VARIANT current;
  VariantInit(&current);
  const HRESULT get_result = api->GetValue(&guid, &current);
  const bool already_required =
      get_result == S_OK && current.vt == value->vt &&
      ((value->vt == VT_UI4 && current.ulVal == value->ulVal) ||
       (value->vt == VT_BOOL && current.boolVal == value->boolVal));
  VariantClear(&current);
  if (!already_required) {
    check_codec_api_result(set_result, name, "SetValue");
  }
}

void set_optional_codec_property(ICodecAPI* api, const GUID& guid, VARIANT* value, const char* name) {
  HRESULT hr = api->IsSupported(&guid);
  if (hr == S_FALSE || hr == E_NOTIMPL) {
    log_skipped_codec_property(name, "is unsupported", hr);
    return;
  }
  check_codec_api_result(hr, name, "IsSupported");

  hr = api->IsModifiable(&guid);
  if (hr == S_FALSE || hr == E_NOTIMPL) {
    log_skipped_codec_property(name, "is read-only or not queryable", hr);
    return;
  }
  check_codec_api_result(hr, name, "IsModifiable");

  check_codec_api_result(api->SetValue(&guid, value), name, "SetValue");
}

void configure_static_codec_properties(ICodecAPI* api, UINT target_bitrate_bps, UINT fps) {
  VARIANT val;
  VariantInit(&val);

  val.vt = VT_BOOL;
  val.boolVal = VARIANT_TRUE;
  set_required_codec_property(api, CODECAPI_AVLowLatencyMode, &val, "CODECAPI_AVLowLatencyMode");

  val.vt = VT_UI4;
  val.ulVal = eAVEncCommonRateControlMode_CBR;
  set_optional_codec_property(api,
                              CODECAPI_AVEncCommonRateControlMode,
                              &val,
                              "CODECAPI_AVEncCommonRateControlMode");

  val.vt = VT_UI4;
  val.ulVal = 0;
  set_optional_codec_property(api,
                              CODECAPI_AVEncMPVDefaultBPictureCount,
                              &val,
                              "CODECAPI_AVEncMPVDefaultBPictureCount");
  const UINT frame_rate = (std::max)(1u, fps);
  const UINT vbv_bytes = (std::max)(1u, target_bitrate_bps / (8u * frame_rate));
  val.vt = VT_UI4;
  val.ulVal = vbv_bytes;
  set_optional_codec_property(api,
                              CODECAPI_AVEncCommonBufferSize,
                              &val,
                              "CODECAPI_AVEncCommonBufferSize");

  val.vt = VT_UI4;
  val.ulVal = 1;
  set_optional_codec_property(api,
                              CODECAPI_AVEncVideoMaxNumRefFrame,
                              &val,
                              "CODECAPI_AVEncVideoMaxNumRefFrame");

  val.vt = VT_BOOL;
  val.boolVal = VARIANT_TRUE;
  set_optional_codec_property(api,
                              CODECAPI_AVEncH264CABACEnable,
                              &val,
                              "CODECAPI_AVEncH264CABACEnable");

  val.vt = VT_UI4;
  val.ulVal = fps * 2;
  set_optional_codec_property(api, CODECAPI_AVEncMPVGOPSize, &val, "CODECAPI_AVEncMPVGOPSize");

  VariantClear(&val);
}

}  // namespace

MfH264Encoder::MfH264Encoder(UINT adapter_index,
                             UINT width,
                             UINT height,
                             UINT target_bitrate_bps,
                             UINT fps,
                             UINT max_queue_depth)
    : adapter_index_(adapter_index),
      width_(width),
      height_(height),
      target_bitrate_bps_(target_bitrate_bps),
      fps_(fps == 0 ? 60 : fps),
      max_queue_depth_(max_queue_depth == 0 ? 1 : (std::min)(max_queue_depth, 4U)) {
  initialize();
}

MfH264Encoder::MfH264Encoder(ID3D11Device* device,
                             UINT width,
                             UINT height,
                             UINT target_bitrate_bps,
                             UINT fps,
                             UINT max_queue_depth)
    : width_(width),
      height_(height),
      target_bitrate_bps_(target_bitrate_bps),
      fps_(fps == 0 ? 60 : fps),
      max_queue_depth_(max_queue_depth == 0 ? 1 : (std::min)(max_queue_depth, 4U)),
      device_(device) {
  if (device == nullptr) {
    throw std::invalid_argument("encoder D3D11 device is null");
  }
  initialize();
}

MfH264Encoder::~MfH264Encoder() {
  static_cast<void>(quiesce());
  if (transform_) {
    transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
    transform_ = nullptr;
  }
  codec_api_ = nullptr;
  device_manager_ = nullptr;
  context_ = nullptr;
  device_ = nullptr;
  if (mf_started_) {
    MFShutdown();
    mf_started_ = false;
  }
}

std::size_t MfH264Encoder::in_flight_count() const noexcept {
  std::scoped_lock lock(mutex_);
  return current_in_flight_;
}

void MfH264Encoder::initialize() {
  HRESULT hr = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
  check_hresult(hr, "MFStartup");
  mf_started_ = true;

  if (!device_) {
    Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
    check_hresult(CreateDXGIFactory1(IID_PPV_ARGS(&factory)), "CreateDXGIFactory1");
    Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
    if (FAILED(factory->EnumAdapters1(adapter_index_, &adapter))) adapter = nullptr;

    constexpr D3D_FEATURE_LEVEL requested_levels[] = {
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
    };
    D3D_FEATURE_LEVEL feature_level{};
    hr = D3D11CreateDevice(
        adapter.Get(), adapter ? D3D_DRIVER_TYPE_UNKNOWN : D3D_DRIVER_TYPE_HARDWARE,
        nullptr, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, requested_levels,
        ARRAYSIZE(requested_levels), D3D11_SDK_VERSION, &device_, &feature_level,
        &context_);
    check_hresult(hr, "D3D11CreateDevice with video support");
  } else {
    device_->GetImmediateContext(&context_);
    if (!context_) {
      throw std::runtime_error("encoder D3D11 immediate context is unavailable");
    }
  }
  Microsoft::WRL::ComPtr<ID3D10Multithread> multithread;
  check_hresult(device_.As(&multithread), "ID3D10Multithread encoder");
  static_cast<void>(multithread->SetMultithreadProtected(TRUE));

  hr = MFCreateDXGIDeviceManager(&reset_token_, &device_manager_);
  check_hresult(hr, "MFCreateDXGIDeviceManager");

  hr = device_manager_->ResetDevice(device_.Get(), reset_token_);
  check_hresult(hr, "IMFDXGIDeviceManager::ResetDevice");

  // 2. Enumerate hardware H.264 encoder MFTs only. Software SYNCMFT is not a fallback.
  MFT_REGISTER_TYPE_INFO input_info{MFMediaType_Video, MFVideoFormat_NV12};
  MFT_REGISTER_TYPE_INFO output_info{MFMediaType_Video, MFVideoFormat_H264};

  IMFActivate** activations = nullptr;
  UINT32 activation_count = 0;

  hr = MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER,
                 MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
                 &input_info,
                 &output_info,
                 &activations,
                 &activation_count);
  check_hresult(hr, "MFTEnumEx hardware H.264 encoder");

  if (activation_count == 0 || activations == nullptr) {
    if (activations != nullptr) {
      CoTaskMemFree(activations);
    }
    throw std::runtime_error("no hardware H.264 encoder MFT available on this system");
  }

  HRESULT last_activation_error = E_FAIL;
  for (UINT32 index = 0; index < activation_count && !transform_; ++index) {
    Microsoft::WRL::ComPtr<IMFTransform> candidate;
    last_activation_error =
        activations[index]->ActivateObject(IID_PPV_ARGS(&candidate));
    if (FAILED(last_activation_error) || !candidate) continue;

    Microsoft::WRL::ComPtr<IMFAttributes> attributes;
    if (SUCCEEDED(candidate->GetAttributes(&attributes)) && attributes) {
      UINT32 asynchronous = FALSE;
      if (SUCCEEDED(attributes->GetUINT32(MF_TRANSFORM_ASYNC, &asynchronous)) &&
          asynchronous != FALSE &&
          FAILED(attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE))) {
        last_activation_error = MF_E_INVALIDREQUEST;
        continue;
      }
    }

    last_activation_error = candidate->ProcessMessage(
        MFT_MESSAGE_SET_D3D_MANAGER,
        reinterpret_cast<ULONG_PTR>(device_manager_.Get()));
    if (SUCCEEDED(last_activation_error)) transform_ = std::move(candidate);
  }
  for (UINT32 index = 0; index < activation_count; ++index) {
    activations[index]->Release();
  }
  CoTaskMemFree(activations);
  if (!transform_) {
    check_hresult(last_activation_error,
                  "no hardware H.264 encoder accepted the capture D3D11 device");
  }
  hr = transform_->QueryInterface(IID_PPV_ARGS(&event_source_));
  check_hresult(hr, "QueryInterface(IMFMediaEventGenerator)");


  // Get stream IDs
  DWORD input_count = 0, output_count = 0;
  hr = transform_->GetStreamCount(&input_count, &output_count);
  check_hresult(hr, "IMFTransform::GetStreamCount");

  hr = transform_->GetStreamIDs(1, &input_stream_id_, 1, &output_stream_id_);
  if (hr == E_NOTIMPL) {
    input_stream_id_ = 0;
    output_stream_id_ = 0;
  }

  hr = transform_->QueryInterface(IID_PPV_ARGS(&codec_api_));
  check_hresult(hr, "ICodecAPI QueryInterface");
  if (!codec_api_) {
    throw std::runtime_error("ICodecAPI unavailable; cannot set required low-latency properties");
  }

  configure_media_types();
  configure_static_codec_properties(codec_api_.Get(), target_bitrate_bps_, fps_);
  configure_codec_properties();

  hr = transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
  check_hresult(hr, "MFT_MESSAGE_NOTIFY_BEGIN_STREAMING");
  hr = transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
  check_hresult(hr, "MFT_MESSAGE_NOTIFY_START_OF_STREAM");

  initialized_ = true;
  started_ = true;
}

void MfH264Encoder::configure_media_types() {
  // Output type (H.264)
  Microsoft::WRL::ComPtr<IMFMediaType> output_type;
  check_hresult(MFCreateMediaType(&output_type), "MFCreateMediaType output");
  check_hresult(output_type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video), "SetGUID MF_MT_MAJOR_TYPE");
  check_hresult(output_type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264), "SetGUID MF_MT_SUBTYPE");
  check_hresult(output_type->SetUINT32(MF_MT_AVG_BITRATE, target_bitrate_bps_), "SetUINT32 MF_MT_AVG_BITRATE");
  check_hresult(MFSetAttributeSize(output_type.Get(), MF_MT_FRAME_SIZE, width_, height_), "SetAttributeSize MF_MT_FRAME_SIZE");
  check_hresult(MFSetAttributeRatio(output_type.Get(), MF_MT_FRAME_RATE, fps_, 1), "SetAttributeRatio MF_MT_FRAME_RATE");
  check_hresult(MFSetAttributeRatio(output_type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1), "SetAttributeRatio MF_MT_PIXEL_ASPECT_RATIO");
  check_hresult(output_type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive), "SetUINT32 MF_MT_INTERLACE_MODE");
  check_hresult(output_type->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_High), "SetUINT32 MF_MT_MPEG2_PROFILE");

  // Request NALU length information if supported
  output_type->SetUINT32(MF_NALU_LENGTH_SET, TRUE);

  // Input type (NV12)
  Microsoft::WRL::ComPtr<IMFMediaType> input_type;
  check_hresult(MFCreateMediaType(&input_type), "MFCreateMediaType input");
  check_hresult(input_type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video), "SetGUID input MF_MT_MAJOR_TYPE");
  check_hresult(input_type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12), "SetGUID input MF_MT_SUBTYPE");
  check_hresult(MFSetAttributeSize(input_type.Get(), MF_MT_FRAME_SIZE, width_, height_), "input MF_MT_FRAME_SIZE");
  check_hresult(MFSetAttributeRatio(input_type.Get(), MF_MT_FRAME_RATE, fps_, 1), "input MF_MT_FRAME_RATE");
  check_hresult(MFSetAttributeRatio(input_type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1), "input MF_MT_PIXEL_ASPECT_RATIO");
  check_hresult(input_type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive), "input MF_MT_INTERLACE_MODE");

  HRESULT hr = transform_->SetOutputType(output_stream_id_, output_type.Get(), 0);
  if (hr == MF_E_TRANSFORM_TYPE_NOT_SET) {
    check_hresult(transform_->SetInputType(input_stream_id_, input_type.Get(), 0), "SetInputType");
    hr = transform_->SetOutputType(output_stream_id_, output_type.Get(), 0);
  }
  if (FAILED(hr)) {
    // Retry without NALU length attribute
    output_type->DeleteItem(MF_NALU_LENGTH_SET);
    nalu_lengths_requested_ = false;
    check_hresult(transform_->SetOutputType(output_stream_id_, output_type.Get(), 0), "SetOutputType without NALU length");
  } else {
    nalu_lengths_requested_ = true;
  }

  check_hresult(transform_->SetInputType(input_stream_id_, input_type.Get(), 0), "SetInputType final");
}

void MfH264Encoder::configure_codec_properties() {
  VARIANT val;
  VariantInit(&val);

  val.vt = VT_BOOL;
  val.boolVal = VARIANT_TRUE;
  set_optional_codec_property(codec_api_.Get(),
                              CODECAPI_AVEncCommonRealTime,
                              &val,
                              "CODECAPI_AVEncCommonRealTime");

  val.vt = VT_UI4;
  val.ulVal = target_bitrate_bps_;
  set_optional_codec_property(codec_api_.Get(),
                              CODECAPI_AVEncCommonMeanBitRate,
                              &val,
                              "CODECAPI_AVEncCommonMeanBitRate");

  val.vt = VT_UI4;
  val.ulVal = target_bitrate_bps_;
  set_optional_codec_property(codec_api_.Get(),
                              CODECAPI_AVEncCommonMaxBitRate,
                              &val,
                              "CODECAPI_AVEncCommonMaxBitRate");

  VariantClear(&val);
}

MfEncoderStatus MfH264Encoder::pump_events() noexcept {
  if (!event_source_) return MfEncoderStatus::InvalidState;
  constexpr UINT kMaxEventsPerPump = 8;
  for (UINT processed = 0; processed < kMaxEventsPerPump; ++processed) {
    Microsoft::WRL::ComPtr<IMFMediaEvent> event;
    const HRESULT get_result =
        event_source_->GetEvent(MF_EVENT_FLAG_NO_WAIT, &event);
    if (get_result == MF_E_NO_EVENTS_AVAILABLE) break;
    if (FAILED(get_result) || !event) {
      async_error_ = FAILED(get_result) ? get_result : E_UNEXPECTED;
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
      return MfEncoderStatus::InternalFailure;
    }
    switch (type) {
      case METransformNeedInput: {
        UINT32 stream_id = 0;
        if (FAILED(event->GetUINT32(MF_EVENT_MFT_INPUT_STREAM_ID, &stream_id)) ||
            stream_id != input_stream_id_) {
          async_error_ = MF_E_INVALIDSTREAMNUMBER;
          return MfEncoderStatus::InvalidState;
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
        drain_complete_ = true;
        break;
      case METransformMarker:
        break;
      case MEError:
        async_error_ = FAILED(event_status) ? event_status : E_FAIL;
        return status_from_hresult(async_error_);
      default:
        async_error_ = E_UNEXPECTED;
        return MfEncoderStatus::InternalFailure;
    }
  }
  if (FAILED(async_error_)) return status_from_hresult(async_error_);
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::encode_frame(ID3D11Texture2D* texture,
                                           std::uint64_t capture_sequence,
                                           std::uint64_t timestamp_ns) {
  std::scoped_lock lock(mutex_);
  if (!started_ || !transform_) {
    return MfEncoderStatus::InvalidState;
  }
  if (texture == nullptr) {
    return MfEncoderStatus::InvalidArgument;
  }
  const MfEncoderStatus event_status = pump_events();
  if (event_status != MfEncoderStatus::Ok) return event_status;
  if (need_input_tokens_ == 0 || current_in_flight_ >= max_queue_depth_) {
    return MfEncoderStatus::QueueFull;
  }
  if (pending_bitrate_bps_.has_value() && current_in_flight_ == 0) {
    VARIANT bitrate;
    VariantInit(&bitrate);
    bitrate.vt = VT_UI4;
    bitrate.ulVal = *pending_bitrate_bps_;
    const HRESULT bitrate_result =
        codec_api_->SetValue(&CODECAPI_AVEncCommonMeanBitRate, &bitrate);
    VariantClear(&bitrate);
    if (FAILED(bitrate_result)) return status_from_hresult(bitrate_result);
    target_bitrate_bps_ = *pending_bitrate_bps_;
    pending_bitrate_bps_.reset();
  }


  bool forced_idr = false;
  if (idr_requested_ && codec_api_) {
    VARIANT val;
    VariantInit(&val);
    val.vt = VT_UI4;
    val.ulVal = 1;
    const HRESULT idr_result =
        codec_api_->SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &val);
    VariantClear(&val);
    if (FAILED(idr_result)) return status_from_hresult(idr_result);
    forced_idr = true;
  }

  Microsoft::WRL::ComPtr<IMFMediaBuffer> buffer;
  HRESULT hr = MFCreateDXGISurfaceBuffer(__uuidof(ID3D11Texture2D), texture, 0, FALSE, &buffer);
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  Microsoft::WRL::ComPtr<IMFSample> sample;
  hr = MFCreateSample(&sample);
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  hr = sample->AddBuffer(buffer.Get());
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  // Time in 100-ns units
  const LONGLONG sample_time = static_cast<LONGLONG>(timestamp_ns / 100);
  const LONGLONG sample_duration = static_cast<LONGLONG>(10'000'000 / (fps_ == 0 ? 30 : fps_));
  sample->SetSampleTime(sample_time);
  sample->SetSampleDuration(sample_duration);

  hr = transform_->ProcessInput(input_stream_id_, sample.Get(), 0);
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }
  --need_input_tokens_;
  if (forced_idr) idr_requested_ = false;

  ++current_in_flight_;
  in_flight_sequences_.push_back(capture_sequence);
  in_flight_timestamps_.push_back(timestamp_ns);

  return MfEncoderStatus::Ok;
}

bool MfH264Encoder::convert_to_annex_b(
    IMFSample* sample, const std::uint8_t* data, std::size_t size,
    std::vector<std::uint8_t>& out) {
  if (sample == nullptr || data == nullptr || size == 0) return false;

  UINT32 blob_size = 0;
  const HRESULT blob_result =
      sample->GetBlobSize(MF_NALU_LENGTH_INFORMATION, &blob_size);
  if (blob_result == S_OK) {
    constexpr std::size_t kMaxNalUnits = 2048;
    if (blob_size == 0 || blob_size % sizeof(DWORD) != 0 ||
        blob_size / sizeof(DWORD) > kMaxNalUnits) {
      return false;
    }
    std::vector<std::uint8_t> blob(blob_size);
    UINT32 copied = 0;
    if (FAILED(sample->GetBlob(MF_NALU_LENGTH_INFORMATION, blob.data(),
                               blob_size, &copied)) ||
        copied != blob_size) {
      return false;
    }
    out.clear();
    out.reserve(size + 4 * (blob_size / sizeof(DWORD)));
    std::size_t offset = 0;
    for (std::size_t index = 0; index < blob_size; index += sizeof(DWORD)) {
      DWORD length = 0;
      std::memcpy(&length, blob.data() + index, sizeof(length));
      if (length == 0 || length > size - offset) return false;
      const std::uint8_t* nal = data + offset;
      std::size_t nal_size = length;
      if (nal_size >= 4 && nal[0] == 0 && nal[1] == 0 && nal[2] == 0 &&
          nal[3] == 1) {
        nal += 4;
        nal_size -= 4;
      } else if (nal_size >= 3 && nal[0] == 0 && nal[1] == 0 &&
                 nal[2] == 1) {
        nal += 3;
        nal_size -= 3;
      }
      if (nal_size == 0) return false;
      out.insert(out.end(), {0, 0, 0, 1});
      out.insert(out.end(), nal, nal + nal_size);
      offset += length;
    }
    return offset == size;
  }
  if (blob_result != MF_E_ATTRIBUTENOTFOUND) return false;

  if (size >= 4 && data[0] == 0 && data[1] == 0 &&
      (data[2] == 1 || (data[2] == 0 && data[3] == 1))) {
    out.assign(data, data + size);
    return true;
  }

  out.clear();
  out.reserve(size + 16);
  std::size_t offset = 0;
  while (offset + 4 <= size) {
    const std::uint32_t length =
        (static_cast<std::uint32_t>(data[offset]) << 24) |
        (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
        (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
        static_cast<std::uint32_t>(data[offset + 3]);
    offset += 4;
    if (length == 0 || length > size - offset) return false;
    out.insert(out.end(), {0, 0, 0, 1});
    out.insert(out.end(), data + offset, data + offset + length);
    offset += length;
  }
  return offset == size && !out.empty();
}

MfEncoderStatus MfH264Encoder::poll_output(std::optional<MfEncodedPacket>& packet) {
  std::scoped_lock lock(mutex_);
  packet.reset();
  if (!started_ || !transform_) return MfEncoderStatus::InvalidState;
  const MfEncoderStatus event_status = pump_events();
  if (event_status != MfEncoderStatus::Ok) return event_status;
  if (have_output_tokens_ == 0) return MfEncoderStatus::NoOutput;

  MFT_OUTPUT_STREAM_INFO stream_info{};
  HRESULT hr = transform_->GetOutputStreamInfo(output_stream_id_, &stream_info);
  if (FAILED(hr)) return status_from_hresult(hr);

  Microsoft::WRL::ComPtr<IMFSample> caller_sample;
  if ((stream_info.dwFlags &
       (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES |
        MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES)) == 0) {
    if (stream_info.cbSize == 0) return MfEncoderStatus::InvalidState;
    Microsoft::WRL::ComPtr<IMFMediaBuffer> buffer;
    hr = MFCreateAlignedMemoryBuffer(
        stream_info.cbSize, mft_alignment_mask(stream_info.cbAlignment), &buffer);
    if (FAILED(hr)) return status_from_hresult(hr);
    hr = MFCreateSample(&caller_sample);
    if (FAILED(hr)) return status_from_hresult(hr);
    hr = caller_sample->AddBuffer(buffer.Get());
    if (FAILED(hr)) return status_from_hresult(hr);
  }

  MFT_OUTPUT_DATA_BUFFER output_data{};
  output_data.dwStreamID = output_stream_id_;
  output_data.pSample = caller_sample.Get();
  DWORD process_status = 0;
  hr = transform_->ProcessOutput(0, 1, &output_data, &process_status);
  if (output_data.pEvents != nullptr) {
    output_data.pEvents->Release();
    output_data.pEvents = nullptr;
  }
  Microsoft::WRL::ComPtr<IMFSample> output_sample;
  if (output_data.pSample == caller_sample.Get()) {
    output_sample = caller_sample;
  } else if (output_data.pSample != nullptr) {
    output_sample.Attach(output_data.pSample);
  }
  if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) {
    if (have_output_tokens_ != 0) --have_output_tokens_;
    return MfEncoderStatus::NoOutput;
  }
  if (FAILED(hr)) {
    std::fprintf(stderr, "MfH264Encoder::ProcessOutput HRESULT=%lu\n",
                 static_cast<unsigned long>(hr));
    return status_from_hresult(hr);
  }
  --have_output_tokens_;
  if ((process_status & MFT_PROCESS_OUTPUT_STATUS_NEW_STREAMS) != 0 ||
      output_data.dwStatus == MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE ||
      output_data.dwStatus == MFT_OUTPUT_DATA_BUFFER_STREAM_END) {
    return MfEncoderStatus::InvalidState;
  }
  if (output_data.dwStatus == MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE ||
      !output_sample) {
    return MfEncoderStatus::NoOutput;
  }

  Microsoft::WRL::ComPtr<IMFMediaBuffer> media_buffer;
  hr = output_sample->ConvertToContiguousBuffer(&media_buffer);
  if (FAILED(hr)) return status_from_hresult(hr);
  BYTE* buffer_data = nullptr;
  DWORD current_len = 0;
  hr = media_buffer->Lock(&buffer_data, nullptr, &current_len);
  if (FAILED(hr)) return status_from_hresult(hr);

  UINT32 clean_point = FALSE;
  static_cast<void>(
      output_sample->GetUINT32(MFSampleExtension_CleanPoint, &clean_point));
  std::uint64_t sequence = 0;
  std::uint64_t timestamp = 0;
  if (!in_flight_sequences_.empty()) {
    sequence = in_flight_sequences_.front();
    in_flight_sequences_.pop_front();
  }
  if (!in_flight_timestamps_.empty()) {
    timestamp = in_flight_timestamps_.front();
    in_flight_timestamps_.pop_front();
  }
  if (current_in_flight_ != 0) --current_in_flight_;

  MfEncodedPacket encoded{};
  encoded.is_keyframe = clean_point != FALSE;
  encoded.capture_sequence = sequence;
  encoded.timestamp_ns = timestamp;
  const bool converted = convert_to_annex_b(
      output_sample.Get(), buffer_data, current_len, encoded.data);
  media_buffer->Unlock();
  if (!converted || encoded.data.empty()) return MfEncoderStatus::InternalFailure;
  packet = std::move(encoded);
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::request_idr() {
  std::scoped_lock lock(mutex_);
  if (!started_ || !codec_api_) return MfEncoderStatus::InvalidState;
  idr_requested_ = true;
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::update_bitrate(UINT target_bitrate_bps) {
  std::scoped_lock lock(mutex_);
  if (!started_ || !codec_api_ || target_bitrate_bps == 0) {
    return MfEncoderStatus::InvalidArgument;
  }
  pending_bitrate_bps_ = target_bitrate_bps;
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::drain() {
  std::scoped_lock lock(mutex_);
  if (!started_ || !transform_ || draining_) {
    return MfEncoderStatus::InvalidState;
  }
  HRESULT hr = transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
  if (FAILED(hr)) return status_from_hresult(hr);
  hr = transform_->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0);
  if (FAILED(hr)) return status_from_hresult(hr);
  draining_ = true;
  drain_complete_ = false;

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (!drain_complete_) {
    const MfEncoderStatus events = pump_events();
    if (events != MfEncoderStatus::Ok) return events;
    while (have_output_tokens_ != 0) {
      MFT_OUTPUT_STREAM_INFO info{};
      hr = transform_->GetOutputStreamInfo(output_stream_id_, &info);
      if (FAILED(hr)) return status_from_hresult(hr);
      const DWORD bytes = info.cbSize != 0 ? info.cbSize : 2U * 1024U * 1024U;
      Microsoft::WRL::ComPtr<IMFMediaBuffer> buffer;
      hr = MFCreateMemoryBuffer(bytes, &buffer);
      if (FAILED(hr)) return status_from_hresult(hr);
      Microsoft::WRL::ComPtr<IMFSample> sample;
      hr = MFCreateSample(&sample);
      if (FAILED(hr)) return status_from_hresult(hr);
      hr = sample->AddBuffer(buffer.Get());
      if (FAILED(hr)) return status_from_hresult(hr);
      MFT_OUTPUT_DATA_BUFFER output{};
      output.dwStreamID = output_stream_id_;
      output.pSample = sample.Get();
      DWORD output_status = 0;
      hr = transform_->ProcessOutput(0, 1, &output, &output_status);
      if (output.pEvents != nullptr) output.pEvents->Release();
      if (FAILED(hr)) return status_from_hresult(hr);
      --have_output_tokens_;
      if (current_in_flight_ != 0) --current_in_flight_;
      if (!in_flight_sequences_.empty()) in_flight_sequences_.pop_front();
      if (!in_flight_timestamps_.empty()) in_flight_timestamps_.pop_front();
    }
    if (drain_complete_) break;
    if (std::chrono::steady_clock::now() >= deadline) {
      async_error_ = HRESULT_FROM_WIN32(WAIT_TIMEOUT);
      return MfEncoderStatus::InternalFailure;
    }
    Sleep(1);
  }
  draining_ = false;
  started_ = false;
  current_in_flight_ = 0;
  in_flight_sequences_.clear();
  in_flight_timestamps_.clear();
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::quiesce() noexcept {
  std::scoped_lock lock(mutex_);
  if (transform_) {
    static_cast<void>(transform_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0));
    for (UINT pass = 0; pass < 4; ++pass) {
      static_cast<void>(pump_events());
    }
  }
  current_in_flight_ = 0;
  in_flight_sequences_.clear();
  in_flight_timestamps_.clear();
  need_input_tokens_ = 0;
  have_output_tokens_ = 0;
  async_error_ = S_OK;
  draining_ = false;
  pending_bitrate_bps_.reset();
  drain_complete_ = false;
  idr_requested_ = false;
  started_ = false;
  return MfEncoderStatus::Ok;
}

}  // namespace latencydesk
