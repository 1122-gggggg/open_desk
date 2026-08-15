#include "mf_h264_encoder.hpp"

#include <mfapi.h>
#include <mferror.h>
#include <wmcodecdsp.h>

#include <algorithm>
#include <cstring>
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
      fps_(fps == 0 ? 30 : fps),
      max_queue_depth_(max_queue_depth == 0 ? 1 : (std::min)(max_queue_depth, 4U)) {
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

  // 1. Create Direct3D 11 device for hardware video acceleration
  Microsoft::WRL::ComPtr<IDXGIFactory1> factory;
  hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
  check_hresult(hr, "CreateDXGIFactory1");

  Microsoft::WRL::ComPtr<IDXGIAdapter1> adapter;
  hr = factory->EnumAdapters1(adapter_index_, &adapter);
  if (FAILED(hr)) {
    // Fallback to default adapter
    adapter = nullptr;
  }

  constexpr D3D_FEATURE_LEVEL requested_levels[] = {
      D3D_FEATURE_LEVEL_11_1,
      D3D_FEATURE_LEVEL_11_0,
  };
  D3D_FEATURE_LEVEL feature_level{};
  UINT creation_flags = D3D11_CREATE_DEVICE_VIDEO_SUPPORT;
#ifndef NDEBUG
  creation_flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

  hr = D3D11CreateDevice(adapter.Get(),
                          adapter ? D3D_DRIVER_TYPE_UNKNOWN : D3D_DRIVER_TYPE_HARDWARE,
                          nullptr,
                          creation_flags,
                          requested_levels,
                          ARRAYSIZE(requested_levels),
                          D3D11_SDK_VERSION,
                          &device_,
                          &feature_level,
                          &context_);
  if (FAILED(hr)) {
    // Retry without debug flag
    hr = D3D11CreateDevice(adapter.Get(),
                            adapter ? D3D_DRIVER_TYPE_UNKNOWN : D3D_DRIVER_TYPE_HARDWARE,
                            nullptr,
                            D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                            requested_levels,
                            ARRAYSIZE(requested_levels),
                            D3D11_SDK_VERSION,
                            &device_,
                            &feature_level,
                            &context_);
  }
  check_hresult(hr, "D3D11CreateDevice with video support");

  hr = MFCreateDXGIDeviceManager(&reset_token_, &device_manager_);
  check_hresult(hr, "MFCreateDXGIDeviceManager");

  hr = device_manager_->ResetDevice(device_.Get(), reset_token_);
  check_hresult(hr, "IMFDXGIDeviceManager::ResetDevice");

  // 2. Enumerate H.264 Encoder MFTs (Hardware first, software fallback)
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
    // Software fallback
    hr = MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER,
                   MFT_ENUM_FLAG_SYNCMFT | MFT_ENUM_FLAG_SORTANDFILTER,
                   &input_info,
                   &output_info,
                   &activations,
                   &activation_count);
    check_hresult(hr, "MFTEnumEx software H.264 encoder");
  }

  if (activation_count == 0 || activations == nullptr) {
    throw std::runtime_error("no H.264 encoder MFT available on this system");
  }

  // Activate the primary MFT
  hr = activations[0]->ActivateObject(IID_PPV_ARGS(&transform_));
  for (UINT32 i = 0; i < activation_count; ++i) {
    activations[i]->Release();
  }
  CoTaskMemFree(activations);
  check_hresult(hr, "IMFActivate::ActivateObject");

  // 3. Configure Transform attributes
  Microsoft::WRL::ComPtr<IMFAttributes> attributes;
  if (SUCCEEDED(transform_->GetAttributes(&attributes)) && attributes) {
    UINT32 async = FALSE;
    if (SUCCEEDED(attributes->GetUINT32(MF_TRANSFORM_ASYNC, &async)) && async) {
      attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
    }
  }

  // Associate D3D manager
  hr = transform_->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,
                                  reinterpret_cast<ULONG_PTR>(device_manager_.Get()));
  // Some software MFTs may return E_NOTIMPL, ignore if so
  if (FAILED(hr) && hr != E_NOTIMPL) {
    check_hresult(hr, "MFT_MESSAGE_SET_D3D_MANAGER");
  }

  // Get stream IDs
  DWORD input_count = 0, output_count = 0;
  hr = transform_->GetStreamCount(&input_count, &output_count);
  check_hresult(hr, "IMFTransform::GetStreamCount");

  hr = transform_->GetStreamIDs(1, &input_stream_id_, 1, &output_stream_id_);
  if (hr == E_NOTIMPL) {
    input_stream_id_ = 0;
    output_stream_id_ = 0;
  }

  configure_media_types();
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
  check_hresult(output_type->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main), "SetUINT32 MF_MT_MPEG2_PROFILE");

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
  HRESULT hr = transform_->QueryInterface(IID_PPV_ARGS(&codec_api_));
  if (FAILED(hr) || !codec_api_) {
    return;
  }

  VARIANT val;
  VariantInit(&val);

  // 1. Low latency mode
  val.vt = VT_BOOL;
  val.boolVal = VARIANT_TRUE;
  codec_api_->SetValue(&CODECAPI_AVLowLatencyMode, &val);

  // 2. Real-time encoding
  val.vt = VT_BOOL;
  val.boolVal = VARIANT_TRUE;
  codec_api_->SetValue(&CODECAPI_AVEncCommonRealTime, &val);

  // 3. Peak-constrained VBR or CBR rate control
  val.vt = VT_UI4;
  val.ulVal = eAVEncCommonRateControlMode_CBR;
  codec_api_->SetValue(&CODECAPI_AVEncCommonRateControlMode, &val);

  // 4. Target bitrate
  val.vt = VT_UI4;
  val.ulVal = target_bitrate_bps_;
  codec_api_->SetValue(&CODECAPI_AVEncCommonMeanBitRate, &val);

  // 5. Zero B-frames for minimum encode delay
  val.vt = VT_UI4;
  val.ulVal = 0;
  codec_api_->SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &val);

  // 6. GOP size
  val.vt = VT_UI4;
  val.ulVal = fps_ * 2;  // 2-second keyframe interval default
  codec_api_->SetValue(&CODECAPI_AVEncMPVGOPSize, &val);

  VariantClear(&val);
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
  if (current_in_flight_ >= max_queue_depth_) {
    return MfEncoderStatus::QueueFull;
  }

  // Handle forced IDR if requested
  if (idr_requested_ && codec_api_) {
    VARIANT val;
    VariantInit(&val);
    val.vt = VT_UI4;
    val.ulVal = 1;
    codec_api_->SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &val);
    VariantClear(&val);
    idr_requested_ = false;
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

  ++current_in_flight_;
  in_flight_sequences_.push_back(capture_sequence);
  in_flight_timestamps_.push_back(timestamp_ns);

  return MfEncoderStatus::Ok;
}

bool MfH264Encoder::convert_to_annex_b(const std::uint8_t* data, std::size_t size, std::vector<std::uint8_t>& out) {
  if (data == nullptr || size == 0) return false;

  // If already starts with Annex-B 3-byte or 4-byte start code
  if (size >= 4 && data[0] == 0 && data[1] == 0 && (data[2] == 1 || (data[2] == 0 && data[3] == 1))) {
    out.assign(data, data + size);
    return true;
  }

  // Length-delimited (AVCC / 4-byte length prefix format)
  out.clear();
  out.reserve(size + 16);

  std::size_t offset = 0;
  while (offset + 4 <= size) {
    const std::uint32_t nalu_len = (static_cast<std::uint32_t>(data[offset]) << 24) |
                                   (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
                                   (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
                                   static_cast<std::uint32_t>(data[offset + 3]);
    offset += 4;
    if (offset + nalu_len > size) {
      // Malformed NALU length, fallback to raw copy
      out.assign(data, data + size);
      return true;
    }
    // 4-byte Annex-B start code
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x01);
    out.insert(out.end(), data + offset, data + offset + nalu_len);
    offset += nalu_len;
  }

  return !out.empty();
}

MfEncoderStatus MfH264Encoder::poll_output(std::optional<MfEncodedPacket>& packet) {
  std::scoped_lock lock(mutex_);
  packet.reset();
  if (!started_ || !transform_) {
    return MfEncoderStatus::InvalidState;
  }

  MFT_OUTPUT_STREAM_INFO stream_info{};
  HRESULT hr = transform_->GetOutputStreamInfo(output_stream_id_, &stream_info);
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  const DWORD buffer_size = stream_info.cbSize > 0 ? stream_info.cbSize : (2 * 1024 * 1024);

  Microsoft::WRL::ComPtr<IMFMediaBuffer> media_buffer;
  hr = MFCreateMemoryBuffer(buffer_size, &media_buffer);
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  Microsoft::WRL::ComPtr<IMFSample> output_sample;
  hr = MFCreateSample(&output_sample);
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  hr = output_sample->AddBuffer(media_buffer.Get());
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  MFT_OUTPUT_DATA_BUFFER output_data{};
  output_data.dwStreamID = output_stream_id_;
  output_data.pSample = output_sample.Get();

  DWORD process_status = 0;
  hr = transform_->ProcessOutput(0, 1, &output_data, &process_status);
  if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) {
    return MfEncoderStatus::NoOutput;
  }
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  // Release any events returned
  if (output_data.pEvents) {
    output_data.pEvents->Release();
    output_data.pEvents = nullptr;
  }

  BYTE* buffer_data = nullptr;
  DWORD current_len = 0;
  hr = media_buffer->Lock(&buffer_data, nullptr, &current_len);
  if (FAILED(hr)) {
    return status_from_hresult(hr);
  }

  UINT32 clean_point = FALSE;
  output_sample->GetUINT32(MFSampleExtension_CleanPoint, &clean_point);

  std::uint64_t sequence = 0;
  std::uint64_t timestamp = 0;
  if (!in_flight_sequences_.empty()) {
    sequence = in_flight_sequences_.front();
    in_flight_sequences_.erase(in_flight_sequences_.begin());
  }
  if (!in_flight_timestamps_.empty()) {
    timestamp = in_flight_timestamps_.front();
    in_flight_timestamps_.erase(in_flight_timestamps_.begin());
  }
  if (current_in_flight_ > 0) {
    --current_in_flight_;
  }

  MfEncodedPacket encoded{};
  encoded.is_keyframe = (clean_point != FALSE);
  encoded.capture_sequence = sequence;
  encoded.timestamp_ns = timestamp;

  static_cast<void>(convert_to_annex_b(buffer_data, current_len, encoded.data));
  media_buffer->Unlock();

  packet = std::move(encoded);
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::request_idr() {
  std::scoped_lock lock(mutex_);
  idr_requested_ = true;
  if (codec_api_) {
    VARIANT val;
    VariantInit(&val);
    val.vt = VT_UI4;
    val.ulVal = 1;
    codec_api_->SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &val);
    VariantClear(&val);
  }
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::update_bitrate(UINT target_bitrate_bps) {
  std::scoped_lock lock(mutex_);
  target_bitrate_bps_ = target_bitrate_bps;
  if (codec_api_) {
    VARIANT val;
    VariantInit(&val);
    val.vt = VT_UI4;
    val.ulVal = target_bitrate_bps_;
    codec_api_->SetValue(&CODECAPI_AVEncCommonMeanBitRate, &val);
    VariantClear(&val);
  }
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::drain() {
  std::scoped_lock lock(mutex_);
  if (!started_ || !transform_) {
    return MfEncoderStatus::InvalidState;
  }
  transform_->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0);
  return MfEncoderStatus::Ok;
}

MfEncoderStatus MfH264Encoder::quiesce() noexcept {
  std::scoped_lock lock(mutex_);
  if (transform_) {
    transform_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
  }
  current_in_flight_ = 0;
  in_flight_sequences_.clear();
  in_flight_timestamps_.clear();
  return MfEncoderStatus::Ok;
}

}  // namespace latencydesk
