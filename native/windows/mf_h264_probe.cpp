#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <codecapi.h>
#include <d3d11.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <mftransform.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using Microsoft::WRL::ComPtr;

namespace {

constexpr UINT kWidth = 640;
constexpr UINT kHeight = 360;
constexpr UINT32 kFrameRate = 60;
constexpr UINT32 kBitrate = 2'000'000;
constexpr LONGLONG kFrameDuration = 10'000'000 / kFrameRate;
constexpr DWORD kEventTimeoutMs = 3'000;
constexpr ULONGLONG kProbeDeadlineMs = 10'000;
constexpr UINT kMaxMftEvents = 32;
constexpr std::size_t kMinimumIdrSliceHeaderBitsAfterPpsId = 8;
constexpr std::size_t kMaxAccessUnitBytes = 16 * 1024 * 1024;
constexpr std::size_t kMaxRbspBytes = 4 * 1024 * 1024;
constexpr std::size_t kMaxNalUnits = 2'048;
constexpr std::size_t kMaxOutputBytes = 32 * 1024 * 1024;

struct ParsedOptions final {
  bool show_help = false;
};

struct ProbeReport final {
  UINT32 hardware_h264_mft_count = 0;
  bool available = false;
  bool low_latency_property_set = false;
  bool nalu_length_information_requested = false;
  bool nalu_length_information_seen = false;
  UINT input_frames_submitted = 0;
  UINT output_samples = 0;
  UINT access_units = 0;
  std::uint64_t output_bytes = 0;
  std::string selected;
  std::string failure;
};

[[nodiscard]] std::string format_hresult(const HRESULT result) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  const auto value = static_cast<std::uint32_t>(result);
  std::string formatted = "0x";
  formatted.reserve(10);
  for (int shift = 28; shift >= 0; shift -= 4) {
    formatted.push_back(kHex[(value >> shift) & 0x0F]);
  }
  return formatted;
}

[[nodiscard]] std::string format_win32_error(const DWORD error) {
  return "win32_error=" + std::to_string(error);
}

void check(const HRESULT result, const std::string_view operation) {
  if (FAILED(result)) {
    throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                             format_hresult(result));
  }
}

[[nodiscard]] std::string narrow(const wchar_t* value) {
  if (value == nullptr) return {};
  const int bytes = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
  if (bytes <= 1) return {};
  std::string output(static_cast<std::size_t>(bytes), '\0');
  check(HRESULT_FROM_WIN32(
            WideCharToMultiByte(CP_UTF8, 0, value, -1, output.data(), bytes, nullptr, nullptr) == 0
                ? GetLastError()
                : ERROR_SUCCESS),
        "WideCharToMultiByte");
  output.pop_back();
  return output;
}

[[nodiscard]] std::string json_escape(const std::string_view value) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string escaped;
  escaped.reserve(value.size());
  for (const char raw_character : value) {
    const auto character = static_cast<unsigned char>(raw_character);
    switch (character) {
      case '"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (character < 0x20) {
          escaped += "\\u00";
          escaped.push_back(kHex[character >> 4]);
          escaped.push_back(kHex[character & 0x0F]);
        } else {
          escaped.push_back(static_cast<char>(character));
        }
    }
  }
  return escaped;
}

[[nodiscard]] const char* json_bool(const bool value) {
  return value ? "true" : "false";
}

void print_usage() {
  std::cout << "Usage: latencydesk_win_mf_h264_probe [--help]\n";
}

void print_report(const ProbeReport& report) {
  std::cout << "{\"hardware_h264_mft_count\":" << report.hardware_h264_mft_count
            << ",\"available\":" << json_bool(report.available)
            << ",\"selected\":\"" << json_escape(report.selected) << "\""
            << ",\"low_latency_property_set\":" << json_bool(report.low_latency_property_set)
            << ",\"nalu_length_information_requested\":"
            << json_bool(report.nalu_length_information_requested)
            << ",\"nalu_length_information_seen\":"
            << json_bool(report.nalu_length_information_seen)
            << ",\"input_frames_submitted\":" << report.input_frames_submitted
            << ",\"output_samples\":" << report.output_samples
            << ",\"access_units\":" << report.access_units
            << ",\"output_bytes\":" << report.output_bytes
            << ",\"failure\":\"" << json_escape(report.failure) << "\"}\n";
}

[[nodiscard]] ParsedOptions parse_options(const int argc, char* argv[]) {
  ParsedOptions parsed;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--help" || argument == "-h") {
      parsed.show_help = true;
      continue;
    }
    throw std::runtime_error("unknown argument: " + std::string(argument));
  }
  return parsed;
}

class Runtime final {
 public:
  Runtime() {
    check(CoInitializeEx(nullptr, COINIT_MULTITHREADED), "CoInitializeEx");
    com_initialized_ = true;
    try {
      check(MFStartup(MF_VERSION, MFSTARTUP_FULL), "MFStartup");
      mf_started_ = true;
    } catch (...) {
      CoUninitialize();
      com_initialized_ = false;
      throw;
    }
  }

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  ~Runtime() {
    if (mf_started_) static_cast<void>(MFShutdown());
    if (com_initialized_) CoUninitialize();
  }

 private:
  bool com_initialized_ = false;
  bool mf_started_ = false;
};

struct D3DResources final {
  ComPtr<ID3D11Device> device;
  ComPtr<ID3D11DeviceContext> context;
  ComPtr<IMFDXGIDeviceManager> manager;
  UINT reset_token = 0;
  D3D_FEATURE_LEVEL feature_level = D3D_FEATURE_LEVEL_9_1;
};

[[nodiscard]] D3DResources create_d3d_resources() {
  D3DResources resources;
  constexpr D3D_FEATURE_LEVEL requested_level = D3D_FEATURE_LEVEL_11_0;
  check(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                          D3D11_CREATE_DEVICE_VIDEO_SUPPORT, &requested_level, 1,
                          D3D11_SDK_VERSION, &resources.device, &resources.feature_level,
                          &resources.context),
        "D3D11CreateDevice");
  if (resources.feature_level < D3D_FEATURE_LEVEL_11_0) {
    throw std::runtime_error("D3D11 feature level 11_0 is required");
  }
  check(MFCreateDXGIDeviceManager(&resources.reset_token, &resources.manager),
        "MFCreateDXGIDeviceManager");
  check(resources.manager->ResetDevice(resources.device.Get(), resources.reset_token),
        "IMFDXGIDeviceManager::ResetDevice");
  return resources;
}

struct ActivationList final {
  IMFActivate** values = nullptr;
  UINT32 count = 0;

  ActivationList() = default;
  ActivationList(const ActivationList&) = delete;
  ActivationList& operator=(const ActivationList&) = delete;

  ActivationList(ActivationList&& other) noexcept : values(other.values), count(other.count) {
    other.values = nullptr;
    other.count = 0;
  }

  ActivationList& operator=(ActivationList&& other) noexcept {
    if (this == &other) return *this;
    release();
    values = other.values;
    count = other.count;
    other.values = nullptr;
    other.count = 0;
    return *this;
  }

  ~ActivationList() {
    release();
  }

 private:
  void release() noexcept {
    for (UINT32 index = 0; index < count; ++index) {
      if (values[index] != nullptr) values[index]->Release();
    }
    CoTaskMemFree(values);
    values = nullptr;
    count = 0;
  }
};

[[nodiscard]] ActivationList enumerate_hardware_h264_encoders() {
  MFT_REGISTER_TYPE_INFO input{MFMediaType_Video, MFVideoFormat_NV12};
  MFT_REGISTER_TYPE_INFO output{MFMediaType_Video, MFVideoFormat_H264};
  ActivationList activations;
  check(MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER,
                  MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER, &input, &output,
                  &activations.values, &activations.count),
        "MFTEnumEx");
  return activations;
}

[[nodiscard]] std::string friendly_name(IMFActivate* activation) {
  wchar_t* allocated = nullptr;
  UINT32 length = 0;
  const HRESULT result =
      activation->GetAllocatedString(MFT_FRIENDLY_NAME_Attribute, &allocated, &length);
  if (FAILED(result)) return "unnamed_hardware_h264_mft";
  const std::string name = narrow(allocated);
  CoTaskMemFree(allocated);
  return name.empty() ? "unnamed_hardware_h264_mft" : name;
}

class CandidateSession final {
 public:
  explicit CandidateSession(IMFActivate* activation) : activation_(activation) {
    check(activation_->ActivateObject(IID_PPV_ARGS(&transform_)), "IMFActivate::ActivateObject");
  }

  CandidateSession(const CandidateSession&) = delete;
  CandidateSession& operator=(const CandidateSession&) = delete;

  ~CandidateSession() {
    abort();
  }

  [[nodiscard]] IMFTransform* transform() const {
    return transform_.Get();
  }

  void finish() noexcept {
    if (finished_) return;
    if (transform_) {
      static_cast<void>(
          transform_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0));
      ComPtr<IMFShutdown> shutdown;
      if (SUCCEEDED(transform_.As(&shutdown))) static_cast<void>(shutdown->Shutdown());
      transform_.Reset();
    }
    if (activation_ != nullptr) static_cast<void>(activation_->ShutdownObject());
    finished_ = true;
  }

  void abort() noexcept {
    if (finished_) return;
    if (transform_) {
      static_cast<void>(transform_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0));
    }
    finish();
  }

 private:
  IMFActivate* activation_ = nullptr;
  ComPtr<IMFTransform> transform_;
  bool finished_ = false;
};

class MftEventWaiter final : public IMFAsyncCallback {
 public:
  explicit MftEventWaiter(IMFMediaEventGenerator* event_source) : event_source_(event_source) {
    ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ready_event_ == nullptr) {
      throw std::runtime_error("CreateEventW failed, " + format_win32_error(GetLastError()));
    }
  }

  MftEventWaiter(const MftEventWaiter&) = delete;
  MftEventWaiter& operator=(const MftEventWaiter&) = delete;

  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID interface_id, void** object) override {
    if (object == nullptr) return E_POINTER;
    *object = nullptr;
    if (interface_id == __uuidof(IUnknown) || interface_id == __uuidof(IMFAsyncCallback)) {
      *object = static_cast<IMFAsyncCallback*>(this);
      AddRef();
      return S_OK;
    }
    return E_NOINTERFACE;
  }

  ULONG STDMETHODCALLTYPE AddRef() override {
    return references_.fetch_add(1, std::memory_order_relaxed) + 1;
  }

  ULONG STDMETHODCALLTYPE Release() override {
    const ULONG remaining = references_.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (remaining == 0) delete this;
    return remaining;
  }

  HRESULT STDMETHODCALLTYPE GetParameters(DWORD*, DWORD*) override {
    return E_NOTIMPL;
  }

  HRESULT STDMETHODCALLTYPE Invoke(IMFAsyncResult* result) override {
    ComPtr<IMFMediaEvent> event;
    const HRESULT completion = event_source_->EndGetEvent(result, &event);
    {
      const std::lock_guard lock(mutex_);
      completion_ = completion;
      event_ = event;
    }
    static_cast<void>(SetEvent(ready_event_));
    return S_OK;
  }

  void arm() {
    if (armed_) throw std::runtime_error("MFT event waiter was armed twice");
    {
      const std::lock_guard lock(mutex_);
      completion_ = E_PENDING;
      event_.Reset();
    }
    if (ResetEvent(ready_event_) == FALSE) {
      throw std::runtime_error("ResetEvent failed, " + format_win32_error(GetLastError()));
    }
    check(event_source_->BeginGetEvent(this, nullptr), "IMFMediaEventGenerator::BeginGetEvent");
    armed_ = true;
  }

  [[nodiscard]] ComPtr<IMFMediaEvent> wait(const DWORD timeout_ms) {
    if (!armed_) throw std::runtime_error("MFT event waiter was not armed");
    const DWORD result = WaitForSingleObject(ready_event_, timeout_ms);
    if (result == WAIT_TIMEOUT) {
      throw std::runtime_error("timed out waiting for a Media Foundation MFT event");
    }
    if (result != WAIT_OBJECT_0) {
      throw std::runtime_error("WaitForSingleObject failed, " +
                               format_win32_error(GetLastError()));
    }
    armed_ = false;
    ComPtr<IMFMediaEvent> event;
    {
      const std::lock_guard lock(mutex_);
      check(completion_, "IMFMediaEventGenerator::EndGetEvent");
      event.Attach(event_.Detach());
    }
    if (!event) throw std::runtime_error("MFT event callback completed without an event");
    return event;
  }

 private:
  ~MftEventWaiter() {
    if (ready_event_ != nullptr) CloseHandle(ready_event_);
  }

  std::atomic<ULONG> references_{1};
  ComPtr<IMFMediaEventGenerator> event_source_;
  HANDLE ready_event_ = nullptr;
  std::mutex mutex_;
  HRESULT completion_ = E_PENDING;
  ComPtr<IMFMediaEvent> event_;
  bool armed_ = false;
};

[[nodiscard]] ComPtr<IMFMediaType> create_input_type() {
  ComPtr<IMFMediaType> type;
  check(MFCreateMediaType(&type), "MFCreateMediaType(input)");
  check(type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video), "input SetGUID(MF_MT_MAJOR_TYPE)");
  check(type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12), "input SetGUID(MF_MT_SUBTYPE)");
  check(MFSetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, kWidth, kHeight),
        "input MFSetAttributeSize(MF_MT_FRAME_SIZE)");
  check(MFSetAttributeRatio(type.Get(), MF_MT_FRAME_RATE, kFrameRate, 1),
        "input MFSetAttributeRatio(MF_MT_FRAME_RATE)");
  check(MFSetAttributeRatio(type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1),
        "input MFSetAttributeRatio(MF_MT_PIXEL_ASPECT_RATIO)");
  check(type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive),
        "input SetUINT32(MF_MT_INTERLACE_MODE)");
  return type;
}

[[nodiscard]] ComPtr<IMFMediaType> create_output_type(const bool request_nalu_lengths) {
  ComPtr<IMFMediaType> type;
  check(MFCreateMediaType(&type), "MFCreateMediaType(output)");
  check(type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video), "output SetGUID(MF_MT_MAJOR_TYPE)");
  check(type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264), "output SetGUID(MF_MT_SUBTYPE)");
  check(MFSetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, kWidth, kHeight),
        "output MFSetAttributeSize(MF_MT_FRAME_SIZE)");
  check(MFSetAttributeRatio(type.Get(), MF_MT_FRAME_RATE, kFrameRate, 1),
        "output MFSetAttributeRatio(MF_MT_FRAME_RATE)");
  check(MFSetAttributeRatio(type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1),
        "output MFSetAttributeRatio(MF_MT_PIXEL_ASPECT_RATIO)");
  check(type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive),
        "output SetUINT32(MF_MT_INTERLACE_MODE)");
  check(type->SetUINT32(MF_MT_AVG_BITRATE, kBitrate), "output SetUINT32(MF_MT_AVG_BITRATE)");
  if (request_nalu_lengths) {
    check(type->SetUINT32(MF_NALU_LENGTH_SET, TRUE), "output SetUINT32(MF_NALU_LENGTH_SET)");
  }
  return type;
}

void require_low_latency_property(IMFTransform* transform) {
  ComPtr<ICodecAPI> codec_api;
  check(transform->QueryInterface(IID_PPV_ARGS(&codec_api)), "QueryInterface(ICodecAPI)");
  VARIANT value;
  VariantInit(&value);
  value.vt = VT_BOOL;
  value.boolVal = VARIANT_TRUE;
  const HRESULT result = codec_api->SetValue(&CODECAPI_AVLowLatencyMode, &value);
  VariantClear(&value);
  check(result, "ICodecAPI::SetValue(CODECAPI_AVLowLatencyMode)");
}

struct StreamIds final {
  DWORD input = 0;
  DWORD output = 0;
};

[[nodiscard]] StreamIds get_stream_ids(IMFTransform* transform) {
  DWORD input_count = 0;
  DWORD output_count = 0;
  check(transform->GetStreamCount(&input_count, &output_count), "IMFTransform::GetStreamCount");
  if (input_count != 1 || output_count != 1) {
    throw std::runtime_error("probe requires exactly one input and one output stream");
  }
  StreamIds ids;
  const HRESULT result = transform->GetStreamIDs(1, &ids.input, 1, &ids.output);
  if (result == E_NOTIMPL) return ids;
  check(result, "IMFTransform::GetStreamIDs");
  return ids;
}

struct StreamConfiguration final {
  StreamIds ids;
  bool nalu_length_information_requested = false;
};

[[nodiscard]] StreamConfiguration configure_transform(IMFTransform* transform,
                                                       const D3DResources& d3d) {
  ComPtr<IMFAttributes> attributes;
  check(transform->GetAttributes(&attributes), "IMFTransform::GetAttributes");
  UINT32 asynchronous = FALSE;
  check(attributes->GetUINT32(MF_TRANSFORM_ASYNC, &asynchronous),
        "IMFAttributes::GetUINT32(MF_TRANSFORM_ASYNC)");
  if (asynchronous != TRUE) {
    throw std::runtime_error("hardware H.264 MFT did not identify itself as asynchronous");
  }
  check(attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE),
        "IMFAttributes::SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK)");
  require_low_latency_property(transform);
  const StreamIds ids = get_stream_ids(transform);
  check(transform->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,
                                  reinterpret_cast<ULONG_PTR>(d3d.manager.Get())),
        "IMFTransform::ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER)");

  const ComPtr<IMFMediaType> input = create_input_type();
  ComPtr<IMFMediaType> output = create_output_type(true);
  bool input_type_set = false;
  bool nalu_lengths_requested = true;
  HRESULT output_result = transform->SetOutputType(ids.output, output.Get(), 0);
  if (output_result == MF_E_TRANSFORM_TYPE_NOT_SET) {
    check(transform->SetInputType(ids.input, input.Get(), 0), "IMFTransform::SetInputType");
    input_type_set = true;
    output_result = transform->SetOutputType(ids.output, output.Get(), 0);
  }
  if (FAILED(output_result)) {
    check(output->DeleteItem(MF_NALU_LENGTH_SET), "output DeleteItem(MF_NALU_LENGTH_SET)");
    nalu_lengths_requested = false;
    check(transform->SetOutputType(ids.output, output.Get(), 0), "IMFTransform::SetOutputType");
  }
  if (!input_type_set) {
    check(transform->SetInputType(ids.input, input.Get(), 0), "IMFTransform::SetInputType");
  }
  return StreamConfiguration{ids, nalu_lengths_requested};
}

[[nodiscard]] ComPtr<IMFSample> create_synthetic_nv12_sample(const D3DResources& d3d) {
  D3D11_TEXTURE2D_DESC description{};
  description.Width = kWidth;
  description.Height = kHeight;
  description.MipLevels = 1;
  description.ArraySize = 1;
  description.Format = DXGI_FORMAT_NV12;
  description.SampleDesc.Count = 1;
  description.Usage = D3D11_USAGE_DEFAULT;
  description.BindFlags = D3D11_BIND_SHADER_RESOURCE;

  std::vector<std::uint8_t> pixels(static_cast<std::size_t>(kWidth) * kHeight * 3 / 2);
  for (UINT y = 0; y < kHeight; ++y) {
    for (UINT x = 0; x < kWidth; ++x) {
      const UINT block = ((x / 32) + (y / 32)) & 1U;
      pixels[static_cast<std::size_t>(y) * kWidth + x] =
          static_cast<std::uint8_t>(block == 0 ? 224 : 32);
    }
  }
  const std::size_t chroma_offset = static_cast<std::size_t>(kWidth) * kHeight;
  for (UINT y = 0; y < kHeight / 2; ++y) {
    for (UINT x = 0; x < kWidth; x += 2) {
      pixels[chroma_offset + static_cast<std::size_t>(y) * kWidth + x] = 128;
      pixels[chroma_offset + static_cast<std::size_t>(y) * kWidth + x + 1] = 128;
    }
  }

  D3D11_SUBRESOURCE_DATA initial_data{};
  initial_data.pSysMem = pixels.data();
  initial_data.SysMemPitch = kWidth;
  ComPtr<ID3D11Texture2D> texture;
  check(d3d.device->CreateTexture2D(&description, &initial_data, &texture),
        "ID3D11Device::CreateTexture2D(NV12)");

  ComPtr<IMFMediaBuffer> buffer;
  check(MFCreateDXGISurfaceBuffer(__uuidof(ID3D11Texture2D), texture.Get(), 0, FALSE, &buffer),
        "MFCreateDXGISurfaceBuffer");
  ComPtr<IMFSample> sample;
  check(MFCreateSample(&sample), "MFCreateSample(input)");
  check(sample->AddBuffer(buffer.Get()), "IMFSample::AddBuffer(DXGI surface)");
  check(sample->SetSampleTime(0), "IMFSample::SetSampleTime");
  check(sample->SetSampleDuration(kFrameDuration), "IMFSample::SetSampleDuration");
  return sample;
}

struct NalSpan final {
  const std::uint8_t* bytes = nullptr;
  std::size_t size = 0;
};

struct AccessUnitSummary final {
  bool has_idr_slice = false;
  bool has_non_idr_slice = false;
  bool has_b_slice = false;
};

enum class SliceClass {
  p,
  b,
  i,
  sp,
  si,
};

class BitReader final {
 public:
  BitReader(const std::uint8_t* bytes, const std::size_t size) : bytes_(bytes), size_(size) {}

  [[nodiscard]] std::uint8_t read_bit() {
    if (bit_offset_ / 8 >= size_) throw std::runtime_error("truncated H.264 slice header");
    const std::uint8_t bit =
        static_cast<std::uint8_t>((bytes_[bit_offset_ / 8] >> (7 - (bit_offset_ % 8))) & 1U);
    ++bit_offset_;
    return bit;
  }

  [[nodiscard]] std::uint32_t read_ue() {
    std::uint32_t leading = 0;
    while (read_bit() == 0) {
      ++leading;
      if (leading > 31) throw std::runtime_error("H.264 Exp-Golomb value overflows u32");
    }
    std::uint32_t suffix = 0;
    for (std::uint32_t index = 0; index < leading; ++index) {
      suffix = (suffix << 1) | read_bit();
    }
    const std::uint32_t base = (std::uint32_t{1} << leading) - 1;
    return base + suffix;
  }
  void require_bits(const std::size_t count) {
    const std::size_t total_bits = size_ * 8;
    if (bit_offset_ > total_bits || count > total_bits - bit_offset_) {
      throw std::runtime_error("truncated H.264 slice header");
    }
  }


 private:
  const std::uint8_t* bytes_;
  std::size_t size_;
  std::size_t bit_offset_ = 0;
};

[[nodiscard]] std::vector<std::uint8_t> unescape_rbsp(const NalSpan ebsp) {
  if (ebsp.size > kMaxRbspBytes + kMaxRbspBytes / 2) {
    throw std::runtime_error("H.264 RBSP exceeds the configured bound");
  }
  std::vector<std::uint8_t> rbsp;
  rbsp.reserve(std::min(ebsp.size, kMaxRbspBytes));
  std::uint8_t zero_count = 0;
  bool next_byte_after_epb = false;
  for (std::size_t cursor = 0; cursor < ebsp.size; ++cursor) {
    const std::uint8_t byte = ebsp.bytes[cursor];
    if (zero_count >= 2 && byte <= 3 && !next_byte_after_epb) {
      if (byte != 3) {
        throw std::runtime_error("H.264 RBSP omits a required emulation-prevention byte");
      }
      if (cursor + 1 >= ebsp.size || ebsp.bytes[cursor + 1] > 3) {
        throw std::runtime_error("malformed H.264 emulation-prevention byte");
      }
      next_byte_after_epb = true;
      continue;
    }
    if (rbsp.size() == kMaxRbspBytes) {
      throw std::runtime_error("H.264 RBSP exceeds the configured bound");
    }
    rbsp.push_back(byte);
    next_byte_after_epb = false;
    if (byte == 0) {
      if (zero_count != std::numeric_limits<std::uint8_t>::max()) ++zero_count;
    } else {
      zero_count = 0;
    }
  }
  return rbsp;
}

[[nodiscard]] SliceClass parse_slice_class(NalSpan payload, const bool is_idr) {
  while (payload.size != 0 && payload.bytes[payload.size - 1] == 0) --payload.size;
  if (payload.size == 0) throw std::runtime_error("H.264 slice header has no RBSP data");
  const std::vector<std::uint8_t> rbsp = unescape_rbsp(payload);
  BitReader reader(rbsp.data(), rbsp.size());
  static_cast<void>(reader.read_ue());
  const std::uint32_t slice_type = reader.read_ue();
  if (slice_type > 9) throw std::runtime_error("invalid H.264 slice type");
  static_cast<void>(reader.read_ue());
  if (is_idr) reader.require_bits(kMinimumIdrSliceHeaderBitsAfterPpsId);
  switch (slice_type % 5) {
    case 0:
      return SliceClass::p;
    case 1:
      return SliceClass::b;
    case 2:
      return SliceClass::i;
    case 3:
      return SliceClass::sp;
    case 4:
      return SliceClass::si;
    default:
      throw std::runtime_error("invalid H.264 slice type");
  }
}

[[nodiscard]] std::vector<NalSpan> split_annex_b(const std::vector<std::uint8_t>& bytes) {
  struct StartCode final {
    std::size_t offset;
    std::size_t prefix_size;
  };

  std::vector<StartCode> starts;
  for (std::size_t cursor = 0; cursor + 3 <= bytes.size();) {
    const bool four_byte_start =
        cursor + 4 <= bytes.size() && bytes[cursor] == 0 && bytes[cursor + 1] == 0 &&
        bytes[cursor + 2] == 0 && bytes[cursor + 3] == 1;
    const bool three_byte_start =
        !four_byte_start && bytes[cursor] == 0 && bytes[cursor + 1] == 0 &&
        bytes[cursor + 2] == 1;
    if (four_byte_start || three_byte_start) {
      if (starts.size() == kMaxNalUnits) {
        throw std::runtime_error("H.264 access unit has too many NAL units");
      }
      const std::size_t prefix_size = four_byte_start ? 4 : 3;
      starts.push_back(StartCode{cursor, prefix_size});
      cursor += prefix_size;
    } else {
      ++cursor;
    }
  }
  if (starts.empty()) return {};
  if (std::any_of(bytes.begin(), bytes.begin() + starts.front().offset,
                  [](const std::uint8_t byte) { return byte != 0; })) {
    throw std::runtime_error("H.264 access unit contains leading garbage");
  }

  std::vector<NalSpan> nals;
  nals.reserve(starts.size());
  for (std::size_t index = 0; index < starts.size(); ++index) {
    const std::size_t begin = starts[index].offset + starts[index].prefix_size;
    const std::size_t end = index + 1 == starts.size() ? bytes.size() : starts[index + 1].offset;
    if (begin >= end) throw std::runtime_error("H.264 access unit contains an empty NAL unit");
    nals.push_back(NalSpan{bytes.data() + begin, end - begin});
  }
  return nals;
}

struct NaluLengthInformation final {
  bool partitions_sample = false;
  std::vector<NalSpan> nals;
};

[[nodiscard]] bool has_nalu_length_information(IMFSample* sample) {
  UINT32 blob_size = 0;
  const HRESULT result = sample->GetBlobSize(MF_NALU_LENGTH_INFORMATION, &blob_size);
  if (result == MF_E_ATTRIBUTENOTFOUND) return false;
  check(result, "IMFSample::GetBlobSize(MF_NALU_LENGTH_INFORMATION)");
  return true;
}

[[nodiscard]] NalSpan strip_annex_b_start_code(NalSpan nal) {
  const bool four_byte_start =
      nal.size >= 4 && nal.bytes[0] == 0 && nal.bytes[1] == 0 && nal.bytes[2] == 0 &&
      nal.bytes[3] == 1;
  const bool three_byte_start =
      !four_byte_start && nal.size >= 3 && nal.bytes[0] == 0 && nal.bytes[1] == 0 &&
      nal.bytes[2] == 1;
  const std::size_t prefix_size = four_byte_start ? 4 : three_byte_start ? 3 : 0;
  nal.bytes += prefix_size;
  nal.size -= prefix_size;
  if (nal.size == 0) {
    throw std::runtime_error("MF_NALU_LENGTH_INFORMATION contains an empty NAL unit");
  }
  return nal;
}

[[nodiscard]] NaluLengthInformation read_nalu_length_information(
    IMFSample* sample, const std::vector<std::uint8_t>& bytes) {
  UINT32 blob_size = 0;
  check(sample->GetBlobSize(MF_NALU_LENGTH_INFORMATION, &blob_size),
        "IMFSample::GetBlobSize(MF_NALU_LENGTH_INFORMATION)");
  if (blob_size == 0 || blob_size % sizeof(DWORD) != 0 ||
      blob_size > kMaxNalUnits * sizeof(DWORD) ||
      blob_size / sizeof(DWORD) > bytes.size()) {
    throw std::runtime_error("invalid MF_NALU_LENGTH_INFORMATION blob size");
  }
  std::vector<std::uint8_t> blob(blob_size);
  UINT32 copied = 0;
  check(sample->GetBlob(MF_NALU_LENGTH_INFORMATION, blob.data(), blob_size, &copied),
        "IMFSample::GetBlob(MF_NALU_LENGTH_INFORMATION)");
  if (copied != blob_size) throw std::runtime_error("truncated MF_NALU_LENGTH_INFORMATION blob");

  NaluLengthInformation information;
  information.nals.reserve(blob_size / sizeof(DWORD));
  std::size_t offset = 0;
  for (std::size_t index = 0; index < blob_size; index += sizeof(DWORD)) {
    DWORD length = 0;
    std::memcpy(&length, blob.data() + index, sizeof(length));
    if (length == 0) {
      throw std::runtime_error("MF_NALU_LENGTH_INFORMATION contains a zero-length NAL unit");
    }
    if (length > bytes.size() - offset) {
      throw std::runtime_error("MF_NALU_LENGTH_INFORMATION exceeds the output sample");
    }
    if (information.nals.size() == kMaxNalUnits) {
      throw std::runtime_error("H.264 access unit has too many NAL units");
    }
    information.nals.push_back(
        strip_annex_b_start_code(NalSpan{bytes.data() + offset, length}));
    offset += length;
  }
  if (offset != bytes.size()) {
    throw std::runtime_error("MF_NALU_LENGTH_INFORMATION does not partition the output sample");
  }
  information.partitions_sample = true;
  return information;
}

[[nodiscard]] AccessUnitSummary inspect_nals(const std::vector<NalSpan>& nals) {
  if (nals.empty()) throw std::runtime_error("H.264 output contains no NAL units");
  AccessUnitSummary summary;
  for (const NalSpan nal : nals) {
    if (nal.size == 0) throw std::runtime_error("H.264 output contains an empty NAL unit");
    const std::uint8_t header = nal.bytes[0];
    if ((header & 0x80U) != 0) throw std::runtime_error("H.264 forbidden_zero_bit is set");
    const std::uint8_t nal_type = header & 0x1FU;
    if (nal_type == 5 && (header & 0x60U) == 0) {
      throw std::runtime_error("H.264 IDR NAL has nal_ref_idc equal to zero");
    }
    switch (nal_type) {
      case 1:
      case 5: {
        const SliceClass slice =
            parse_slice_class(NalSpan{nal.bytes + 1, nal.size - 1}, nal_type == 5);
        if (nal_type == 5 && slice != SliceClass::i && slice != SliceClass::si) {
          throw std::runtime_error("H.264 IDR NAL contains a non-intra slice");
        }
        summary.has_b_slice = summary.has_b_slice || slice == SliceClass::b;
        summary.has_non_idr_slice = summary.has_non_idr_slice || nal_type == 1;
        summary.has_idr_slice = summary.has_idr_slice || nal_type == 5;
        break;
      }
      case 2:
      case 3:
      case 4:
        throw std::runtime_error("H.264 data-partition NAL units are unsupported");
      case 6:
      case 7:
      case 8:
      case 9:
      case 10:
      case 11:
      case 12:
        break;
      default:
        throw std::runtime_error("H.264 output contains an unsupported NAL unit type");
    }
  }
  if (summary.has_idr_slice && summary.has_non_idr_slice) {
    throw std::runtime_error("H.264 access unit mixes IDR and non-IDR slices");
  }
  if (summary.has_b_slice) throw std::runtime_error("H.264 output contains a B slice");
  return summary;
}

[[nodiscard]] std::vector<std::uint8_t> copy_sample_bytes(IMFSample* sample) {
  DWORD total_length = 0;
  check(sample->GetTotalLength(&total_length), "IMFSample::GetTotalLength");
  if (total_length == 0 || total_length > kMaxAccessUnitBytes) {
    throw std::runtime_error("H.264 output sample violates the access-unit byte bound");
  }
  ComPtr<IMFMediaBuffer> buffer;
  check(sample->ConvertToContiguousBuffer(&buffer), "IMFSample::ConvertToContiguousBuffer");
  BYTE* data = nullptr;
  DWORD maximum_length = 0;
  DWORD current_length = 0;
  check(buffer->Lock(&data, &maximum_length, &current_length), "IMFMediaBuffer::Lock");
  struct Unlock final {
    IMFMediaBuffer* buffer;
    ~Unlock() {
      static_cast<void>(buffer->Unlock());
    }
  } unlock{buffer.Get()};
  if (current_length == 0 || current_length > maximum_length || current_length != total_length ||
      current_length > kMaxAccessUnitBytes) {
    throw std::runtime_error("H.264 output sample violates the access-unit byte bound");
  }
  return std::vector<std::uint8_t>(data, data + current_length);
}

struct OutputValidation final {
  bool contains_picture = false;
  bool contains_idr = false;
  bool nalu_length_information_present = false;
  std::size_t bytes = 0;
};

[[nodiscard]] OutputValidation validate_output_sample(IMFSample* sample) {
  const std::vector<std::uint8_t> bytes = copy_sample_bytes(sample);
  const bool nalu_length_information_present = has_nalu_length_information(sample);
  std::vector<NalSpan> nals;
  if (nalu_length_information_present) {
    NaluLengthInformation information = read_nalu_length_information(sample, bytes);
    if (information.partitions_sample) nals.swap(information.nals);
  }
  if (nals.empty()) nals = split_annex_b(bytes);
  if (nals.empty()) {
    throw std::runtime_error(
        nalu_length_information_present
            ? "MF_NALU_LENGTH_INFORMATION does not partition non-Annex-B H.264 output"
            : "H.264 output has neither Annex-B start codes nor NAL length information");
  }
  const AccessUnitSummary summary = inspect_nals(nals);
  return OutputValidation{
      .contains_picture = summary.has_idr_slice || summary.has_non_idr_slice,
      .contains_idr = summary.has_idr_slice,
      .nalu_length_information_present = nalu_length_information_present,
      .bytes = bytes.size(),
  };
}

struct CandidateMetrics final {
  UINT input_frames_submitted = 0;
  UINT output_samples = 0;
  UINT access_units = 0;
  std::uint64_t output_bytes = 0;
  bool nalu_length_information_seen = false;
  bool saw_idr = false;
};

[[nodiscard]] DWORD mft_alignment_mask(const DWORD alignment_bytes) {
  constexpr DWORD kMaxSupportedAlignment = 512;
  const DWORD required_alignment = alignment_bytes == 0 ? 1 : alignment_bytes;
  if (required_alignment > kMaxSupportedAlignment ||
      (required_alignment & (required_alignment - 1)) != 0) {
    throw std::runtime_error("MFT requested an unsupported output-buffer alignment");
  }
  return required_alignment - 1;
}

void process_output(IMFTransform* transform, const DWORD output_stream, CandidateMetrics* metrics) {
  MFT_OUTPUT_STREAM_INFO stream_info{};
  check(transform->GetOutputStreamInfo(output_stream, &stream_info),
        "IMFTransform::GetOutputStreamInfo");

  MFT_OUTPUT_DATA_BUFFER output{};
  output.dwStreamID = output_stream;
  ComPtr<IMFSample> caller_sample;
  if ((stream_info.dwFlags &
       (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES)) == 0) {
    if (stream_info.cbSize == 0) {
      throw std::runtime_error("MFT requires caller output samples without a byte requirement");
    }
    ComPtr<IMFMediaBuffer> buffer;
    check(MFCreateAlignedMemoryBuffer(stream_info.cbSize,
                                      mft_alignment_mask(stream_info.cbAlignment), &buffer),
          "MFCreateAlignedMemoryBuffer(output)");
    check(MFCreateSample(&caller_sample), "MFCreateSample(output)");
    check(caller_sample->AddBuffer(buffer.Get()), "IMFSample::AddBuffer(output)");
    output.pSample = caller_sample.Get();
  }

  DWORD process_status = 0;
  const HRESULT result = transform->ProcessOutput(0, 1, &output, &process_status);
  if (output.pEvents != nullptr) {
    output.pEvents->Release();
    output.pEvents = nullptr;
  }
  ComPtr<IMFSample> sample;
  if (output.pSample != caller_sample.Get() && output.pSample != nullptr) {
    sample.Attach(output.pSample);
  }
  check(result, "IMFTransform::ProcessOutput");
  if ((process_status & MFT_PROCESS_OUTPUT_STATUS_NEW_STREAMS) != 0) {
    throw std::runtime_error("H.264 MFT changed its fixed output stream during the smoke probe");
  }
  if (output.dwStatus == MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE ||
      output.dwStatus == MFT_OUTPUT_DATA_BUFFER_STREAM_END) {
    throw std::runtime_error("H.264 MFT changed its fixed output stream during the smoke probe");
  }
  if (output.dwStatus != 0 && output.dwStatus != MFT_OUTPUT_DATA_BUFFER_INCOMPLETE &&
      output.dwStatus != MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE) {
    throw std::runtime_error("H.264 MFT returned an unsupported output status");
  }
  if (output.dwStatus == MFT_OUTPUT_DATA_BUFFER_NO_SAMPLE) return;
  if (output.pSample == caller_sample.Get()) sample = caller_sample;
  if (!sample) throw std::runtime_error("H.264 MFT reported output without a sample");

  const OutputValidation validation = validate_output_sample(sample.Get());
  if (metrics->output_bytes > kMaxOutputBytes - validation.bytes) {
    throw std::runtime_error("H.264 smoke probe exceeded its total output byte bound");
  }
  ++metrics->output_samples;
  metrics->output_bytes += validation.bytes;
  metrics->nalu_length_information_seen =
      metrics->nalu_length_information_seen || validation.nalu_length_information_present;
  if (validation.contains_picture) ++metrics->access_units;
  metrics->saw_idr = metrics->saw_idr || validation.contains_idr;
}

struct CandidateResult final {
  bool nalu_length_information_requested = false;
  bool nalu_length_information_seen = false;
  UINT input_frames_submitted = 0;
  UINT output_samples = 0;
  UINT access_units = 0;
  std::uint64_t output_bytes = 0;
};

[[nodiscard]] CandidateResult run_candidate(IMFActivate* activation,
                                            const D3DResources& d3d) {
  CandidateSession session(activation);
  try {
    IMFTransform* const transform = session.transform();
    const StreamConfiguration configuration = configure_transform(transform, d3d);

    ComPtr<IMFMediaEventGenerator> event_source;
    check(transform->QueryInterface(IID_PPV_ARGS(&event_source)),
          "QueryInterface(IMFMediaEventGenerator)");
    ComPtr<MftEventWaiter> waiter;
    waiter.Attach(new MftEventWaiter(event_source.Get()));
    CandidateMetrics metrics;
    bool draining = false;
    bool drain_complete = false;
    const ULONGLONG deadline = GetTickCount64() + kProbeDeadlineMs;
    UINT processed_events = 0;

    waiter->arm();
    check(transform->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0),
          "IMFTransform::ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING)");
    check(transform->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
          "IMFTransform::ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM)");

    while (!drain_complete) {
      const ULONGLONG now = GetTickCount64();
      if (now >= deadline) {
        throw std::runtime_error("hardware MFT exceeded the smoke-probe drain deadline");
      }
      const ULONGLONG remaining_ms = deadline - now;
      const DWORD timeout_ms = static_cast<DWORD>(
          std::min<ULONGLONG>(remaining_ms, static_cast<ULONGLONG>(kEventTimeoutMs)));
      const ComPtr<IMFMediaEvent> event = waiter->wait(timeout_ms);
      if (++processed_events > kMaxMftEvents) {
        throw std::runtime_error("hardware MFT exceeded the smoke-probe event bound");
      }
      MediaEventType event_type = MEUnknown;
      check(event->GetType(&event_type), "IMFMediaEvent::GetType");
      if (event_type == METransformNeedInput) {
        UINT32 stream_id = 0;
        check(event->GetUINT32(MF_EVENT_MFT_INPUT_STREAM_ID, &stream_id),
              "IMFMediaEvent::GetUINT32(MF_EVENT_MFT_INPUT_STREAM_ID)");
        if (stream_id != configuration.ids.input) {
          throw std::runtime_error("hardware MFT requested an unexpected input stream");
        }
        if (!draining) {
          const ComPtr<IMFSample> sample = create_synthetic_nv12_sample(d3d);
          check(transform->ProcessInput(configuration.ids.input, sample.Get(), 0),
                "IMFTransform::ProcessInput(DXGI NV12 surface)");
          ++metrics.input_frames_submitted;
          check(transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0),
                "IMFTransform::ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM)");
          check(transform->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0),
                "IMFTransform::ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN)");
          draining = true;
        }
      } else if (event_type == METransformHaveOutput) {
        process_output(transform, configuration.ids.output, &metrics);
      } else if (event_type == METransformDrainComplete) {
        if (!draining) throw std::runtime_error("hardware MFT drained before receiving input");
        drain_complete = true;
      } else if (event_type == MEError) {
        HRESULT status = E_FAIL;
        check(event->GetStatus(&status), "IMFMediaEvent::GetStatus(MEError)");
        throw std::runtime_error("hardware MFT emitted MEError, HRESULT=" +
                                 format_hresult(status));
      } else {
        throw std::runtime_error("hardware MFT emitted an unexpected event type");
      }
      if (!drain_complete) waiter->arm();
    }

    if (metrics.input_frames_submitted != 1 || metrics.access_units == 0 || !metrics.saw_idr) {
      throw std::runtime_error("hardware MFT did not drain a validated IDR access unit");
    }
    session.finish();
    return CandidateResult{
        .nalu_length_information_requested = configuration.nalu_length_information_requested,
        .nalu_length_information_seen = metrics.nalu_length_information_seen,
        .input_frames_submitted = metrics.input_frames_submitted,
        .output_samples = metrics.output_samples,
        .access_units = metrics.access_units,
        .output_bytes = metrics.output_bytes,
    };
  } catch (...) {
    session.abort();
    throw;
  }
}

void run_probe(ProbeReport* report) {
  const ActivationList activations = enumerate_hardware_h264_encoders();
  report->hardware_h264_mft_count = activations.count;
  if (activations.count == 0) {
    report->failure = "no_hardware_h264_mft";
    return;
  }

  const D3DResources d3d = create_d3d_resources();
  std::string last_failure;
  for (UINT32 index = 0; index < activations.count; ++index) {
    const std::string name = friendly_name(activations.values[index]);
    try {
      const CandidateResult result = run_candidate(activations.values[index], d3d);
      report->available = true;
      report->selected = name;
      report->low_latency_property_set = true;
      report->nalu_length_information_requested = result.nalu_length_information_requested;
      report->nalu_length_information_seen = result.nalu_length_information_seen;
      report->input_frames_submitted = result.input_frames_submitted;
      report->output_samples = result.output_samples;
      report->access_units = result.access_units;
      report->output_bytes = result.output_bytes;
      return;
    } catch (const std::exception& error) {
      last_failure = name + ": " + error.what();
    }
  }
  report->failure = "all_hardware_h264_mfts_failed: " + last_failure;
}

}  // namespace

int main(int argc, char* argv[]) {
  ProbeReport report;
  try {
    const ParsedOptions options = parse_options(argc, argv);
    if (options.show_help) {
      print_usage();
      return EXIT_SUCCESS;
    }
    [[maybe_unused]] Runtime runtime;
    run_probe(&report);
    print_report(report);
    return report.available ? EXIT_SUCCESS : 2;
  } catch (const std::exception& error) {
    report.failure = error.what();
    print_report(report);
    return EXIT_FAILURE;
  }
}
