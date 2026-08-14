#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <codecapi.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wrl/client.h>

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

using Microsoft::WRL::ComPtr;

namespace {

void check(const HRESULT result, const char* operation) {
  if (FAILED(result)) {
    throw std::runtime_error(std::string(operation) + " failed, HRESULT=" +
                             std::to_string(static_cast<unsigned long>(result)));
  }
}

class Runtime final {
 public:
  Runtime() {
    check(CoInitializeEx(nullptr, COINIT_MULTITHREADED), "CoInitializeEx");
    check(MFStartup(MF_VERSION, MFSTARTUP_LITE), "MFStartup");
  }
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;
  ~Runtime() {
    static_cast<void>(MFShutdown());
    CoUninitialize();
  }
};

}  // namespace

int main() try {
  [[maybe_unused]] Runtime runtime;
  MFT_REGISTER_TYPE_INFO input{MFMediaType_Video, MFVideoFormat_H264};
  MFT_REGISTER_TYPE_INFO output{MFMediaType_Video, MFVideoFormat_NV12};
  IMFActivate** activations = nullptr;
  UINT32 count = 0;
  check(MFTEnumEx(MFT_CATEGORY_VIDEO_DECODER,
                  MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
                  &input, &output, &activations, &count),
        "MFTEnumEx");
  if (count == 0) {
    std::cout << "{\"hardware_h264_decoder_count\":0,\"available\":false}\n";
    return 2;
  }

  ComPtr<IMFTransform> transform;
  check(activations[0]->ActivateObject(IID_PPV_ARGS(&transform)), "ActivateObject");
  ComPtr<ICodecAPI> codec_api;
  bool low_latency_set = false;
  if (SUCCEEDED(transform.As(&codec_api))) {
    VARIANT value;
    VariantInit(&value);
    value.vt = VT_BOOL;
    value.boolVal = VARIANT_TRUE;
    low_latency_set =
        SUCCEEDED(codec_api->SetValue(&CODECAPI_AVLowLatencyMode, &value));
    VariantClear(&value);
  }
  for (UINT32 index = 0; index < count; ++index) {
    activations[index]->Release();
  }
  CoTaskMemFree(activations);
  std::cout << "{\"hardware_h264_decoder_count\":" << count
            << ",\"available\":true,\"low_latency_property_set\":"
            << std::boolalpha << low_latency_set << "}\n";
  return low_latency_set ? EXIT_SUCCESS : 3;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return EXIT_FAILURE;
}
