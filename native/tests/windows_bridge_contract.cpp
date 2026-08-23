#include "latencydesk_windows_bridge.h"

#include "capture_detach.hpp"
#include "dda_capture_source.hpp"
#include "input_event_queue.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <type_traits>
#include <utility>

namespace bridge = latencydesk::windows_bridge;

static_assert(std::is_same_v<
              decltype(bridge::make_desktop_duplication_capture(
                  std::declval<std::uint32_t>(), std::declval<std::uint32_t>(),
                  std::declval<std::uint32_t>(), std::declval<std::uint32_t&>())),
              std::unique_ptr<bridge::Capture>>);
static_assert(std::is_same_v<
              decltype(bridge::prepare_current_process_wer_exclusion()),
              std::uint32_t>);
static_assert(std::is_same_v<
              decltype(bridge::capture_detach(
                  std::declval<bridge::Capture&>(), std::declval<std::uint32_t>(),
                  std::declval<std::uint32_t>(), std::declval<std::uint32_t>(),
                  std::declval<std::uint32_t&>())),
              std::unique_ptr<bridge::Surface>>);

#define TEST_ASSERT(cond, msg)                                            \
  do {                                                                    \
    if (!(cond)) {                                                        \
      std::cerr << "Assertion failed: (" #cond ") at line " << __LINE__   \
                << ": " << (msg) << "\n";                                 \
      return EXIT_FAILURE;                                                \
    }                                                                     \
  } while (false)

int main() {
  // 1. ABI version check
  TEST_ASSERT(bridge::bridge_abi_version() == bridge::kBridgeAbiVersion,
              "unexpected bridge ABI version");

  // Input motion may be coalesced, but transitions must never be silently
  // evicted. Saturating an all-transition queue yields one explicit marker.
  {
    bridge::InputEventQueue queue;
    queue.push(bridge::QueuedInput{.kind = bridge::kInputKindMouseMove, .x = 1});
    queue.push(bridge::QueuedInput{.kind = bridge::kInputKindMouseMove, .x = 2});
    TEST_ASSERT(queue.size() == 1U, "adjacent mouse moves must coalesce");
    bridge::QueuedInput event{};
    TEST_ASSERT(queue.pop(event), "coalesced mouse move must be readable");
    TEST_ASSERT(event.kind == bridge::kInputKindMouseMove && event.x == 2,
                "coalescing must retain the newest absolute position");

    for (std::size_t index = 0; index < bridge::InputEventQueue::kCapacity;
         ++index) {
      queue.push(bridge::QueuedInput{.kind = bridge::kInputKindKey,
                                     .pressed = static_cast<std::uint8_t>(index & 1U),
                                     .vk = static_cast<std::uint32_t>(index)});
    }
    queue.push(bridge::QueuedInput{.kind = bridge::kInputKindButton,
                                   .button = 1,
                                   .pressed = 0});
    TEST_ASSERT(queue.overflow_latched(),
                "all-transition overflow must latch fail-closed state");
    TEST_ASSERT(queue.size() == 1U,
                "overflow must collapse unsafe backlog to one marker");
    TEST_ASSERT(queue.pop(event), "overflow marker must be readable");
    TEST_ASSERT(event.kind == bridge::kInputKindOverflow,
                "transition saturation must be explicit");
  }

  // 2. Capacity bounds check
  TEST_ASSERT(!bridge::valid_capture_queue_capacity(0U),
              "capacity 0 must be invalid");
  TEST_ASSERT(bridge::valid_capture_queue_capacity(1U),
              "capacity 1 must be valid");
  TEST_ASSERT(!bridge::valid_capture_queue_capacity(2U),
              "capacity 2 must be invalid");
  TEST_ASSERT(!bridge::valid_capture_queue_capacity(UINT32_MAX),
              "capacity UINT32_MAX must be invalid");

  // 3. Every bridge status code (0 through 12)
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::Ok) == 0U,
              "BridgeStatus::Ok code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::NoFrame) == 1U,
              "BridgeStatus::NoFrame code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::AccessLost) == 2U,
              "BridgeStatus::AccessLost code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::ProtectedContent) == 3U,
              "BridgeStatus::ProtectedContent code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::PermissionDenied) == 4U,
              "BridgeStatus::PermissionDenied code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::PermissionRevoked) == 5U,
              "BridgeStatus::PermissionRevoked code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::DeviceLost) == 6U,
              "BridgeStatus::DeviceLost code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::InvalidState) == 7U,
              "BridgeStatus::InvalidState code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::InvalidArgument) == 8U,
              "BridgeStatus::InvalidArgument code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::QueueFull) == 9U,
              "BridgeStatus::QueueFull code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::Unsupported) == 10U,
              "BridgeStatus::Unsupported code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::SessionChanged) == 11U,
              "BridgeStatus::SessionChanged code mismatch");
  TEST_ASSERT(bridge::status_code(bridge::BridgeStatus::InternalFailure) == 12U,
              "BridgeStatus::InternalFailure code mismatch");

  // 4. status_from_hresult mappings for every status branch
  TEST_ASSERT(bridge::status_from_hresult(S_OK) == bridge::BridgeStatus::Ok,
              "status_from_hresult(S_OK)");
  TEST_ASSERT(bridge::status_from_hresult(DXGI_ERROR_WAIT_TIMEOUT) ==
                  bridge::BridgeStatus::NoFrame,
              "status_from_hresult(DXGI_ERROR_WAIT_TIMEOUT)");
  TEST_ASSERT(bridge::status_from_hresult(DXGI_ERROR_ACCESS_LOST) ==
                  bridge::BridgeStatus::AccessLost,
              "status_from_hresult(DXGI_ERROR_ACCESS_LOST)");
  TEST_ASSERT(bridge::status_from_hresult(DXGI_ERROR_DEVICE_REMOVED) ==
                  bridge::BridgeStatus::DeviceLost,
              "status_from_hresult(DXGI_ERROR_DEVICE_REMOVED)");
  TEST_ASSERT(bridge::status_from_hresult(DXGI_ERROR_DEVICE_RESET) ==
                  bridge::BridgeStatus::DeviceLost,
              "status_from_hresult(DXGI_ERROR_DEVICE_RESET)");
  TEST_ASSERT(bridge::status_from_hresult(DXGI_ERROR_SESSION_DISCONNECTED) ==
                  bridge::BridgeStatus::SessionChanged,
              "status_from_hresult(DXGI_ERROR_SESSION_DISCONNECTED)");
  TEST_ASSERT(bridge::status_from_hresult(E_ACCESSDENIED) ==
                  bridge::BridgeStatus::PermissionDenied,
              "status_from_hresult(E_ACCESSDENIED)");
  TEST_ASSERT(bridge::status_from_hresult(E_INVALIDARG) ==
                  bridge::BridgeStatus::InvalidArgument,
              "status_from_hresult(E_INVALIDARG)");
  TEST_ASSERT(bridge::status_from_hresult(DXGI_ERROR_INVALID_CALL) ==
                  bridge::BridgeStatus::InvalidState,
              "status_from_hresult(DXGI_ERROR_INVALID_CALL)");
  TEST_ASSERT(bridge::status_from_hresult(DXGI_ERROR_UNSUPPORTED) ==
                  bridge::BridgeStatus::Unsupported,
              "status_from_hresult(DXGI_ERROR_UNSUPPORTED)");
  TEST_ASSERT(bridge::status_from_hresult(E_FAIL) ==
                  bridge::BridgeStatus::InternalFailure,
              "status_from_hresult(E_FAIL)");
  TEST_ASSERT(bridge::status_from_hresult(E_UNEXPECTED) ==
                  bridge::BridgeStatus::InternalFailure,
              "status_from_hresult(E_UNEXPECTED)");

  // 5. status_from_wer_hresult mappings
  TEST_ASSERT(bridge::status_from_wer_hresult(S_OK) == bridge::BridgeStatus::Ok,
              "status_from_wer_hresult(S_OK)");
  TEST_ASSERT(bridge::status_from_wer_hresult(
                  HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)) ==
                  bridge::BridgeStatus::Ok,
              "status_from_wer_hresult(ERROR_ALREADY_EXISTS)");
  TEST_ASSERT(bridge::status_from_wer_hresult(E_ACCESSDENIED) ==
                  bridge::BridgeStatus::PermissionDenied,
              "status_from_wer_hresult(E_ACCESSDENIED)");
  TEST_ASSERT(bridge::status_from_wer_hresult(E_INVALIDARG) ==
                  bridge::BridgeStatus::InvalidArgument,
              "status_from_wer_hresult(E_INVALIDARG)");
  TEST_ASSERT(bridge::status_from_wer_hresult(
                  HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)) ==
                  bridge::BridgeStatus::Unsupported,
              "status_from_wer_hresult(ERROR_NOT_SUPPORTED)");
  TEST_ASSERT(bridge::status_from_wer_hresult(E_FAIL) ==
                  bridge::BridgeStatus::InternalFailure,
              "status_from_wer_hresult(E_FAIL)");

  // 6. prepare_current_process_wer_exclusion
  const auto wer_status = bridge::prepare_current_process_wer_exclusion();
  TEST_ASSERT(wer_status == bridge::status_code(bridge::BridgeStatus::Ok),
              "prepare_current_process_wer_exclusion failed");
  // Idempotence: second call must also return Ok
  const auto wer_status2 = bridge::prepare_current_process_wer_exclusion();
  TEST_ASSERT(wer_status2 == bridge::status_code(bridge::BridgeStatus::Ok),
              "prepare_current_process_wer_exclusion idempotence failed");

  // 7. make_desktop_duplication_capture capacity validation
  {
    std::uint32_t status = 0;
    auto cap_invalid0 = bridge::make_desktop_duplication_capture(0, 0, 0, status);
    TEST_ASSERT(cap_invalid0 == nullptr, "capacity 0 must return null");
    TEST_ASSERT(status == bridge::status_code(bridge::BridgeStatus::InvalidArgument),
                "capacity 0 status must be InvalidArgument");

    auto cap_invalid2 = bridge::make_desktop_duplication_capture(0, 0, 2, status);
    TEST_ASSERT(cap_invalid2 == nullptr, "capacity 2 must return null");
    TEST_ASSERT(status == bridge::status_code(bridge::BridgeStatus::InvalidArgument),
                "capacity 2 status must be InvalidArgument");

    auto cap_valid = bridge::make_desktop_duplication_capture(0, 0, 1, status);
    TEST_ASSERT(cap_valid != nullptr, "capacity 1 must return valid handle");
    TEST_ASSERT(status == bridge::status_code(bridge::BridgeStatus::Ok),
                "capacity 1 status must be Ok");

    // 8. Unstarted Capture behavior tests
    TEST_ASSERT(bridge::capture_poll(*cap_valid, 0) ==
                    bridge::status_code(bridge::BridgeStatus::InvalidState),
                "unstarted capture_poll must return InvalidState");

    std::uint32_t detach_status = 0;
    auto surface = bridge::capture_detach(*cap_valid, 0, 0, 0, detach_status);
    TEST_ASSERT(surface == nullptr, "unstarted capture_detach must return null");
    TEST_ASSERT(detach_status ==
                    bridge::status_code(bridge::BridgeStatus::InvalidState),
                "unstarted capture_detach status must be InvalidState");

    TEST_ASSERT(bridge::capture_discard(*cap_valid) ==
                    bridge::status_code(bridge::BridgeStatus::InvalidState),
                "unstarted capture_discard must return InvalidState");

    TEST_ASSERT(bridge::capture_pending_width(*cap_valid) == 0U,
                "unstarted pending width must be 0");
    TEST_ASSERT(bridge::capture_pending_height(*cap_valid) == 0U,
                "unstarted pending height must be 0");
    TEST_ASSERT(bridge::capture_pending_format(*cap_valid) == 0U,
                "unstarted pending format must be 0");
    TEST_ASSERT(!bridge::capture_pending_pointer_visible(*cap_valid),
                "unstarted pending pointer visible must be false");
    TEST_ASSERT(bridge::capture_pending_pointer_x(*cap_valid) == 0,
                "unstarted pending pointer x must be 0");
    TEST_ASSERT(bridge::capture_pending_pointer_y(*cap_valid) == 0,
                "unstarted pending pointer y must be 0");

    TEST_ASSERT(bridge::capture_stop(*cap_valid) ==
                    bridge::status_code(bridge::BridgeStatus::Ok),
                "unstarted capture_stop must return Ok");
  }

  // 9. NV12 descriptor construction validation
  {
    const auto nv12_desc = latencydesk::DdaCaptureSource::make_nv12_description(1920, 1080);
    TEST_ASSERT(nv12_desc.Width == 1920, "NV12 width mismatch");
    TEST_ASSERT(nv12_desc.Height == 1080, "NV12 height mismatch");
    TEST_ASSERT(nv12_desc.Format == DXGI_FORMAT_NV12, "NV12 format mismatch");
    TEST_ASSERT(nv12_desc.MipLevels == 1, "NV12 mip levels mismatch");
    TEST_ASSERT(nv12_desc.ArraySize == 1, "NV12 array size mismatch");
    TEST_ASSERT(nv12_desc.SampleDesc.Count == 1, "NV12 sample count mismatch");
    TEST_ASSERT(nv12_desc.Usage == D3D11_USAGE_DEFAULT, "NV12 usage mismatch");
    TEST_ASSERT((nv12_desc.BindFlags & D3D11_BIND_RENDER_TARGET) != 0,
                "NV12 must have D3D11_BIND_RENDER_TARGET");
    TEST_ASSERT((nv12_desc.BindFlags & D3D11_BIND_SHADER_RESOURCE) != 0,
                "NV12 must have D3D11_BIND_SHADER_RESOURCE");
    TEST_ASSERT(nv12_desc.CPUAccessFlags == 0, "NV12 CPU access must be 0");
  }

  // 10. Intermediate input descriptor validation
  {
    // For BGRA source
    D3D11_TEXTURE2D_DESC bgra_src_desc{};
    bgra_src_desc.Width = 1920;
    bgra_src_desc.Height = 1080;
    bgra_src_desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    bgra_src_desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    bgra_src_desc.Usage = D3D11_USAGE_DEFAULT;
    bgra_src_desc.SampleDesc.Count = 1;

    const auto inter_bgra_desc =
        latencydesk::DdaCaptureSource::make_intermediate_description(bgra_src_desc);
    TEST_ASSERT(inter_bgra_desc.Width == 1920, "intermediate BGRA width mismatch");
    TEST_ASSERT(inter_bgra_desc.Height == 1080, "intermediate BGRA height mismatch");
    TEST_ASSERT(inter_bgra_desc.Format == DXGI_FORMAT_B8G8R8A8_UNORM,
                "intermediate BGRA format mismatch");
    TEST_ASSERT(inter_bgra_desc.Usage == D3D11_USAGE_DEFAULT,
                "intermediate BGRA usage mismatch");
    TEST_ASSERT((inter_bgra_desc.BindFlags & D3D11_BIND_RENDER_TARGET) != 0,
                "intermediate BGRA must have D3D11_BIND_RENDER_TARGET");
    TEST_ASSERT((inter_bgra_desc.BindFlags & D3D11_BIND_SHADER_RESOURCE) != 0,
                "intermediate BGRA must have D3D11_BIND_SHADER_RESOURCE");
    TEST_ASSERT(inter_bgra_desc.CPUAccessFlags == 0,
                "intermediate BGRA CPU access must be 0");

    // For NV12 source (must have D3D11_BIND_DECODER for VideoProcessorInputView)
    D3D11_TEXTURE2D_DESC nv12_src_desc{};
    nv12_src_desc.Width = 1920;
    nv12_src_desc.Height = 1080;
    nv12_src_desc.Format = DXGI_FORMAT_NV12;
    nv12_src_desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    nv12_src_desc.Usage = D3D11_USAGE_DEFAULT;
    nv12_src_desc.SampleDesc.Count = 1;

    const auto inter_nv12_desc =
        latencydesk::DdaCaptureSource::make_intermediate_description(nv12_src_desc);
    TEST_ASSERT(inter_nv12_desc.Width == 1920, "intermediate NV12 width mismatch");
    TEST_ASSERT(inter_nv12_desc.Height == 1080, "intermediate NV12 height mismatch");
    TEST_ASSERT(inter_nv12_desc.Format == DXGI_FORMAT_NV12,
                "intermediate NV12 format mismatch");
    TEST_ASSERT((inter_nv12_desc.BindFlags & D3D11_BIND_DECODER) != 0,
                "intermediate NV12 MUST have D3D11_BIND_DECODER for VideoProcessorInputView");
    TEST_ASSERT(inter_nv12_desc.CPUAccessFlags == 0,
                "intermediate NV12 CPU access must be 0");
  }

  // 11. Deterministic D3D11 Device Seam (Real Direct3D Resource, CreateVideoProcessor, VideoProcessorBlt and Completion Verification)
  bool d3d11_device_available = false;
  bool video_processor_blt_verified = false;
  {
    Microsoft::WRL::ComPtr<ID3D11Device> device;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context;
    D3D_FEATURE_LEVEL feature_level{};
    HRESULT hr = D3D11CreateDevice(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0,
        D3D11_SDK_VERSION, &device, &feature_level, &context);
    if (FAILED(hr)) {
      hr = D3D11CreateDevice(
          nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
          D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0,
          D3D11_SDK_VERSION, &device, &feature_level, &context);
    }
    if (FAILED(hr) || device == nullptr || context == nullptr) {
      std::cout << "{\"skipped\":true,\"reason\":\"D3D11 device creation unavailable on host\"}\n";
      return EXIT_SUCCESS;
    }
    d3d11_device_available = true;

    // Create source BGRA texture
    D3D11_TEXTURE2D_DESC src_desc{};
    src_desc.Width = 64;
    src_desc.Height = 64;
    src_desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    src_desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    src_desc.Usage = D3D11_USAGE_DEFAULT;
    src_desc.MipLevels = 1;
    src_desc.ArraySize = 1;
    src_desc.SampleDesc.Count = 1;

    Microsoft::WRL::ComPtr<ID3D11Texture2D> src_texture;
    const HRESULT hr_src = device->CreateTexture2D(&src_desc, nullptr, &src_texture);
    TEST_ASSERT(SUCCEEDED(hr_src), "D3D11 CreateTexture2D src");

    // Create intermediate BGRA texture
    const auto inter_bgra =
        latencydesk::DdaCaptureSource::make_intermediate_description(src_desc);
    Microsoft::WRL::ComPtr<ID3D11Texture2D> inter_bgra_texture;
    const HRESULT hr_inter_bgra =
        device->CreateTexture2D(&inter_bgra, nullptr, &inter_bgra_texture);
    TEST_ASSERT(SUCCEEDED(hr_inter_bgra), "D3D11 CreateTexture2D intermediate BGRA");

    // Verify CopyResource from src to intermediate works
    context->CopyResource(inter_bgra_texture.Get(), src_texture.Get());

    // Create intermediate NV12 decoder texture (with D3D11_BIND_DECODER)
    D3D11_TEXTURE2D_DESC nv12_src{};
    nv12_src.Width = 64;
    nv12_src.Height = 64;
    nv12_src.Format = DXGI_FORMAT_NV12;
    nv12_src.Usage = D3D11_USAGE_DEFAULT;
    nv12_src.SampleDesc.Count = 1;
    const auto inter_nv12 =
        latencydesk::DdaCaptureSource::make_intermediate_description(nv12_src);
    Microsoft::WRL::ComPtr<ID3D11Texture2D> inter_nv12_texture;
    const HRESULT hr_inter_nv12 =
        device->CreateTexture2D(&inter_nv12, nullptr, &inter_nv12_texture);
    TEST_ASSERT(SUCCEEDED(hr_inter_nv12), "D3D11 CreateTexture2D intermediate NV12 (D3D11_BIND_DECODER)");

    // Create output NV12 texture
    const auto nv12_desc =
        latencydesk::DdaCaptureSource::make_nv12_description(64, 64);
    Microsoft::WRL::ComPtr<ID3D11Texture2D> nv12_texture;
    const HRESULT hr_nv12 =
        device->CreateTexture2D(&nv12_desc, nullptr, &nv12_texture);
    TEST_ASSERT(SUCCEEDED(hr_nv12), "D3D11 CreateTexture2D nv12");

    // Video device & processor behavioral verification
    Microsoft::WRL::ComPtr<ID3D11VideoDevice> video_device;
    Microsoft::WRL::ComPtr<ID3D11VideoContext> video_context;
    if (FAILED(device.As(&video_device)) || FAILED(context.As(&video_context)) ||
        video_device == nullptr || video_context == nullptr) {
      std::cout << "{\"skipped\":true,\"reason\":\"D3D11 VideoDevice/VideoContext unavailable on host\"}\n";
      return EXIT_SUCCESS;
    }

    D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
    content.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
    content.InputWidth = 64;
    content.InputHeight = 64;
    content.OutputWidth = 64;
    content.OutputHeight = 64;
    content.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;

    Microsoft::WRL::ComPtr<ID3D11VideoProcessorEnumerator> enumerator;
    const HRESULT hr_enum =
        video_device->CreateVideoProcessorEnumerator(&content, &enumerator);
    if (FAILED(hr_enum) || enumerator == nullptr) {
      std::cout << "{\"skipped\":true,\"reason\":\"D3D11 VideoProcessorEnumerator unavailable on host\"}\n";
      return EXIT_SUCCESS;
    }

    UINT input_support = 0;
    const HRESULT hr_in_sup = enumerator->CheckVideoProcessorFormat(
        DXGI_FORMAT_B8G8R8A8_UNORM, &input_support);
    UINT output_support = 0;
    const HRESULT hr_out_sup =
        enumerator->CheckVideoProcessorFormat(DXGI_FORMAT_NV12, &output_support);
    if (FAILED(hr_in_sup) || (input_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT) == 0 ||
        FAILED(hr_out_sup) || (output_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT) == 0) {
      std::cout << "{\"skipped\":true,\"reason\":\"VideoProcessor BGRA to NV12 conversion unsupported by driver\"}\n";
      return EXIT_SUCCESS;
    }

    Microsoft::WRL::ComPtr<ID3D11VideoProcessor> video_processor;
    const HRESULT hr_proc =
        video_device->CreateVideoProcessor(enumerator.Get(), 0, &video_processor);
    TEST_ASSERT(SUCCEEDED(hr_proc) && video_processor != nullptr,
                "CreateVideoProcessor must succeed");

    video_context->VideoProcessorSetStreamFrameFormat(
        video_processor.Get(), 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
    const RECT rect{0, 0, 64, 64};
    video_context->VideoProcessorSetStreamSourceRect(video_processor.Get(), 0, TRUE, &rect);
    video_context->VideoProcessorSetStreamDestRect(video_processor.Get(), 0, TRUE, &rect);

    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output_view_desc{};
    output_view_desc.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
    output_view_desc.Texture2D.MipSlice = 0;
    Microsoft::WRL::ComPtr<ID3D11VideoProcessorOutputView> output_view;
    const HRESULT hr_out_view = video_device->CreateVideoProcessorOutputView(
        nv12_texture.Get(), enumerator.Get(), &output_view_desc, &output_view);
    TEST_ASSERT(SUCCEEDED(hr_out_view) && output_view != nullptr,
                "CreateVideoProcessorOutputView on NV12 output texture must succeed");

    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input_view_desc{};
    input_view_desc.FourCC = 0;
    input_view_desc.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
    input_view_desc.Texture2D.MipSlice = 0;

    Microsoft::WRL::ComPtr<ID3D11VideoProcessorInputView> input_view;
    HRESULT hr_in_view = video_device->CreateVideoProcessorInputView(
        src_texture.Get(), enumerator.Get(), &input_view_desc, &input_view);
    if (FAILED(hr_in_view)) {
      hr_in_view = video_device->CreateVideoProcessorInputView(
          inter_bgra_texture.Get(), enumerator.Get(), &input_view_desc, &input_view);
    }
    TEST_ASSERT(SUCCEEDED(hr_in_view) && input_view != nullptr,
                "CreateVideoProcessorInputView must succeed for BGRA input");

    D3D11_VIDEO_PROCESSOR_STREAM stream{};
    stream.Enable = TRUE;
    stream.pInputSurface = input_view.Get();

    latencydesk::CaptureDetachState detach_blt;
    detach_blt.native_work_started();
    TEST_ASSERT(!detach_blt.release_permitted(),
                "release must be blocked while VideoProcessorBlt is in flight");

    const HRESULT hr_blt = video_context->VideoProcessorBlt(
        video_processor.Get(), output_view.Get(), 0, 1, &stream);
    TEST_ASSERT(SUCCEEDED(hr_blt), "VideoProcessorBlt must succeed");

    D3D11_QUERY_DESC query_desc{};
    query_desc.Query = D3D11_QUERY_EVENT;
    Microsoft::WRL::ComPtr<ID3D11Query> query;
    TEST_ASSERT(SUCCEEDED(device->CreateQuery(&query_desc, &query)),
                "CreateQuery D3D11_QUERY_EVENT must succeed");

    context->End(query.Get());
    context->Flush();

    bool query_completed = false;
    for (int i = 0; i < 5000; ++i) {
      const HRESULT q_hr =
          context->GetData(query.Get(), nullptr, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH);
      if (q_hr == S_OK) {
        query_completed = true;
        break;
      }
      if (q_hr != S_FALSE) {
        TEST_ASSERT(false, "GetData query unexpected error");
      }
      Sleep(1);
    }
    TEST_ASSERT(query_completed, "VideoProcessorBlt completion query must complete with S_OK");

    detach_blt.completion_proven();
    TEST_ASSERT(detach_blt.release_permitted(),
                "release must be permitted after VideoProcessorBlt completion proof");

    video_processor_blt_verified = true;
  }

  // 12. CaptureDetachState lifecycle and failure cleanup invariants
  {
    latencydesk::CaptureDetachState state;
    TEST_ASSERT(state.release_permitted(),
                "Initial state must permit release (no work pending)");

    state.native_work_started();
    TEST_ASSERT(!state.release_permitted(),
                "Work started must block release until proven");

    state.completion_proven();
    TEST_ASSERT(state.release_permitted(),
                "Completion proven must permit release");
  }
  // 13. Encoder contract and lifecycle
  bool encoder_lifecycle_verified = false;
  {
    std::uint32_t encoder_status = 0;
    auto encoder = bridge::make_mf_h264_encoder(0, 1920, 1080, 5000000, 30, 1, encoder_status);
    if (encoder != nullptr && encoder_status == bridge::status_code(bridge::BridgeStatus::Ok)) {
      TEST_ASSERT(bridge::encoder_request_idr(*encoder) == bridge::status_code(bridge::BridgeStatus::Ok),
                  "encoder_request_idr must return Ok");
      TEST_ASSERT(bridge::encoder_update_bitrate(*encoder, 4000000) == bridge::status_code(bridge::BridgeStatus::Ok),
                  "encoder_update_bitrate must return Ok");
      TEST_ASSERT(bridge::encoder_drain(*encoder) == bridge::status_code(bridge::BridgeStatus::Ok),
                  "encoder_drain must return Ok");
      TEST_ASSERT(bridge::encoder_quiesce(*encoder) == bridge::status_code(bridge::BridgeStatus::Ok),
                  "encoder_quiesce must return Ok");
      encoder_lifecycle_verified = true;
    }
  }

  std::cout << "{\"all_status_codes_verified\":true,"
               "\"all_status_mappings_verified\":true,"
               "\"wer_exclusion_idempotent\":true,"
               "\"capacity_contract_verified\":true,"
               "\"unstarted_capture_state_verified\":true,"
               "\"nv12_descriptor_verified\":true,"
               "\"intermediate_decoder_bind_flag_verified\":true,"
               "\"d3d11_device_available\":" << (d3d11_device_available ? "true" : "false") << ","
               "\"video_processor_bgra_to_nv12_blt_verified\":" << (video_processor_blt_verified ? "true" : "false") << ","
               "\"encoder_lifecycle_verified\":" << (encoder_lifecycle_verified ? "true" : "false") << ","
               "\"transactional_detach_invariants_verified\":true}\n";
  return EXIT_SUCCESS;
}
