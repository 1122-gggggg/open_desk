#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include <stdexcept>
#include <string>

namespace latencydesk {

/// Constructs the explicit RGB input stream color space for SDR desktop capture (BGRA).
/// Desktop capture surfaces are full-range (0-255) RGB.
/// Note: D3D11 RGB color space specifies RGB_Range = 0 (0-255 full range).
/// D3D11 RGB stream color spaces do not encode a YCbCr matrix or transfer curve,
/// so YCbCr_Matrix is left 0 (not applicable).
[[nodiscard]] constexpr D3D11_VIDEO_PROCESSOR_COLOR_SPACE make_rgb_stream_color_space() noexcept {
  D3D11_VIDEO_PROCESSOR_COLOR_SPACE space{};
  space.Usage = 0;             // Playback
  space.RGB_Range = 0;         // 0: 0-255 Full Range RGB
  space.YCbCr_Matrix = 0;      // Unused/not applicable for RGB stream input
  space.YCbCr_xvYCC = 0;       // Conventional YCbCr
  space.Nominal_Range = D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255;
  space.Reserved = 0;
  return space;
}

/// Constructs the explicit output color space for SDR NV12 video encoding.
/// Standard SDR video encoding operates in BT.709 matrix (YCbCr_Matrix = 1)
/// and studio/limited nominal range (16-235).
[[nodiscard]] constexpr D3D11_VIDEO_PROCESSOR_COLOR_SPACE make_sdr_nv12_output_color_space() noexcept {
  D3D11_VIDEO_PROCESSOR_COLOR_SPACE space{};
  space.Usage = 0;             // Playback
  space.RGB_Range = 0;         // Not applicable to YCbCr output
  space.YCbCr_Matrix = 1;      // 1: BT.709 matrix for HD SDR video encoding
  space.YCbCr_xvYCC = 0;       // Conventional YCbCr
  space.Nominal_Range = D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;
  space.Reserved = 0;
  return space;
}

/// Returns true if and only if the display color space is standard SDR sRGB (G22/P709 full range).
[[nodiscard]] constexpr bool is_sdr_color_space(DXGI_COLOR_SPACE_TYPE color_space) noexcept {
  return color_space == DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
}

/// Formats a DXGI_COLOR_SPACE_TYPE enum value into a diagnostic string.
[[nodiscard]] inline const char* color_space_to_string(DXGI_COLOR_SPACE_TYPE color_space) noexcept {
  switch (color_space) {
    case DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709:
      return "DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709";
    case DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709:
      return "DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709";
    case DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P709:
      return "DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P709";
    case DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P2020:
      return "DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P2020";
    case DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020:
      return "DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020";
    case DXGI_COLOR_SPACE_RGB_STUDIO_G2084_NONE_P2020:
      return "DXGI_COLOR_SPACE_RGB_STUDIO_G2084_NONE_P2020";
    case DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020:
      return "DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020";
    case DXGI_COLOR_SPACE_CUSTOM:
      return "DXGI_COLOR_SPACE_CUSTOM";
    default:
      return "unknown";
  }
}

/// Validates that the display color space is standard SDR.
/// Fails closed for HDR or non-SDR color spaces to avoid implicit tone-mapping or color distortion.
inline void validate_display_color_space(DXGI_COLOR_SPACE_TYPE color_space) {
  if (!is_sdr_color_space(color_space)) {
    throw std::runtime_error(
        std::string("unsupported display color space: ") + color_space_to_string(color_space) +
        " (expected DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709; HDR and non-SDR display color spaces are rejected to avoid implicit tone-mapping or color distortion)");
  }
}

/// Queries the actual display color space from an IDXGIOutput.
/// Uses IDXGIOutput6 if available; defaults to standard SDR for legacy interfaces.
inline DXGI_COLOR_SPACE_TYPE query_output_color_space(IDXGIOutput* output) {
  if (output == nullptr) {
    throw std::invalid_argument("null IDXGIOutput pointer");
  }
  Microsoft::WRL::ComPtr<IDXGIOutput6> output6;
  const HRESULT hr = output->QueryInterface(IID_PPV_ARGS(&output6));
  if (SUCCEEDED(hr) && output6 != nullptr) {
    DXGI_OUTPUT_DESC1 desc1{};
    const HRESULT desc_hr = output6->GetDesc1(&desc1);
    if (SUCCEEDED(desc_hr)) {
      return desc1.ColorSpace;
    }
  }
  return DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
}

/// Validates that the IDXGIOutput is configured for standard SDR color space.
inline void validate_output_color_space(IDXGIOutput* output) {
  const DXGI_COLOR_SPACE_TYPE color_space = query_output_color_space(output);
  validate_display_color_space(color_space);
}

/// Formats a DXGI_MODE_ROTATION enum value into a diagnostic string.
[[nodiscard]] inline const char* rotation_to_string(DXGI_MODE_ROTATION rotation) noexcept {
  switch (rotation) {
    case DXGI_MODE_ROTATION_UNSPECIFIED:
      return "unspecified";
    case DXGI_MODE_ROTATION_IDENTITY:
      return "identity";
    case DXGI_MODE_ROTATION_ROTATE90:
      return "rotate90";
    case DXGI_MODE_ROTATION_ROTATE180:
      return "rotate180";
    case DXGI_MODE_ROTATION_ROTATE270:
      return "rotate270";
    default:
      return "unknown";
  }
}

/// Returns true if and only if the display rotation is identity (0 degrees).
[[nodiscard]] constexpr bool is_identity_rotation(DXGI_MODE_ROTATION rotation) noexcept {
  return rotation == DXGI_MODE_ROTATION_IDENTITY;
}

/// Validates that the DXGI output rotation is identity.
/// Fails closed for any non-identity rotation rather than emit misoriented frames.
inline void validate_output_rotation(DXGI_MODE_ROTATION rotation) {
  if (!is_identity_rotation(rotation)) {
    throw std::runtime_error(
        std::string("unsupported display rotation: ") + rotation_to_string(rotation) +
        " (expected DXGI_MODE_ROTATION_IDENTITY; non-identity rotation is rejected to avoid emitting misoriented frames)");
  }
}

/// Validates that the DXGI duplication description specifies identity rotation.
inline void validate_duplication_desc(const DXGI_OUTDUPL_DESC& desc) {
  validate_output_rotation(desc.Rotation);
}

/// Validates that the IDXGIOutputDuplication has identity rotation.
inline void validate_duplication(IDXGIOutputDuplication* duplication) {
  if (duplication == nullptr) {
    throw std::invalid_argument("null IDXGIOutputDuplication pointer");
  }
  DXGI_OUTDUPL_DESC desc{};
  duplication->GetDesc(&desc);
  validate_output_rotation(desc.Rotation);
}

/// Validates that the video processor enumerator supports BGRA input and NV12 output.
inline void check_video_processor_format_support(ID3D11VideoProcessorEnumerator* enumerator) {
  if (enumerator == nullptr) {
    throw std::invalid_argument("null ID3D11VideoProcessorEnumerator");
  }
  UINT input_support = 0;
  const HRESULT bgra_hr = enumerator->CheckVideoProcessorFormat(
      DXGI_FORMAT_B8G8R8A8_UNORM, &input_support);
  if (FAILED(bgra_hr) || (input_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT) == 0) {
    throw std::runtime_error("video processor does not support BGRA input format");
  }
  UINT output_support = 0;
  const HRESULT nv12_hr = enumerator->CheckVideoProcessorFormat(
      DXGI_FORMAT_NV12, &output_support);
  if (FAILED(nv12_hr) || (output_support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT) == 0) {
    throw std::runtime_error("video processor does not support NV12 output format");
  }
}

/// Explicitly configures RGB input and SDR NV12 output colorspace, progressive frame format,
/// and 1:1 source/dest/target rectangles on the video context.
inline void configure_video_processor_sdr_color_space(
    ID3D11VideoContext* video_context,
    ID3D11VideoProcessor* processor,
    UINT width,
    UINT height) {
  if (video_context == nullptr || processor == nullptr) {
    throw std::invalid_argument("null video context or processor");
  }
  const D3D11_VIDEO_PROCESSOR_COLOR_SPACE input_space = make_rgb_stream_color_space();
  video_context->VideoProcessorSetStreamColorSpace(processor, 0, &input_space);

  const D3D11_VIDEO_PROCESSOR_COLOR_SPACE output_space = make_sdr_nv12_output_color_space();
  video_context->VideoProcessorSetOutputColorSpace(processor, &output_space);

  video_context->VideoProcessorSetStreamFrameFormat(
      processor, 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);

  const RECT rect{0, 0, static_cast<LONG>(width), static_cast<LONG>(height)};
  video_context->VideoProcessorSetStreamSourceRect(processor, 0, TRUE, &rect);
  video_context->VideoProcessorSetStreamDestRect(processor, 0, TRUE, &rect);
  video_context->VideoProcessorSetOutputTargetRect(processor, TRUE, &rect);
}

}  // namespace latencydesk
