#include "capture_color_contract.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

bool test_color_contract() {
  const auto rgb_input = latencydesk::make_rgb_stream_color_space();
  if (rgb_input.Usage != 0) {
    std::cerr << "RGB input stream color space Usage is not playback (0)\n";
    return false;
  }
  if (rgb_input.RGB_Range != 0) {
    std::cerr << "RGB input stream color space RGB_Range is not full range 0-255 (0)\n";
    return false;
  }
  if (rgb_input.Nominal_Range != D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255) {
    std::cerr << "RGB input stream color space Nominal_Range is not 0-255\n";
    return false;
  }
  // RGB input streams do not encode YCbCr matrix; ensure we do not demand BT.709 matrix on RGB.
  if (rgb_input.YCbCr_Matrix != 0) {
    std::cerr << "RGB input stream color space unexpectedly set YCbCr_Matrix\n";
    return false;
  }

  const auto nv12_output = latencydesk::make_sdr_nv12_output_color_space();
  if (nv12_output.Usage != 0) {
    std::cerr << "NV12 output color space Usage is not playback (0)\n";
    return false;
  }
  if (nv12_output.YCbCr_Matrix != 1) {
    std::cerr << "NV12 output color space YCbCr_Matrix is not BT.709 (1)\n";
    return false;
  }
  if (nv12_output.YCbCr_xvYCC != 0) {
    std::cerr << "NV12 output color space YCbCr_xvYCC is not conventional (0)\n";
    return false;
  }
  if (nv12_output.Nominal_Range != D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235) {
    std::cerr << "NV12 output color space Nominal_Range is not studio/limited 16-235\n";
    return false;
  }

  return true;
}

bool test_display_color_space_policy() {
  if (!latencydesk::is_sdr_color_space(DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709)) {
    std::cerr << "standard SDR sRGB color space was rejected by is_sdr_color_space\n";
    return false;
  }
  try {
    latencydesk::validate_display_color_space(DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709);
  } catch (const std::exception& error) {
    std::cerr << "standard SDR color space validation threw unexpectedly: " << error.what() << '\n';
    return false;
  }

  const DXGI_COLOR_SPACE_TYPE non_sdr_cases[] = {
      DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709,
      DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P709,
      DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P2020,
      DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020,
      DXGI_COLOR_SPACE_RGB_STUDIO_G2084_NONE_P2020,
      DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020,
      DXGI_COLOR_SPACE_CUSTOM,
      static_cast<DXGI_COLOR_SPACE_TYPE>(999),
  };

  for (const auto color_space : non_sdr_cases) {
    if (latencydesk::is_sdr_color_space(color_space)) {
      std::cerr << "non-SDR / HDR color space " << static_cast<int>(color_space)
                << " was accepted by is_sdr_color_space\n";
      return false;
    }
    bool threw = false;
    try {
      latencydesk::validate_display_color_space(color_space);
    } catch (const std::runtime_error& error) {
      threw = true;
      const std::string msg = error.what();
      if (msg.find("unsupported display color space") == std::string::npos ||
          msg.find("DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709") == std::string::npos) {
        std::cerr << "color space validation error message lacked diagnostic context: " << msg << '\n';
        return false;
      }
    }
    if (!threw) {
      std::cerr << "non-SDR / HDR color space " << static_cast<int>(color_space)
                << " did not fail closed\n";
      return false;
    }
  }

  if (std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709)) !=
          "DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709" ||
      std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709)) !=
          "DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709" ||
      std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P709)) !=
          "DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P709" ||
      std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P2020)) !=
          "DXGI_COLOR_SPACE_RGB_STUDIO_G22_NONE_P2020" ||
      std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020)) !=
          "DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020" ||
      std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_RGB_STUDIO_G2084_NONE_P2020)) !=
          "DXGI_COLOR_SPACE_RGB_STUDIO_G2084_NONE_P2020" ||
      std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020)) !=
          "DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020" ||
      std::string(latencydesk::color_space_to_string(DXGI_COLOR_SPACE_CUSTOM)) !=
          "DXGI_COLOR_SPACE_CUSTOM" ||
      std::string(latencydesk::color_space_to_string(static_cast<DXGI_COLOR_SPACE_TYPE>(999))) !=
          "unknown") {
    std::cerr << "color_space_to_string produced incorrect diagnostic strings\n";
    return false;
  }

  return true;
}

bool test_rotation_contract() {
  if (!latencydesk::is_identity_rotation(DXGI_MODE_ROTATION_IDENTITY)) {
    std::cerr << "identity rotation rejected by is_identity_rotation\n";
    return false;
  }
  try {
    latencydesk::validate_output_rotation(DXGI_MODE_ROTATION_IDENTITY);
  } catch (const std::exception& error) {
    std::cerr << "identity rotation validation threw unexpectedly: " << error.what() << '\n';
    return false;
  }

  DXGI_OUTDUPL_DESC identity_dupl_desc{};
  identity_dupl_desc.Rotation = DXGI_MODE_ROTATION_IDENTITY;
  try {
    latencydesk::validate_duplication_desc(identity_dupl_desc);
  } catch (const std::exception& error) {
    std::cerr << "identity duplication desc validation threw unexpectedly: " << error.what() << '\n';
    return false;
  }

  const DXGI_MODE_ROTATION non_identity_cases[] = {
      DXGI_MODE_ROTATION_UNSPECIFIED,
      DXGI_MODE_ROTATION_ROTATE90,
      DXGI_MODE_ROTATION_ROTATE180,
      DXGI_MODE_ROTATION_ROTATE270,
      static_cast<DXGI_MODE_ROTATION>(99),
  };

  for (const auto rotation : non_identity_cases) {
    if (latencydesk::is_identity_rotation(rotation)) {
      std::cerr << "non-identity rotation " << static_cast<int>(rotation)
                << " was accepted by is_identity_rotation\n";
      return false;
    }
    bool threw = false;
    try {
      latencydesk::validate_output_rotation(rotation);
    } catch (const std::runtime_error& error) {
      threw = true;
      const std::string msg = error.what();
      if (msg.find("unsupported display rotation") == std::string::npos ||
          msg.find("DXGI_MODE_ROTATION_IDENTITY") == std::string::npos) {
        std::cerr << "validation error message lacked diagnostic context: " << msg << '\n';
        return false;
      }
    }
    if (!threw) {
      std::cerr << "non-identity rotation " << static_cast<int>(rotation)
                << " did not fail closed\n";
      return false;
    }

    DXGI_OUTDUPL_DESC dupl_desc{};
    dupl_desc.Rotation = rotation;
    bool dupl_threw = false;
    try {
      latencydesk::validate_duplication_desc(dupl_desc);
    } catch (const std::runtime_error&) {
      dupl_threw = true;
    }
    if (!dupl_threw) {
      std::cerr << "non-identity duplication rotation " << static_cast<int>(rotation)
                << " did not fail closed via validate_duplication_desc\n";
      return false;
    }
  }

  if (std::string(latencydesk::rotation_to_string(DXGI_MODE_ROTATION_IDENTITY)) != "identity" ||
      std::string(latencydesk::rotation_to_string(DXGI_MODE_ROTATION_ROTATE90)) != "rotate90" ||
      std::string(latencydesk::rotation_to_string(DXGI_MODE_ROTATION_ROTATE180)) != "rotate180" ||
      std::string(latencydesk::rotation_to_string(DXGI_MODE_ROTATION_ROTATE270)) != "rotate270" ||
      std::string(latencydesk::rotation_to_string(DXGI_MODE_ROTATION_UNSPECIFIED)) != "unspecified" ||
      std::string(latencydesk::rotation_to_string(static_cast<DXGI_MODE_ROTATION>(999))) != "unknown") {
    std::cerr << "rotation_to_string produced incorrect names\n";
    return false;
  }

  return true;
}

bool test_null_checks() {
  bool threw_null_enumerator = false;
  try {
    latencydesk::check_video_processor_format_support(nullptr);
  } catch (const std::invalid_argument&) {
    threw_null_enumerator = true;
  }
  if (!threw_null_enumerator) {
    std::cerr << "check_video_processor_format_support did not reject null enumerator\n";
    return false;
  }

  bool threw_null_context = false;
  try {
    latencydesk::configure_video_processor_sdr_color_space(nullptr, nullptr, 1920, 1080);
  } catch (const std::invalid_argument&) {
    threw_null_context = true;
  }
  if (!threw_null_context) {
    std::cerr << "configure_video_processor_sdr_color_space did not reject null pointers\n";
    return false;
  }

  bool threw_null_output_query = false;
  try {
    latencydesk::query_output_color_space(nullptr);
  } catch (const std::invalid_argument&) {
    threw_null_output_query = true;
  }
  if (!threw_null_output_query) {
    std::cerr << "query_output_color_space did not reject null pointer\n";
    return false;
  }

  bool threw_null_output_validate = false;
  try {
    latencydesk::validate_output_color_space(nullptr);
  } catch (const std::invalid_argument&) {
    threw_null_output_validate = true;
  }
  if (!threw_null_output_validate) {
    std::cerr << "validate_output_color_space did not reject null pointer\n";
    return false;
  }

  bool threw_null_duplication = false;
  try {
    latencydesk::validate_duplication(nullptr);
  } catch (const std::invalid_argument&) {
    threw_null_duplication = true;
  }
  if (!threw_null_duplication) {
    std::cerr << "validate_duplication did not reject null pointer\n";
    return false;
  }

  return true;
}

}  // namespace

int main() {
  if (!test_color_contract()) {
    return EXIT_FAILURE;
  }
  if (!test_display_color_space_policy()) {
    return EXIT_FAILURE;
  }
  if (!test_rotation_contract()) {
    return EXIT_FAILURE;
  }
  if (!test_null_checks()) {
    return EXIT_FAILURE;
  }

  std::cout << "{\"color_contract_verified\":true"
            << ",\"input_stream_range\":\"0_255\""
            << ",\"input_stream_color_space\":\"RGB_Full\""
            << ",\"output_nv12_matrix\":\"BT.709\""
            << ",\"output_nv12_range\":\"16_235\""
            << ",\"sdr_color_space_accepted\":true"
            << ",\"hdr_color_space_fails_closed\":true"
            << ",\"truthful_color_space_diagnostics\":true"
            << ",\"rotation_identity_accepted\":true"
            << ",\"rotation_non_identity_fails_closed\":true"
            << ",\"duplication_rotation_validated\":true"
            << ",\"truthful_rotation_diagnostics\":true"
            << ",\"null_guards_verified\":true}\n";

  return EXIT_SUCCESS;
}
