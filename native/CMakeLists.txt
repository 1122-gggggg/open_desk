cmake_minimum_required(VERSION 3.20)
project(latencydesk_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /WX /permissive- /EHsc)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(latencydesk_protocol_conformance tests/protocol_conformance.cpp)
target_include_directories(latencydesk_protocol_conformance PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)

add_executable(latencydesk_callback_gate tests/callback_gate.cpp)
target_include_directories(latencydesk_callback_gate PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
find_package(Threads REQUIRED)
target_link_libraries(latencydesk_callback_gate PRIVATE Threads::Threads)
add_executable(latencydesk_capture_detach tests/capture_detach.cpp)
target_include_directories(latencydesk_capture_detach PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
add_executable(latencydesk_portal_stream_target tests/portal_stream_target.cpp)
target_include_directories(latencydesk_portal_stream_target PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
enable_testing()
add_test(NAME protocol_conformance COMMAND latencydesk_protocol_conformance)
add_test(NAME callback_gate COMMAND latencydesk_callback_gate)
add_test(NAME capture_detach COMMAND latencydesk_capture_detach)
add_test(NAME portal_stream_target COMMAND latencydesk_portal_stream_target)

if(WIN32)
  # Keep the legacy min/max macros out of every Windows SDK translation unit.
  # Several probes use std::numeric_limits and std::min/std::max, so this must
  # be a target-wide build contract rather than an include-order accident.
  add_compile_definitions(NOMINMAX)

  add_library(latencydesk_win_dda_capture_source STATIC windows/dda_capture_source.cpp)
  target_include_directories(latencydesk_win_dda_capture_source PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common)
  target_link_libraries(latencydesk_win_dda_capture_source PUBLIC d3d11 dxgi)

  add_executable(latencydesk_win_dda_probe windows/dda_probe.cpp)
  target_include_directories(latencydesk_win_dda_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
  target_link_libraries(latencydesk_win_dda_probe PRIVATE latencydesk_win_dda_capture_source user32 ole32)

  add_test(
    NAME windows_dda_probe_help
    COMMAND latencydesk_win_dda_probe --help)
  set_tests_properties(
    windows_dda_probe_help
    PROPERTIES PASS_REGULAR_EXPRESSION "latencydesk_win_dda_probe")

  add_executable(latencydesk_win_mf_h264_probe windows/mf_h264_probe.cpp)
  target_link_libraries(latencydesk_win_mf_h264_probe PRIVATE d3d11 dxgi mfplat mf mfuuid wmcodecdspuuid ole32 oleaut32 propsys)
  add_test(
    NAME windows_mf_h264_probe_help
    COMMAND latencydesk_win_mf_h264_probe --help)
  set_tests_properties(
    windows_mf_h264_probe_help
    PROPERTIES PASS_REGULAR_EXPRESSION "Usage: latencydesk_win_mf_h264_probe")

  add_executable(latencydesk_win_mf_h264_encoder_async_probe
    windows/mf_h264_encoder_async_probe.cpp
    windows/mf_h264_encoder.cpp)
  target_include_directories(latencydesk_win_mf_h264_encoder_async_probe
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/windows)
  target_link_libraries(latencydesk_win_mf_h264_encoder_async_probe
    PRIVATE d3d11 dxgi mfplat mf mfuuid wmcodecdspuuid ole32 oleaut32 propsys)

  add_library(latencydesk_win_wgc_capture_source STATIC windows/wgc_capture_source.cpp)
  target_include_directories(latencydesk_win_wgc_capture_source PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/common)
  target_link_libraries(latencydesk_win_wgc_capture_source
    PUBLIC latencydesk_win_dda_capture_source d3d11 dxgi windowsapp)

  add_executable(latencydesk_win_mf_h264_decode_probe
    windows/mf_h264_decode_probe.cpp
    windows/mf_h264_decoder.cpp
    windows/mf_h264_encoder.cpp)
  target_include_directories(latencydesk_win_mf_h264_decode_probe
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/windows)
  target_link_libraries(latencydesk_win_mf_h264_decode_probe
    PRIVATE d3d11 d3d10 dxgi mfplat mf mfuuid wmcodecdspuuid ole32 oleaut32 propsys)

  add_executable(latencydesk_win_wgc_probe windows/wgc_probe.cpp)
  target_link_libraries(latencydesk_win_wgc_probe PRIVATE windowsapp)

  add_executable(latencydesk_win_capture_benchmark windows/capture_benchmark.cpp)
  target_include_directories(latencydesk_win_capture_benchmark PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
  target_link_libraries(latencydesk_win_capture_benchmark PRIVATE d3d11 dxgi user32 ole32 windowsapp)
  add_test(
    NAME windows_capture_benchmark_help
    COMMAND latencydesk_win_capture_benchmark --help)
  set_tests_properties(
    windows_capture_benchmark_help
    PROPERTIES PASS_REGULAR_EXPRESSION "latencydesk_win_capture_benchmark")

  add_executable(latencydesk_win_capture_color_contract tests/capture_color_contract.cpp)
  target_include_directories(latencydesk_win_capture_color_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
  target_link_libraries(latencydesk_win_capture_color_contract PRIVATE d3d11 dxgi)
  add_test(
    NAME windows_capture_color_contract
    COMMAND latencydesk_win_capture_color_contract)

  add_executable(latencydesk_win_bridge_contract tests/windows_bridge_contract.cpp windows/latencydesk_windows_bridge.cpp windows/mf_h264_encoder.cpp windows/mf_h264_decoder.cpp)
  target_include_directories(latencydesk_win_bridge_contract PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common ${CMAKE_CURRENT_SOURCE_DIR}/windows/include ${CMAKE_CURRENT_SOURCE_DIR}/windows)
  target_link_libraries(latencydesk_win_bridge_contract PRIVATE latencydesk_win_dda_capture_source d3d11 d3d10 dxgi dxguid user32 ole32 oleaut32 propsys mfplat mf mfuuid wmcodecdspuuid wer)
  add_test(
    NAME windows_bridge_contract
    COMMAND latencydesk_win_bridge_contract)
  add_executable(latencydesk_win_d3d11_present_probe windows/d3d11_present_probe.cpp)
  target_link_libraries(latencydesk_win_d3d11_present_probe PRIVATE d3d11 dxgi user32 ole32)
  add_test(
    NAME windows_d3d11_present_probe_help
    COMMAND latencydesk_win_d3d11_present_probe --help)
  set_tests_properties(
    windows_d3d11_present_probe_help
    PROPERTIES PASS_REGULAR_EXPRESSION "Usage: latencydesk_win_d3d11_present_probe")

  add_executable(latencydesk_win_input_probe windows/input_probe.cpp)
  target_link_libraries(latencydesk_win_input_probe PRIVATE user32)
  add_test(
    NAME windows_input_probe_help
    COMMAND latencydesk_win_input_probe --help)
  set_tests_properties(
    windows_input_probe_help
    PROPERTIES PASS_REGULAR_EXPRESSION "Usage: latencydesk_win_input_probe")
endif()

if(UNIX AND NOT APPLE)
  find_package(X11)
  if(X11_FOUND)
    add_executable(latencydesk_linux_x11_capture_probe linux/x11_capture_probe.cpp)
    target_include_directories(latencydesk_linux_x11_capture_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
    target_link_libraries(latencydesk_linux_x11_capture_probe PRIVATE X11::X11)
  endif()

  add_executable(latencydesk_linux_capability_probe linux/capability_probe.cpp)
  target_link_libraries(latencydesk_linux_capability_probe PRIVATE dl)

  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(LATENCYDESK_PORTAL_PIPEWIRE QUIET IMPORTED_TARGET
      gio-2.0
      gio-unix-2.0
      libpipewire-0.3)
  endif()
  if(LATENCYDESK_PORTAL_PIPEWIRE_FOUND)
    add_executable(latencydesk_linux_pipewire_import_probe linux/pipewire_import_probe.cpp)
    target_include_directories(latencydesk_linux_pipewire_import_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
    target_link_libraries(latencydesk_linux_pipewire_import_probe PRIVATE PkgConfig::LATENCYDESK_PORTAL_PIPEWIRE)
    add_test(
      NAME linux_pipewire_import_probe_help
      COMMAND latencydesk_linux_pipewire_import_probe --help)
  endif()
endif()
