#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/base.h>

#include <cstdlib>
#include <iostream>

int wmain() try {
  winrt::init_apartment(winrt::apartment_type::multi_threaded);
  const bool supported =
      winrt::Windows::Graphics::Capture::GraphicsCaptureSession::IsSupported();
  std::cout << "{\"backend\":\"windows_graphics_capture\",\"supported\":"
            << std::boolalpha << supported
            << ",\"selection_ui_required_for_standard_picker\":true}\n";
  return supported ? EXIT_SUCCESS : 2;
} catch (const winrt::hresult_error& error) {
  std::wcerr << error.message().c_str() << L'\n';
  return EXIT_FAILURE;
}
