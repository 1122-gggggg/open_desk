#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int wmain(int argc, wchar_t** argv) try {
  bool inject = false;
  std::vector<INPUT> inputs;
  for (int index = 1; index < argc; ++index) {
    const std::wstring argument = argv[index];
    if (argument == L"--inject-relative" && index + 2 < argc) {
      inject = true;
      LONG dx = std::stol(argv[++index]);
      LONG dy = std::stol(argv[++index]);
      INPUT input{};
      input.type = INPUT_MOUSE;
      input.mi.dx = dx;
      input.mi.dy = dy;
      input.mi.dwFlags = MOUSEEVENTF_MOVE;
      inputs.push_back(input);
    } else if (argument == L"--inject-absolute" && index + 4 < argc) {
      inject = true;
      LONG x = std::stol(argv[++index]);
      LONG y = std::stol(argv[++index]);
      LONG width = std::stol(argv[++index]);
      LONG height = std::stol(argv[++index]);
      if (width <= 0 || height <= 0) {
        throw std::invalid_argument("width and height must be positive");
      }
      LONG norm_x = static_cast<LONG>(
          (static_cast<ULONGLONG>(x) * 65535) / (width > 1 ? width - 1 : 1));
      LONG norm_y = static_cast<LONG>(
          (static_cast<ULONGLONG>(y) * 65535) / (height > 1 ? height - 1 : 1));
      INPUT input{};
      input.type = INPUT_MOUSE;
      input.mi.dx = norm_x;
      input.mi.dy = norm_y;
      input.mi.dwFlags =
          MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
      inputs.push_back(input);
    } else if (argument == L"--inject-key" && index + 2 < argc) {
      inject = true;
      WORD vk = static_cast<WORD>(std::stol(argv[++index]));
      const std::wstring state_str = argv[++index];
      bool pressed = (state_str == L"1" || state_str == L"true");
      INPUT input{};
      input.type = INPUT_KEYBOARD;
      input.ki.wVk = vk;
      input.ki.dwFlags = pressed ? 0 : KEYEVENTF_KEYUP;
      inputs.push_back(input);
    } else if (argument == L"--inject-button" && index + 2 < argc) {
      inject = true;
      int button = std::stoi(argv[++index]);
      const std::wstring state_str = argv[++index];
      bool pressed = (state_str == L"1" || state_str == L"true");
      INPUT input{};
      input.type = INPUT_MOUSE;
      if (button == 0) {
        input.mi.dwFlags = pressed ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
      } else if (button == 1) {
        input.mi.dwFlags = pressed ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
      } else if (button == 2) {
        input.mi.dwFlags = pressed ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP;
      } else if (button == 3) {
        input.mi.dwFlags = pressed ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
        input.mi.mouseData = XBUTTON1;
      } else if (button == 4) {
        input.mi.dwFlags = pressed ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
        input.mi.mouseData = XBUTTON2;
      } else {
        throw std::invalid_argument("unknown mouse button");
      }
      inputs.push_back(input);
    } else if (argument == L"--inject-wheel" && index + 2 < argc) {
      inject = true;
      int horizontal = std::stoi(argv[++index]);
      int vertical = std::stoi(argv[++index]);
      if (vertical != 0) {
        INPUT input{};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_WHEEL;
        input.mi.mouseData = static_cast<DWORD>(vertical * WHEEL_DELTA);
        inputs.push_back(input);
      }
      if (horizontal != 0) {
        INPUT input{};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_HWHEEL;
        input.mi.mouseData = static_cast<DWORD>(horizontal * WHEEL_DELTA);
        inputs.push_back(input);
      }
    } else if (argument == L"--help") {
      std::wcout << L"Usage: latencydesk_win_input_probe [--inject-relative DX DY] "
                    L"[--inject-absolute X Y W H] [--inject-key VK PRESSED] "
                    L"[--inject-button BTN PRESSED] [--inject-wheel H V]\n";
      return EXIT_SUCCESS;
    } else {
      throw std::invalid_argument("unknown argument");
    }
  }
  DWORD session_id = 0;
  if (ProcessIdToSessionId(GetCurrentProcessId(), &session_id) == FALSE) {
    throw std::runtime_error("ProcessIdToSessionId failed");
  }
  bool injected = false;
  DWORD error = 0;
  if (inject && !inputs.empty()) {
    const UINT count = static_cast<UINT>(inputs.size());
    injected = SendInput(count, inputs.data(), sizeof(INPUT)) == count;
    if (!injected) error = GetLastError();
  }
  std::cout << "{\"session_id\":" << session_id
            << ",\"secure_desktop_supported\":false,\"explicit_injection_requested\":"
            << std::boolalpha << inject << ",\"injected\":" << injected
            << ",\"inputs_count\":" << inputs.size()
            << ",\"win32_error\":" << error << "}\n";
  return (!inject || injected) ? EXIT_SUCCESS : 3;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return EXIT_FAILURE;
}
