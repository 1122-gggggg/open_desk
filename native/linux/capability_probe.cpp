#include <dlfcn.h>

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

bool library_available(const char* name) {
  void* handle = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
  if (handle == nullptr) {
    return false;
  }
  dlclose(handle);
  return true;
}

bool environment_present(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr && std::string_view(value).size() > 0;
}

}  // namespace

int main() {
  const bool pipewire = library_available("libpipewire-0.3.so.0");
  const bool libei = library_available("libei.so.1") || library_available("libei.so.0");
  const bool wayland = environment_present("WAYLAND_DISPLAY");
  const bool session_bus = environment_present("DBUS_SESSION_BUS_ADDRESS");
  const bool x11 = environment_present("DISPLAY");
  std::cout << std::boolalpha
            << "{\"wayland_display\":" << wayland
            << ",\"session_bus\":" << session_bus
            << ",\"pipewire_runtime\":" << pipewire
            << ",\"libei_runtime\":" << libei
            << ",\"x11_display\":" << x11
            << ",\"portal_capture_ready\":"
            << (wayland && session_bus && pipewire) << "}\n";
  return EXIT_SUCCESS;
}
