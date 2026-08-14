#include "media_wire.hpp"

#include <X11/Xlib.h>
#include <X11/Xutil.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct DisplayCloser {
  void operator()(Display* display) const noexcept {
    if (display != nullptr) {
      XCloseDisplay(display);
    }
  }
};

struct ImageCloser {
  void operator()(XImage* image) const noexcept {
    if (image != nullptr) {
      XDestroyImage(image);
    }
  }
};

std::uint64_t parse_frames(const int argc, char** argv) {
  std::uint64_t frames = 10;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--frames" && index + 1 < argc) {
      frames = std::stoull(argv[++index]);
    } else if (argument == "--help") {
      std::cout << "latencydesk_linux_x11_capture_probe [--frames N]\n";
      std::exit(EXIT_SUCCESS);
    } else {
      throw std::invalid_argument("unknown argument: " + argument);
    }
  }
  if (frames == 0 || frames > 10000) {
    throw std::invalid_argument("frames out of range");
  }
  return frames;
}

}  // namespace

int main(int argc, char** argv) try {
  const auto requested_frames = parse_frames(argc, argv);
  std::unique_ptr<Display, DisplayCloser> display(XOpenDisplay(nullptr));
  if (!display) {
    std::cerr << "DISPLAY is unavailable\n";
    return 2;
  }
  const int screen = DefaultScreen(display.get());
  const Window root = RootWindow(display.get(), screen);
  XWindowAttributes attributes{};
  if (XGetWindowAttributes(display.get(), root, &attributes) == 0) {
    throw std::runtime_error("XGetWindowAttributes failed");
  }
  if (attributes.width <= 0 || attributes.height <= 0) {
    throw std::runtime_error("invalid root dimensions");
  }

  std::uint64_t aggregate = 0;
  std::uint64_t bytes = 0;
  const auto begin = std::chrono::steady_clock::now();
  for (std::uint64_t frame = 0; frame < requested_frames; ++frame) {
    std::unique_ptr<XImage, ImageCloser> image(XGetImage(
        display.get(), root, 0, 0, static_cast<unsigned int>(attributes.width),
        static_cast<unsigned int>(attributes.height), AllPlanes, ZPixmap));
    if (!image || image->data == nullptr || image->bytes_per_line <= 0) {
      throw std::runtime_error("XGetImage failed");
    }
    const auto frame_bytes = static_cast<std::size_t>(image->bytes_per_line) *
                             static_cast<std::size_t>(image->height);
    const auto* raw = reinterpret_cast<const std::uint8_t*>(image->data);
    const auto frame_checksum = latencydesk::fnv1a(
        std::span<const std::uint8_t>(raw, frame_bytes));
    aggregate ^= frame_checksum + 0x9e3779b97f4a7c15ULL + (aggregate << 6U) +
                 (aggregate >> 2U);
    bytes += frame_bytes;
  }
  const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - begin);
  std::cout << "{\"backend\":\"x11_xgetimage\",\"frames\":" << requested_frames
            << ",\"width\":" << attributes.width << ",\"height\":"
            << attributes.height << ",\"bytes\":" << bytes
            << ",\"elapsed_us\":" << elapsed.count()
            << ",\"aggregate_checksum\":" << aggregate << "}\n";
  return EXIT_SUCCESS;
} catch (const std::exception& error) {
  std::cerr << error.what() << '\n';
  return EXIT_FAILURE;
}
