#include "media_wire.hpp"

#include <cstdlib>
#include <iostream>

int main() {
  using namespace latencydesk;
  const MediaHeader original{
      .kind = 1,
      .flags = static_cast<std::uint16_t>(kKeyframe | kLossless),
      .stream_id = 7,
      .codec_epoch = 3,
      .frame_id = 42,
      .dependency_frame_id = kNoDependency,
      .frame_len = 2000,
      .fragment_offset = 1000,
      .fragment_len = 1000,
  };
  const auto bytes = encode(original);
  const auto decoded = decode(bytes);
  if (decoded.kind != original.kind || decoded.flags != original.flags ||
      decoded.stream_id != original.stream_id ||
      decoded.codec_epoch != original.codec_epoch ||
      decoded.frame_id != original.frame_id ||
      decoded.dependency_frame_id != original.dependency_frame_id ||
      decoded.frame_len != original.frame_len ||
      decoded.fragment_offset != original.fragment_offset ||
      decoded.fragment_len != original.fragment_len) {
    std::cerr << "round-trip mismatch\n";
    return EXIT_FAILURE;
  }
  auto malformed = bytes;
  malformed[42] = 1;
  try {
    static_cast<void>(decode(malformed));
    std::cerr << "reserved byte accepted\n";
    return EXIT_FAILURE;
  } catch (const std::invalid_argument&) {
  }
  std::cout << "{\"media_header_bytes\":" << bytes.size()
            << ",\"round_trip\":true,\"reserved_rejected\":true}\n";
  return EXIT_SUCCESS;
}
