#include "portal_stream_target.hpp"

#include <cstdlib>
#include <iostream>

int main() {
  using latencydesk::PortalStreamIdentity;
  using latencydesk::select_pipewire_target;

  const PortalStreamIdentity legacy{
      .node_id = 17,
      .pipewire_serial = 0,
  };
  const auto legacy_target = select_pipewire_target(5, legacy);
  if (!legacy_target || *legacy_target != "17") {
    std::cerr << "legacy portal did not target the node id\n";
    return EXIT_FAILURE;
  }

  const PortalStreamIdentity version_six{
      .node_id = 17,
      .pipewire_serial = 91,
  };
  const auto serial_target = select_pipewire_target(6, version_six);
  if (!serial_target || *serial_target != "91") {
    std::cerr << "ScreenCast v6 did not target the PipeWire serial\n";
    return EXIT_FAILURE;
  }

  const auto missing_serial = select_pipewire_target(6, legacy);
  if (missing_serial) {
    std::cerr << "ScreenCast v6 accepted a reusable node id without serial\n";
    return EXIT_FAILURE;
  }

  const auto invalid_node = select_pipewire_target(
      5, PortalStreamIdentity{.node_id = 0, .pipewire_serial = 91});
  if (invalid_node) {
    std::cerr << "zero PipeWire node id was accepted\n";
    return EXIT_FAILURE;
  }

  const auto unknown_version = select_pipewire_target(0, version_six);
  if (unknown_version) {
    std::cerr << "unknown ScreenCast interface version was accepted\n";
    return EXIT_FAILURE;
  }

  std::cout << "{\"legacy_node_target\":true,\"v6_serial_target\":true,"
               "\"v6_missing_serial_rejected\":true,"
               "\"zero_node_rejected\":true,\"unknown_version_rejected\":true}\n";
  return EXIT_SUCCESS;
}
