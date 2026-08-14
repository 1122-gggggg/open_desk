#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace latencydesk {

/// Stable identity returned by one authorized ScreenCast Start response.
struct PortalStreamIdentity {
  std::uint32_t node_id{};
  std::uint64_t pipewire_serial{};
};

/// Chooses the PipeWire target object for one live portal stream.
///
/// ScreenCast v6 deprecates reusable node IDs in favour of the never-reused
/// `pipewire-serial` property. Older interfaces have no serial, so their
/// target remains scoped by the portal session that returned it.
[[nodiscard]] inline std::optional<std::string> select_pipewire_target(
    const std::uint32_t screen_cast_version,
    const PortalStreamIdentity stream) {
  if (screen_cast_version == 0 || stream.node_id == 0) {
    return std::nullopt;
  }
  if (screen_cast_version >= 6) {
    if (stream.pipewire_serial == 0) {
      return std::nullopt;
    }
    return std::to_string(stream.pipewire_serial);
  }
  return std::to_string(stream.node_id);
}

}  // namespace latencydesk
