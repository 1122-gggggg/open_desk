#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace latencydesk {

inline constexpr std::size_t kMediaHeaderLength = 44;
inline constexpr std::uint32_t kMaxFrameBytes = 16U * 1024U * 1024U;
inline constexpr std::uint16_t kMaxFragmentBytes = 16U * 1024U;
inline constexpr std::uint64_t kNoDependency = UINT64_MAX;
inline constexpr std::uint16_t kKeyframe = 1U << 0U;
inline constexpr std::uint16_t kDiscardable = 1U << 1U;
inline constexpr std::uint16_t kLossless = 1U << 2U;
inline constexpr std::uint16_t kParity = 1U << 3U;
inline constexpr std::uint16_t kKnownFlags = kKeyframe | kDiscardable | kLossless | kParity;

struct MediaHeader {
  std::uint8_t kind{};
  std::uint16_t flags{};
  std::uint32_t stream_id{};
  std::uint32_t codec_epoch{};
  std::uint64_t frame_id{};
  std::uint64_t dependency_frame_id{kNoDependency};
  std::uint32_t frame_len{};
  std::uint32_t fragment_offset{};
  std::uint16_t fragment_len{};
};

inline void write_u16(std::span<std::uint8_t> out, const std::size_t offset,
                      const std::uint16_t value) {
  out[offset] = static_cast<std::uint8_t>(value >> 8U);
  out[offset + 1] = static_cast<std::uint8_t>(value);
}

inline void write_u32(std::span<std::uint8_t> out, const std::size_t offset,
                      const std::uint32_t value) {
  for (std::size_t index = 0; index < 4; ++index) {
    out[offset + index] = static_cast<std::uint8_t>(value >> ((3U - index) * 8U));
  }
}

inline void write_u64(std::span<std::uint8_t> out, const std::size_t offset,
                      const std::uint64_t value) {
  for (std::size_t index = 0; index < 8; ++index) {
    out[offset + index] = static_cast<std::uint8_t>(value >> ((7U - index) * 8U));
  }
}

inline std::uint16_t read_u16(const std::span<const std::uint8_t> bytes,
                              const std::size_t offset) {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                    bytes[offset + 1]);
}

inline std::uint32_t read_u32(const std::span<const std::uint8_t> bytes,
                              const std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4; ++index) {
    value = (value << 8U) | bytes[offset + index];
  }
  return value;
}

inline std::uint64_t read_u64(const std::span<const std::uint8_t> bytes,
                              const std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < 8; ++index) {
    value = (value << 8U) | bytes[offset + index];
  }
  return value;
}

inline void validate(const MediaHeader& header) {
  if (header.kind < 1U || header.kind > 4U) {
    throw std::invalid_argument("unknown media kind");
  }
  if ((header.flags & static_cast<std::uint16_t>(~kKnownFlags)) != 0U) {
    throw std::invalid_argument("unknown flags");
  }
  if (header.frame_len == 0U || header.frame_len > kMaxFrameBytes) {
    throw std::invalid_argument("frame length");
  }
  if (header.fragment_len == 0U || header.fragment_len > kMaxFragmentBytes) {
    throw std::invalid_argument("fragment length");
  }
  const auto end = static_cast<std::uint64_t>(header.fragment_offset) + header.fragment_len;
  if (header.fragment_offset >= header.frame_len || end > header.frame_len) {
    throw std::invalid_argument("fragment range");
  }
  if ((header.flags & kKeyframe) != 0U && header.dependency_frame_id != kNoDependency) {
    throw std::invalid_argument("keyframe dependency");
  }
  if (header.dependency_frame_id != kNoDependency &&
      header.dependency_frame_id >= header.frame_id) {
    throw std::invalid_argument("forward dependency");
  }
  if ((header.flags & kParity) != 0U && (header.flags & kKeyframe) != 0U) {
    throw std::invalid_argument("invalid flag combination");
  }
}

inline std::array<std::uint8_t, kMediaHeaderLength> encode(const MediaHeader& header) {
  validate(header);
  std::array<std::uint8_t, kMediaHeaderLength> out{};
  out[0] = 'L'; out[1] = 'D'; out[2] = 'S'; out[3] = 'K';
  out[4] = 1U;
  out[5] = header.kind;
  write_u16(out, 6, header.flags);
  write_u32(out, 8, header.stream_id);
  write_u32(out, 12, header.codec_epoch);
  write_u64(out, 16, header.frame_id);
  write_u64(out, 24, header.dependency_frame_id);
  write_u32(out, 32, header.frame_len);
  write_u32(out, 36, header.fragment_offset);
  write_u16(out, 40, header.fragment_len);
  return out;
}

inline MediaHeader decode(const std::span<const std::uint8_t> bytes) {
  if (bytes.size() < kMediaHeaderLength) {
    throw std::invalid_argument("truncated");
  }
  if (bytes[0] != 'L' || bytes[1] != 'D' || bytes[2] != 'S' || bytes[3] != 'K') {
    throw std::invalid_argument("magic");
  }
  if (bytes[4] != 1U) {
    throw std::invalid_argument("version");
  }
  if (bytes[42] != 0U || bytes[43] != 0U) {
    throw std::invalid_argument("reserved");
  }
  MediaHeader header{
      .kind = bytes[5],
      .flags = read_u16(bytes, 6),
      .stream_id = read_u32(bytes, 8),
      .codec_epoch = read_u32(bytes, 12),
      .frame_id = read_u64(bytes, 16),
      .dependency_frame_id = read_u64(bytes, 24),
      .frame_len = read_u32(bytes, 32),
      .fragment_offset = read_u32(bytes, 36),
      .fragment_len = read_u16(bytes, 40),
  };
  validate(header);
  return header;
}

inline std::uint64_t fnv1a(const std::span<const std::uint8_t> bytes) {
  std::uint64_t hash = 0xcbf29ce484222325ULL;
  for (const auto byte : bytes) {
    hash ^= byte;
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

}  // namespace latencydesk
