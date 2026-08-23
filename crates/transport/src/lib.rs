//! Deterministic, bounded media transport primitives.
//!
//! The production QUIC/UDP provider will sit below these types. Packetization,
//! reassembly, deadline semantics, and hostile-network tests remain transport
//! independent so they can be exercised in CI without sockets or a GPU.

use latencydesk_protocol::{
    media_flags, rate_flags, CongestionFeedbackMessage, MediaHeader, MediaKind, MediaPacket,
    ProtocolError, RateUpdateMessage, MAX_FRAGMENT_BYTES, MAX_FRAME_BYTES, MEDIA_HEADER_LEN,
    NO_DEPENDENCY,
};
use std::collections::BTreeMap;
use std::fmt;

/// Minimum internet-safe datagram MTU (IPv6 minimum MTU without fragmentation).
pub const MIN_DATAGRAM_MTU: usize = 1_200;
/// Maximum internet-safe datagram MTU for remote desktop media.
pub const MAX_DATAGRAM_MTU: usize = 1_450;
/// Conservative internet-safe default. A provider may negotiate another value
/// after path validation, but must never exceed protocol bounds.
pub const DEFAULT_MAX_DATAGRAM_BYTES: usize = 1_200;

/// Validates that a path MTU is within internet-safe bounds (1200..=1450).
pub fn validate_datagram_mtu(mtu: usize) -> Result<(), TransportError> {
    if !(MIN_DATAGRAM_MTU..=MAX_DATAGRAM_MTU).contains(&mtu) {
        return Err(TransportError::DatagramMtu(mtu));
    }
    Ok(())
}
/// Metadata shared by all fragments of one encoded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentSpec {
    pub kind: MediaKind,
    pub flags: u16,
    pub stream_id: u32,
    pub codec_epoch: u32,
    pub frame_id: u64,
    pub dependency_frame_id: Option<u64>,
}

impl FragmentSpec {
    fn dependency_wire(self) -> u64 {
        self.dependency_frame_id.unwrap_or(NO_DEPENDENCY)
    }
}

/// Splits one access unit into complete protocol datagrams.
pub fn fragment_frame(
    spec: FragmentSpec,
    frame: &[u8],
    max_datagram_bytes: usize,
) -> Result<Vec<Vec<u8>>, TransportError> {
    validate_datagram_mtu(max_datagram_bytes)?;
    fragment_frame_impl(spec, frame, max_datagram_bytes)
}

/// Splits one access unit using the byte budget available to the encoded
/// [`MediaPacket`].
///
/// Unlike [`fragment_frame`], this accepts a packet budget smaller than the
/// internet-safe path MTU. QUIC providers should subtract their outer framing
/// overhead from the path's datagram limit before calling this function.
pub fn fragment_frame_with_packet_budget(
    spec: FragmentSpec,
    frame: &[u8],
    max_media_packet_bytes: usize,
) -> Result<Vec<Vec<u8>>, TransportError> {
    if !(MEDIA_HEADER_LEN + 1..=MAX_DATAGRAM_MTU).contains(&max_media_packet_bytes) {
        return Err(TransportError::DatagramMtu(max_media_packet_bytes));
    }
    fragment_frame_impl(spec, frame, max_media_packet_bytes)
}

fn fragment_frame_impl(
    spec: FragmentSpec,
    frame: &[u8],
    max_media_packet_bytes: usize,
) -> Result<Vec<Vec<u8>>, TransportError> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES as usize {
        return Err(TransportError::FrameLength(frame.len()));
    }
    let payload_cap = max_media_packet_bytes
        .checked_sub(MEDIA_HEADER_LEN)
        .filter(|payload_cap| *payload_cap > 0)
        .ok_or(TransportError::DatagramMtu(max_media_packet_bytes))?;
    if payload_cap == 0 || payload_cap > usize::from(MAX_FRAGMENT_BYTES) {
        return Err(TransportError::DatagramMtu(max_media_packet_bytes));
    }
    let frame_len =
        u32::try_from(frame.len()).map_err(|_| TransportError::FrameLength(frame.len()))?;
    let count = frame.len().div_ceil(payload_cap);
    let mut packets = Vec::with_capacity(count);
    for (index, payload) in frame.chunks(payload_cap).enumerate() {
        let offset = index
            .checked_mul(payload_cap)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(TransportError::Arithmetic)?;
        let fragment_len = u16::try_from(payload.len()).map_err(|_| TransportError::Arithmetic)?;
        let header = MediaHeader {
            kind: spec.kind,
            flags: spec.flags,
            stream_id: spec.stream_id,
            codec_epoch: spec.codec_epoch,
            frame_id: spec.frame_id,
            dependency_frame_id: spec.dependency_wire(),
            frame_len,
            fragment_offset: offset,
            fragment_len,
        };
        packets.push(MediaPacket::encode(header, payload).map_err(TransportError::Protocol)?);
    }
    Ok(packets)
}

/// Unique identity of a frame under construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameKey {
    pub stream_id: u32,
    pub codec_epoch: u32,
    pub frame_id: u64,
    /// Stable numeric representation avoids exposing ordering assumptions on the enum.
    pub kind: u8,
}

impl FrameKey {
    fn from_header(header: MediaHeader) -> Self {
        Self {
            stream_id: header.stream_id,
            codec_epoch: header.codec_epoch,
            frame_id: header.frame_id,
            kind: header.kind as u8,
        }
    }
}

/// Complete reassembled access unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledFrame {
    pub header: MediaHeader,
    pub bytes: Vec<u8>,
    pub first_fragment_ns: u64,
    pub completed_ns: u64,
}

/// Hard resource caps for peer-controlled fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyConfig {
    pub max_inflight_frames: usize,
    pub max_buffered_bytes: usize,
    pub max_fragments_per_frame: usize,
    pub max_fragment_entries: usize,
    pub max_frame_age_ns: u64,
    pub min_datagram_bytes: usize,
    pub max_datagram_bytes: usize,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            max_inflight_frames: 32,
            max_buffered_bytes: 64 * 1024 * 1024,
            max_fragments_per_frame: 16_384,
            max_fragment_entries: 65_536,
            max_frame_age_ns: 250_000_000,
            min_datagram_bytes: MIN_DATAGRAM_MTU,
            max_datagram_bytes: MAX_DATAGRAM_MTU,
        }
    }
}

impl ReassemblyConfig {
    pub fn validate(self) -> Result<(), TransportError> {
        if self.max_inflight_frames == 0
            || self.max_buffered_bytes == 0
            || self.max_fragments_per_frame == 0
            || self.max_fragment_entries == 0
            || self.max_fragments_per_frame > self.max_fragment_entries
            || self.max_frame_age_ns == 0
            || self.max_buffered_bytes > 512 * 1024 * 1024
            || self.min_datagram_bytes < MEDIA_HEADER_LEN
            || self.max_datagram_bytes < self.min_datagram_bytes
        {
            return Err(TransportError::InvalidReassemblyConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct PartialFrame {
    canonical: MediaHeader,
    fragments: BTreeMap<u32, Vec<u8>>,
    received_bytes: usize,
    first_seen_ns: u64,
    last_update_ns: u64,
}

impl PartialFrame {
    fn new(header: MediaHeader, now_ns: u64) -> Self {
        Self {
            canonical: header,
            fragments: BTreeMap::new(),
            received_bytes: 0,
            first_seen_ns: now_ns,
            last_update_ns: now_ns,
        }
    }

    fn metadata_matches(&self, header: MediaHeader) -> bool {
        self.canonical.kind == header.kind
            && self.canonical.flags == header.flags
            && self.canonical.stream_id == header.stream_id
            && self.canonical.codec_epoch == header.codec_epoch
            && self.canonical.frame_id == header.frame_id
            && self.canonical.dependency_frame_id == header.dependency_frame_id
            && self.canonical.frame_len == header.frame_len
    }
}

/// Result of ingesting one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    Pending {
        key: FrameKey,
        received_bytes: usize,
    },
    Duplicate {
        key: FrameKey,
    },
    Complete(ReassembledFrame),
}

/// Observable resource and hostile-network counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReassemblyStats {
    pub datagrams_accepted: u64,
    pub duplicate_fragments: u64,
    pub frames_completed: u64,
    pub frames_expired: u64,
    pub frames_evicted: u64,
    pub malformed_datagrams: u64,
    pub conflicting_fragments: u64,
    pub stale_epoch_datagrams: u64,
    pub epoch_bumps: u64,
}

/// Bounded, out-of-order fragment reassembler.
#[derive(Debug)]
pub struct Reassembler {
    config: ReassemblyConfig,
    frames: BTreeMap<FrameKey, PartialFrame>,
    buffered_bytes: usize,
    reserved_bytes: usize,
    fragment_entries: usize,
    stats: ReassemblyStats,
    active_codec_epoch: u32,
}

impl Reassembler {
    pub fn new(config: ReassemblyConfig) -> Result<Self, TransportError> {
        config.validate()?;
        Ok(Self {
            config,
            frames: BTreeMap::new(),
            buffered_bytes: 0,
            reserved_bytes: 0,
            fragment_entries: 0,
            stats: ReassemblyStats::default(),
            active_codec_epoch: 1,
        })
    }

    #[must_use]
    pub const fn active_codec_epoch(&self) -> u32 {
        self.active_codec_epoch
    }

    /// Parses and stores one complete datagram. All lengths are validated before
    /// payload allocation. Exact duplicates are idempotent; any overlap or
    /// metadata conflict invalidates the entire in-flight frame.
    pub fn ingest(
        &mut self,
        datagram: &[u8],
        now_ns: u64,
    ) -> Result<IngestOutcome, TransportError> {
        self.expire(now_ns);
        if datagram.len() > self.config.max_datagram_bytes {
            return Err(TransportError::DatagramMtu(datagram.len()));
        }
        let packet = match MediaPacket::decode(datagram) {
            Ok(packet) => packet,
            Err(error) => {
                self.stats.malformed_datagrams = self.stats.malformed_datagrams.saturating_add(1);
                return Err(TransportError::Protocol(error));
            }
        };
        if packet.header.flags & media_flags::PARITY != 0 {
            return Err(TransportError::UnsupportedParity);
        }
        let packet_epoch = packet.header.codec_epoch;
        if packet_epoch < self.active_codec_epoch {
            self.stats.stale_epoch_datagrams = self.stats.stale_epoch_datagrams.saturating_add(1);
            return Err(TransportError::StaleCodecEpoch {
                packet_epoch,
                current_epoch: self.active_codec_epoch,
            });
        }
        if packet_epoch > self.active_codec_epoch {
            let stale_keys: Vec<FrameKey> = self
                .frames
                .keys()
                .copied()
                .filter(|k| k.codec_epoch < packet_epoch)
                .collect();
            for key in stale_keys {
                self.remove_frame(key);
            }
            self.active_codec_epoch = packet_epoch;
            self.stats.epoch_bumps = self.stats.epoch_bumps.saturating_add(1);
        }

        let key = FrameKey::from_header(packet.header);
        let declared = packet.header.frame_len as usize;
        if declared > self.config.max_buffered_bytes {
            return Err(TransportError::FrameExceedsReassemblyBudget {
                frame_bytes: declared,
                budget_bytes: self.config.max_buffered_bytes,
            });
        }

        if let Some(existing) = self.frames.get(&key) {
            if !existing.metadata_matches(packet.header) {
                self.remove_frame(key);
                self.stats.conflicting_fragments =
                    self.stats.conflicting_fragments.saturating_add(1);
                return Err(TransportError::MetadataConflict(key));
            }
        } else {
            self.make_room_for_new_frame(declared)?;
            self.reserved_bytes = self.reserved_bytes.saturating_add(declared);
            self.frames
                .insert(key, PartialFrame::new(packet.header, now_ns));
        }

        let is_exact_duplicate = self
            .frames
            .get(&key)
            .and_then(|partial| partial.fragments.get(&packet.header.fragment_offset))
            .is_some_and(|existing| existing.as_slice() == packet.payload);
        if !is_exact_duplicate && self.fragment_entries >= self.config.max_fragment_entries {
            self.remove_frame(key);
            return Err(TransportError::FragmentEntryLimit);
        }
        let insertion = {
            let partial = self.frames.get_mut(&key).expect("frame inserted above");
            insert_fragment(
                partial,
                packet.header.fragment_offset,
                packet.payload,
                now_ns,
                self.config.max_fragments_per_frame,
            )
        };
        match insertion {
            Ok(FragmentInsertion::Duplicate) => {
                self.stats.duplicate_fragments = self.stats.duplicate_fragments.saturating_add(1);
                Ok(IngestOutcome::Duplicate { key })
            }
            Ok(FragmentInsertion::Added(bytes)) => {
                self.buffered_bytes = self.buffered_bytes.saturating_add(bytes);
                self.fragment_entries = self.fragment_entries.saturating_add(1);
                self.stats.datagrams_accepted = self.stats.datagrams_accepted.saturating_add(1);
                let complete = self.frames.get(&key).is_some_and(|partial| {
                    partial.received_bytes == partial.canonical.frame_len as usize
                });
                if complete {
                    let partial = self.frames.remove(&key).expect("complete frame exists");
                    self.buffered_bytes =
                        self.buffered_bytes.saturating_sub(partial.received_bytes);
                    self.reserved_bytes = self
                        .reserved_bytes
                        .saturating_sub(partial.canonical.frame_len as usize);
                    self.fragment_entries = self
                        .fragment_entries
                        .saturating_sub(partial.fragments.len());
                    let frame = assemble(partial, now_ns)?;
                    self.stats.frames_completed = self.stats.frames_completed.saturating_add(1);
                    Ok(IngestOutcome::Complete(frame))
                } else {
                    let received_bytes = self.frames[&key].received_bytes;
                    Ok(IngestOutcome::Pending {
                        key,
                        received_bytes,
                    })
                }
            }
            Err(error) => {
                self.remove_frame(key);
                self.stats.conflicting_fragments =
                    self.stats.conflicting_fragments.saturating_add(1);
                Err(error)
            }
        }
    }

    /// Removes incomplete frames older than the configured age.
    pub fn expire(&mut self, now_ns: u64) -> usize {
        let expired: Vec<FrameKey> = self
            .frames
            .iter()
            .filter_map(|(key, frame)| {
                let age = now_ns.saturating_sub(frame.first_seen_ns);
                (age >= self.config.max_frame_age_ns).then_some(*key)
            })
            .collect();
        for key in &expired {
            self.remove_frame(*key);
        }
        self.stats.frames_expired = self
            .stats
            .frames_expired
            .saturating_add(expired.len() as u64);
        expired.len()
    }

    #[must_use]
    pub fn inflight_frames(&self) -> usize {
        self.frames.len()
    }

    #[must_use]
    pub const fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Bytes reserved from peer-declared complete frame lengths.
    #[must_use]
    pub const fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    #[must_use]
    pub const fn fragment_entries(&self) -> usize {
        self.fragment_entries
    }

    #[must_use]
    pub const fn stats(&self) -> ReassemblyStats {
        self.stats
    }

    fn make_room_for_new_frame(
        &mut self,
        declared_frame_bytes: usize,
    ) -> Result<(), TransportError> {
        while self.frames.len() >= self.config.max_inflight_frames
            || self.reserved_bytes.saturating_add(declared_frame_bytes)
                > self.config.max_buffered_bytes
        {
            let victim = self
                .frames
                .iter()
                .min_by_key(|(key, frame)| (frame.last_update_ns, frame.first_seen_ns, **key))
                .map(|(key, _)| *key);
            let Some(victim) = victim else {
                return Err(TransportError::ReassemblyCapacity);
            };
            self.remove_frame(victim);
            self.stats.frames_evicted = self.stats.frames_evicted.saturating_add(1);
        }
        Ok(())
    }

    fn remove_frame(&mut self, key: FrameKey) {
        if let Some(removed) = self.frames.remove(&key) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(removed.received_bytes);
            self.reserved_bytes = self
                .reserved_bytes
                .saturating_sub(removed.canonical.frame_len as usize);
            self.fragment_entries = self
                .fragment_entries
                .saturating_sub(removed.fragments.len());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentInsertion {
    Duplicate,
    Added(usize),
}

fn insert_fragment(
    partial: &mut PartialFrame,
    offset: u32,
    payload: &[u8],
    now_ns: u64,
    max_fragments_per_frame: usize,
) -> Result<FragmentInsertion, TransportError> {
    let end = offset
        .checked_add(u32::try_from(payload.len()).map_err(|_| TransportError::Arithmetic)?)
        .ok_or(TransportError::Arithmetic)?;

    if let Some(existing) = partial.fragments.get(&offset) {
        return if existing.as_slice() == payload {
            Ok(FragmentInsertion::Duplicate)
        } else {
            Err(TransportError::FragmentConflict)
        };
    }
    if partial.fragments.len() >= max_fragments_per_frame {
        return Err(TransportError::FragmentEntryLimit);
    }
    if let Some((previous_offset, previous)) = partial.fragments.range(..offset).next_back() {
        let previous_end = previous_offset
            .checked_add(u32::try_from(previous.len()).map_err(|_| TransportError::Arithmetic)?)
            .ok_or(TransportError::Arithmetic)?;
        if previous_end > offset {
            return Err(TransportError::FragmentOverlap);
        }
    }
    if let Some((next_offset, _)) = partial.fragments.range(offset..).next() {
        if end > *next_offset {
            return Err(TransportError::FragmentOverlap);
        }
    }

    partial.fragments.insert(offset, payload.to_vec());
    partial.received_bytes = partial.received_bytes.saturating_add(payload.len());
    partial.last_update_ns = now_ns;
    Ok(FragmentInsertion::Added(payload.len()))
}

fn assemble(partial: PartialFrame, completed_ns: u64) -> Result<ReassembledFrame, TransportError> {
    let declared = partial.canonical.frame_len as usize;
    if partial.received_bytes != declared {
        return Err(TransportError::IncompleteAssembly);
    }
    let mut bytes = vec![0_u8; declared];
    let mut expected_offset = 0_u32;
    for (offset, fragment) in partial.fragments {
        if offset != expected_offset {
            return Err(TransportError::IncompleteAssembly);
        }
        let start = offset as usize;
        let end = start
            .checked_add(fragment.len())
            .ok_or(TransportError::Arithmetic)?;
        bytes
            .get_mut(start..end)
            .ok_or(TransportError::IncompleteAssembly)?
            .copy_from_slice(&fragment);
        expected_offset = u32::try_from(end).map_err(|_| TransportError::Arithmetic)?;
    }
    if expected_offset != partial.canonical.frame_len {
        return Err(TransportError::IncompleteAssembly);
    }
    Ok(ReassembledFrame {
        header: partial.canonical,
        bytes,
        first_fragment_ns: partial.first_seen_ns,
        completed_ns,
    })
}

/// Logical lane used by the deterministic network model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkLane {
    Input,
    Control,
    RecoveryMedia,
    RealtimeMedia,
    Audio,
    Refinement,
}

/// One packet submitted to a transport provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimPacket {
    pub id: u64,
    pub lane: NetworkLane,
    pub send_ns: u64,
    pub deadline_ns: u64,
    pub bytes: Vec<u8>,
}

impl SimPacket {
    pub fn validate(&self, max_packet_bytes: usize) -> Result<(), TransportError> {
        if self.bytes.is_empty() || self.bytes.len() > max_packet_bytes {
            return Err(TransportError::PacketSize(self.bytes.len()));
        }
        if self.deadline_ns <= self.send_ns {
            return Err(TransportError::InvalidDeadline);
        }
        Ok(())
    }
}

/// Integer-only deterministic network profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkProfile {
    pub base_delay_ns: u64,
    pub jitter_ns: u64,
    pub bandwidth_bps: u64,
    pub loss_per_million: u32,
    pub duplicate_per_million: u32,
    pub reorder_per_million: u32,
    pub corrupt_per_million: u32,
    pub max_queued_packets: usize,
    pub max_queued_bytes: usize,
    pub max_packet_bytes: usize,
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self {
            base_delay_ns: 1_000_000,
            jitter_ns: 100_000,
            bandwidth_bps: 1_000_000_000,
            loss_per_million: 0,
            duplicate_per_million: 0,
            reorder_per_million: 0,
            corrupt_per_million: 0,
            max_queued_packets: 8_192,
            max_queued_bytes: 64 * 1024 * 1024,
            max_packet_bytes: 64 * 1024,
        }
    }
}

impl NetworkProfile {
    pub fn validate(self) -> Result<(), TransportError> {
        let probabilities = [
            self.loss_per_million,
            self.duplicate_per_million,
            self.reorder_per_million,
            self.corrupt_per_million,
        ];
        if probabilities.into_iter().any(|value| value > 1_000_000)
            || self.bandwidth_bps == 0
            || self.max_queued_packets == 0
            || self.max_queued_bytes == 0
            || self.max_packet_bytes == 0
        {
            return Err(TransportError::InvalidNetworkProfile);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct QueuedPacket {
    delivery_ns: u64,
    insertion_order: u64,
    packet: SimPacket,
}

/// Deterministic simulator counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkStats {
    pub submitted: u64,
    pub delivered: u64,
    pub lost: u64,
    pub duplicated: u64,
    pub reordered: u64,
    pub corrupted: u64,
    pub expired: u64,
    pub queue_dropped: u64,
    pub delivered_bytes: u64,
}

/// Reproducible delay/loss/reorder/duplication/corruption/bandwidth simulator.
#[derive(Debug)]
pub struct NetworkSimulator {
    profile: NetworkProfile,
    rng: XorShift64,
    queue: Vec<QueuedPacket>,
    queued_bytes: usize,
    next_wire_free_ns: u64,
    insertion_order: u64,
    stats: NetworkStats,
}

impl NetworkSimulator {
    pub fn new(profile: NetworkProfile, seed: u64) -> Result<Self, TransportError> {
        profile.validate()?;
        Ok(Self {
            profile,
            rng: XorShift64::new(seed),
            queue: Vec::new(),
            queued_bytes: 0,
            next_wire_free_ns: 0,
            insertion_order: 0,
            stats: NetworkStats::default(),
        })
    }

    /// Submits a packet. A probabilistic drop is a successful simulation event,
    /// while invalid sizes and local queue exhaustion are explicit errors.
    pub fn submit(&mut self, packet: SimPacket) -> Result<SubmitOutcome, TransportError> {
        packet.validate(self.profile.max_packet_bytes)?;
        self.stats.submitted = self.stats.submitted.saturating_add(1);
        if self.roll(self.profile.loss_per_million) {
            self.stats.lost = self.stats.lost.saturating_add(1);
            return Ok(SubmitOutcome::SimulatedLoss);
        }
        let duplicate = self.roll(self.profile.duplicate_per_million);
        let copies = if duplicate { 2 } else { 1 };
        if duplicate {
            self.stats.duplicated = self.stats.duplicated.saturating_add(1);
        }
        let required_bytes = packet
            .bytes
            .len()
            .checked_mul(copies)
            .ok_or(TransportError::Arithmetic)?;
        if self.queue.len().saturating_add(copies) > self.profile.max_queued_packets
            || self.queued_bytes.saturating_add(required_bytes) > self.profile.max_queued_bytes
        {
            self.stats.queue_dropped = self.stats.queue_dropped.saturating_add(1);
            return Err(TransportError::NetworkQueueFull);
        }

        for copy_index in 0..copies {
            let mut copy = packet.clone();
            if copy_index == 1 {
                copy.id = copy.id.wrapping_add(1_u64 << 63);
            }
            if self.roll(self.profile.corrupt_per_million) && !copy.bytes.is_empty() {
                let index = (self.rng.next_u64() as usize) % copy.bytes.len();
                copy.bytes[index] ^= 1_u8 << ((self.rng.next_u64() % 8) as u32);
                self.stats.corrupted = self.stats.corrupted.saturating_add(1);
            }
            let reordered = self.roll(self.profile.reorder_per_million);
            if reordered {
                self.stats.reordered = self.stats.reordered.saturating_add(1);
            }
            let delivery_ns = self.schedule_delivery(&copy, reordered, copy_index)?;
            self.insertion_order = self.insertion_order.wrapping_add(1);
            self.queued_bytes = self.queued_bytes.saturating_add(copy.bytes.len());
            self.queue.push(QueuedPacket {
                delivery_ns,
                insertion_order: self.insertion_order,
                packet: copy,
            });
        }
        Ok(SubmitOutcome::Queued { copies })
    }

    /// Returns all due packets ordered by simulated delivery time. Packets that
    /// missed their application deadline are discarded before reaching callers.
    pub fn poll(&mut self, now_ns: u64) -> Vec<DeliveredPacket> {
        self.queue
            .sort_by_key(|queued| (queued.delivery_ns, queued.insertion_order));
        let split = self
            .queue
            .partition_point(|queued| queued.delivery_ns <= now_ns);
        let due: Vec<QueuedPacket> = self.queue.drain(..split).collect();
        let mut delivered = Vec::with_capacity(due.len());
        for queued in due {
            self.queued_bytes = self.queued_bytes.saturating_sub(queued.packet.bytes.len());
            if queued.delivery_ns > queued.packet.deadline_ns {
                self.stats.expired = self.stats.expired.saturating_add(1);
                continue;
            }
            self.stats.delivered = self.stats.delivered.saturating_add(1);
            self.stats.delivered_bytes = self
                .stats
                .delivered_bytes
                .saturating_add(queued.packet.bytes.len() as u64);
            delivered.push(DeliveredPacket {
                delivery_ns: queued.delivery_ns,
                packet: queued.packet,
            });
        }
        delivered
    }

    #[must_use]
    pub fn queued_packets(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    #[must_use]
    pub const fn stats(&self) -> NetworkStats {
        self.stats
    }

    fn schedule_delivery(
        &mut self,
        packet: &SimPacket,
        reordered: bool,
        copy_index: usize,
    ) -> Result<u64, TransportError> {
        let bits = (packet.bytes.len() as u128)
            .checked_mul(8)
            .and_then(|value| value.checked_mul(1_000_000_000))
            .ok_or(TransportError::Arithmetic)?;
        let serialization_ns = bits
            .div_ceil(u128::from(self.profile.bandwidth_bps))
            .min(u128::from(u64::MAX)) as u64;
        let wire_start = packet.send_ns.max(self.next_wire_free_ns);
        self.next_wire_free_ns = wire_start.saturating_add(serialization_ns);
        let jitter = self.signed_jitter();
        let base = self
            .next_wire_free_ns
            .saturating_add(self.profile.base_delay_ns)
            .saturating_add((copy_index as u64).saturating_mul(50_000));
        let with_jitter = add_signed_saturating(base, jitter);
        Ok(if reordered {
            with_jitter.saturating_add(self.profile.jitter_ns.saturating_mul(4).max(1))
        } else {
            with_jitter
        })
    }

    fn signed_jitter(&mut self) -> i128 {
        if self.profile.jitter_ns == 0 {
            return 0;
        }
        let span = u128::from(self.profile.jitter_ns)
            .saturating_mul(2)
            .saturating_add(1);
        let value = u128::from(self.rng.next_u64()) % span;
        value as i128 - i128::from(self.profile.jitter_ns)
    }

    fn roll(&mut self, per_million: u32) -> bool {
        per_million != 0 && self.rng.next_u64() % 1_000_000 < u64::from(per_million)
    }
}

fn add_signed_saturating(value: u64, delta: i128) -> u64 {
    if delta >= 0 {
        value.saturating_add(delta.min(i128::from(u64::MAX)) as u64)
    } else {
        value.saturating_sub((-delta).min(i128::from(u64::MAX)) as u64)
    }
}

/// Packet accepted by the simulated receiver together with its local arrival time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredPacket {
    pub delivery_ns: u64,
    pub packet: SimPacket,
}

/// Result of simulator submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    Queued { copies: usize },
    SimulatedLoss,
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }
}

/// Minimum target bitrate in bps (0.5 Mbps).
pub const MIN_TARGET_BITRATE_BPS: u32 = 500_000;
/// Maximum target bitrate in bps (100 Mbps).
pub const MAX_TARGET_BITRATE_BPS: u32 = 100_000_000;
/// Minimum target framerate in fps.
pub const MIN_TARGET_FRAMERATE_FPS: u32 = 15;
/// Maximum target framerate in fps.
pub const MAX_TARGET_FRAMERATE_FPS: u32 = 120;

/// Configuration for adaptive congestion control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveCongestionConfig {
    pub min_bitrate_bps: u32,
    pub max_bitrate_bps: u32,
    pub initial_bitrate_bps: u32,
    pub min_fps: u32,
    pub max_fps: u32,
    pub initial_fps: u32,
    pub target_rtt_ns: u64,
    pub max_tolerable_jitter_ns: u64,
    pub loss_threshold_high_million: u32,
    pub loss_threshold_low_million: u32,
    pub additive_increase_bps: u32,
    pub multiplicative_decrease_scaled: u32,
    pub reconfigure_bitrate_delta_bps: u32,
}

impl Default for AdaptiveCongestionConfig {
    fn default() -> Self {
        Self {
            min_bitrate_bps: MIN_TARGET_BITRATE_BPS,
            max_bitrate_bps: MAX_TARGET_BITRATE_BPS,
            initial_bitrate_bps: 20_000_000,
            min_fps: MIN_TARGET_FRAMERATE_FPS,
            max_fps: MAX_TARGET_FRAMERATE_FPS,
            initial_fps: 60,
            target_rtt_ns: 30_000_000,
            max_tolerable_jitter_ns: 15_000_000,
            loss_threshold_high_million: 50_000,
            loss_threshold_low_million: 10_000,
            additive_increase_bps: 1_000_000,
            multiplicative_decrease_scaled: 750_000,
            reconfigure_bitrate_delta_bps: 2_000_000,
        }
    }
}

impl AdaptiveCongestionConfig {
    pub fn validate(self) -> Result<(), TransportError> {
        if self.min_bitrate_bps < MIN_TARGET_BITRATE_BPS
            || self.max_bitrate_bps > MAX_TARGET_BITRATE_BPS
            || self.min_bitrate_bps > self.max_bitrate_bps
            || self.initial_bitrate_bps < self.min_bitrate_bps
            || self.initial_bitrate_bps > self.max_bitrate_bps
            || self.min_fps < MIN_TARGET_FRAMERATE_FPS
            || self.max_fps > MAX_TARGET_FRAMERATE_FPS
            || self.min_fps > self.max_fps
            || self.initial_fps < self.min_fps
            || self.initial_fps > self.max_fps
            || self.target_rtt_ns == 0
            || self.additive_increase_bps == 0
            || self.multiplicative_decrease_scaled == 0
            || self.multiplicative_decrease_scaled >= 1_000_000
        {
            return Err(TransportError::CongestionConfigInvalid);
        }
        Ok(())
    }
}

/// Output recommendation from the congestion controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionDecision {
    pub target_bitrate_bps: u32,
    pub max_bitrate_bps: u32,
    pub target_fps: u32,
    pub requires_codec_reconfigure: bool,
    pub force_keyframe: bool,
    pub smoothed_rtt_ns: u64,
    pub smoothed_loss_million: u32,
    pub smoothed_jitter_ns: u64,
}

/// Reason for a codec reconfiguration signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconfigureReason {
    LossSpike,
    EpochBump,
    BandwidthAdjustment,
    RecoveryRequested,
}

/// Reconfiguration signal to send to the video encoder/coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecReconfigureSignal {
    pub stream_id: u32,
    pub codec_epoch: u32,
    pub target_bitrate_bps: u32,
    pub max_bitrate_bps: u32,
    pub target_fps: u32,
    pub force_keyframe: bool,
    pub reason: ReconfigureReason,
}

impl CodecReconfigureSignal {
    #[must_use]
    pub fn to_rate_update_message(&self) -> RateUpdateMessage {
        let mut flags = 0u16;
        if self.force_keyframe {
            flags |= rate_flags::FORCE_KEYFRAME;
        }
        if self.reason == ReconfigureReason::EpochBump {
            flags |= rate_flags::EPOCH_BUMP;
        }
        RateUpdateMessage {
            stream_id: self.stream_id,
            codec_epoch: self.codec_epoch,
            target_bitrate_bps: self.target_bitrate_bps,
            max_bitrate_bps: self.max_bitrate_bps,
            target_fps: self.target_fps,
            flags,
        }
    }
}

/// Real-time statistics from the congestion controller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CongestionStats {
    pub current_bitrate_bps: u32,
    pub current_fps: u32,
    pub smoothed_rtt_ns: u64,
    pub smoothed_loss_million: u32,
    pub smoothed_jitter_ns: u64,
    pub loss_events: u64,
    pub recovery_events: u64,
    pub reconfigure_signals: u64,
}

/// Production adaptive congestion controller.
#[derive(Debug, Clone)]
pub struct AdaptiveCongestionController {
    config: AdaptiveCongestionConfig,
    current_bitrate_bps: u32,
    current_fps: u32,
    smoothed_rtt_ns: u64,
    smoothed_loss_million: u32,
    smoothed_jitter_ns: u64,
    last_reconfigure_bitrate_bps: u32,
    last_reconfigure_fps: u32,
    last_update_ns: u64,
    stats: CongestionStats,
}

impl AdaptiveCongestionController {
    pub fn new(config: AdaptiveCongestionConfig) -> Result<Self, TransportError> {
        config.validate()?;
        let initial_bitrate = config.initial_bitrate_bps;
        let initial_fps = config.initial_fps;
        Ok(Self {
            config,
            current_bitrate_bps: initial_bitrate,
            current_fps: initial_fps,
            smoothed_rtt_ns: config.target_rtt_ns,
            smoothed_loss_million: 0,
            smoothed_jitter_ns: 0,
            last_reconfigure_bitrate_bps: initial_bitrate,
            last_reconfigure_fps: initial_fps,
            last_update_ns: 0,
            stats: CongestionStats {
                current_bitrate_bps: initial_bitrate,
                current_fps: initial_fps,
                smoothed_rtt_ns: config.target_rtt_ns,
                ..Default::default()
            },
        })
    }

    #[must_use]
    pub const fn target_bitrate_bps(&self) -> u32 {
        self.current_bitrate_bps
    }

    #[must_use]
    pub const fn max_bitrate_bps(&self) -> u32 {
        let max = self.current_bitrate_bps.saturating_mul(12) / 10;
        if max > self.config.max_bitrate_bps {
            self.config.max_bitrate_bps
        } else {
            max
        }
    }

    #[must_use]
    pub const fn target_fps(&self) -> u32 {
        self.current_fps
    }

    #[must_use]
    pub const fn stats(&self) -> CongestionStats {
        self.stats
    }

    pub fn on_sample(
        &mut self,
        rtt_ns: u64,
        loss_million: u32,
        jitter_ns: u64,
        now_ns: u64,
    ) -> CongestionDecision {
        if self.smoothed_rtt_ns == 0 {
            self.smoothed_rtt_ns = rtt_ns;
        } else {
            self.smoothed_rtt_ns = (self
                .smoothed_rtt_ns
                .saturating_mul(3)
                .saturating_add(rtt_ns))
                / 4;
        }
        if self.smoothed_loss_million == 0 && self.last_update_ns == 0 {
            self.smoothed_loss_million = loss_million;
        } else {
            self.smoothed_loss_million = (self
                .smoothed_loss_million
                .saturating_mul(3)
                .saturating_add(loss_million))
                / 4;
        }
        if self.smoothed_jitter_ns == 0 && self.last_update_ns == 0 {
            self.smoothed_jitter_ns = jitter_ns;
        } else {
            self.smoothed_jitter_ns = (self
                .smoothed_jitter_ns
                .saturating_mul(3)
                .saturating_add(jitter_ns))
                / 4;
        }
        self.last_update_ns = now_ns;

        let mut force_keyframe = false;
        let is_congested = self.smoothed_loss_million > self.config.loss_threshold_high_million
            || self.smoothed_rtt_ns > self.config.target_rtt_ns.saturating_mul(2)
            || self.smoothed_jitter_ns > self.config.max_tolerable_jitter_ns.saturating_mul(2);

        if is_congested {
            self.stats.loss_events = self.stats.loss_events.saturating_add(1);
            let reduced = (self.current_bitrate_bps as u64)
                .saturating_mul(u64::from(self.config.multiplicative_decrease_scaled))
                / 1_000_000;
            self.current_bitrate_bps =
                (reduced as u32).clamp(self.config.min_bitrate_bps, self.config.max_bitrate_bps);
            if self.smoothed_loss_million > 100_000 {
                self.current_fps = self
                    .current_fps
                    .saturating_sub(15)
                    .clamp(self.config.min_fps, self.config.max_fps);
                force_keyframe = true;
            }
        } else if self.smoothed_loss_million <= self.config.loss_threshold_low_million
            && self.smoothed_rtt_ns <= self.config.target_rtt_ns
            && self.smoothed_jitter_ns <= self.config.max_tolerable_jitter_ns
        {
            self.current_bitrate_bps = self
                .current_bitrate_bps
                .saturating_add(self.config.additive_increase_bps)
                .clamp(self.config.min_bitrate_bps, self.config.max_bitrate_bps);

            if self.current_bitrate_bps > 10_000_000 && self.current_fps < self.config.max_fps {
                self.current_fps = self
                    .current_fps
                    .saturating_add(5)
                    .clamp(self.config.min_fps, self.config.max_fps);
            }
        }

        let bitrate_diff = self
            .current_bitrate_bps
            .abs_diff(self.last_reconfigure_bitrate_bps);
        let fps_diff = self.current_fps.abs_diff(self.last_reconfigure_fps);

        let requires_reconfigure = force_keyframe
            || bitrate_diff >= self.config.reconfigure_bitrate_delta_bps
            || fps_diff >= 15;

        if requires_reconfigure {
            self.last_reconfigure_bitrate_bps = self.current_bitrate_bps;
            self.last_reconfigure_fps = self.current_fps;
            self.stats.reconfigure_signals = self.stats.reconfigure_signals.saturating_add(1);
        }

        self.stats.current_bitrate_bps = self.current_bitrate_bps;
        self.stats.current_fps = self.current_fps;
        self.stats.smoothed_rtt_ns = self.smoothed_rtt_ns;
        self.stats.smoothed_loss_million = self.smoothed_loss_million;
        self.stats.smoothed_jitter_ns = self.smoothed_jitter_ns;

        CongestionDecision {
            target_bitrate_bps: self.current_bitrate_bps,
            max_bitrate_bps: self.max_bitrate_bps(),
            target_fps: self.current_fps,
            requires_codec_reconfigure: requires_reconfigure,
            force_keyframe,
            smoothed_rtt_ns: self.smoothed_rtt_ns,
            smoothed_loss_million: self.smoothed_loss_million,
            smoothed_jitter_ns: self.smoothed_jitter_ns,
        }
    }

    pub fn on_feedback(
        &mut self,
        feedback: &CongestionFeedbackMessage,
        now_ns: u64,
    ) -> CongestionDecision {
        self.on_sample(
            u64::from(feedback.rtt_ns),
            feedback.loss_per_million,
            u64::from(feedback.jitter_ns),
            now_ns,
        )
    }

    pub fn on_loss_event(&mut self, now_ns: u64) -> CongestionDecision {
        self.stats.recovery_events = self.stats.recovery_events.saturating_add(1);
        let reduced = (self.current_bitrate_bps as u64)
            .saturating_mul(u64::from(self.config.multiplicative_decrease_scaled))
            / 1_000_000;
        self.current_bitrate_bps =
            (reduced as u32).clamp(self.config.min_bitrate_bps, self.config.max_bitrate_bps);
        self.last_reconfigure_bitrate_bps = self.current_bitrate_bps;
        self.last_update_ns = now_ns;
        self.stats.reconfigure_signals = self.stats.reconfigure_signals.saturating_add(1);
        self.stats.current_bitrate_bps = self.current_bitrate_bps;

        CongestionDecision {
            target_bitrate_bps: self.current_bitrate_bps,
            max_bitrate_bps: self.max_bitrate_bps(),
            target_fps: self.current_fps,
            requires_codec_reconfigure: true,
            force_keyframe: true,
            smoothed_rtt_ns: self.smoothed_rtt_ns,
            smoothed_loss_million: self.smoothed_loss_million,
            smoothed_jitter_ns: self.smoothed_jitter_ns,
        }
    }

    pub fn on_epoch_bump(&mut self, _new_epoch: u32, now_ns: u64) -> CongestionDecision {
        self.last_update_ns = now_ns;
        self.last_reconfigure_bitrate_bps = self.current_bitrate_bps;
        self.last_reconfigure_fps = self.current_fps;
        self.stats.reconfigure_signals = self.stats.reconfigure_signals.saturating_add(1);

        CongestionDecision {
            target_bitrate_bps: self.current_bitrate_bps,
            max_bitrate_bps: self.max_bitrate_bps(),
            target_fps: self.current_fps,
            requires_codec_reconfigure: true,
            force_keyframe: true,
            smoothed_rtt_ns: self.smoothed_rtt_ns,
            smoothed_loss_million: self.smoothed_loss_million,
            smoothed_jitter_ns: self.smoothed_jitter_ns,
        }
    }
}

/// Transport-layer error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Protocol(ProtocolError),
    FrameLength(usize),
    DatagramMtu(usize),
    PacketSize(usize),
    InvalidDeadline,
    Arithmetic,
    InvalidReassemblyConfig,
    FrameExceedsReassemblyBudget {
        frame_bytes: usize,
        budget_bytes: usize,
    },
    ReassemblyCapacity,
    MetadataConflict(FrameKey),
    FragmentConflict,
    FragmentOverlap,
    FragmentEntryLimit,
    IncompleteAssembly,
    UnsupportedParity,
    InvalidNetworkProfile,
    NetworkQueueFull,
    StaleCodecEpoch {
        packet_epoch: u32,
        current_epoch: u32,
    },
    ReplayDetected(u64),
    CongestionConfigInvalid,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(frame_id: u64) -> FragmentSpec {
        FragmentSpec {
            kind: MediaKind::Video,
            flags: media_flags::KEYFRAME,
            stream_id: 1,
            codec_epoch: 1,
            frame_id,
            dependency_frame_id: None,
        }
    }

    #[test]
    fn out_of_order_round_trip() {
        let frame: Vec<u8> = (0..20_000).map(|index| (index % 251) as u8).collect();
        let mut packets = fragment_frame(spec(9), &frame, 1_200).expect("fragment");
        packets.reverse();
        let mut reassembler = Reassembler::new(ReassemblyConfig::default()).expect("config");
        let mut completed = None;
        for (index, packet) in packets.iter().enumerate() {
            if let IngestOutcome::Complete(value) = reassembler
                .ingest(packet, index as u64 * 1_000)
                .expect("ingest")
            {
                completed = Some(value.bytes);
            }
        }
        assert_eq!(completed, Some(frame));
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn packet_budget_round_trip_supports_quic_overhead() {
        let frame: Vec<u8> = (0..5_000).map(|index| (index % 251) as u8).collect();
        let mut packets =
            fragment_frame_with_packet_budget(spec(10), &frame, 1_156).expect("fragment");

        assert!(packets.len() > 1);
        assert!(packets.iter().all(|packet| packet.len() <= 1_156));
        packets.reverse();

        let mut reassembler = Reassembler::new(ReassemblyConfig::default()).expect("config");
        let mut completed = None;
        for (index, packet) in packets.iter().enumerate() {
            if let IngestOutcome::Complete(value) = reassembler
                .ingest(packet, index as u64 * 1_000)
                .expect("ingest")
            {
                completed = Some(value.bytes);
            }
        }

        assert_eq!(completed, Some(frame));
    }

    #[test]
    fn exact_duplicate_is_idempotent() {
        let packets = fragment_frame(spec(1), &[3_u8; 2_000], 1_200).expect("fragment");
        let mut reassembler = Reassembler::new(ReassemblyConfig::default()).expect("config");
        assert!(matches!(
            reassembler.ingest(&packets[0], 0).expect("first"),
            IngestOutcome::Pending { .. }
        ));
        assert!(matches!(
            reassembler.ingest(&packets[0], 1).expect("duplicate"),
            IngestOutcome::Duplicate { .. }
        ));
    }

    #[test]
    fn conflicting_overlap_drops_frame() {
        let packets = fragment_frame(spec(2), &[7_u8; 2_000], 1_200).expect("fragment");
        let first = MediaPacket::decode(&packets[0]).expect("decode");
        let mut overlapping_header = first.header;
        overlapping_header.fragment_offset = 10;
        overlapping_header.fragment_len = 20;
        let overlapping = MediaPacket::encode(overlapping_header, &[8_u8; 20]).expect("encode");
        let mut reassembler = Reassembler::new(ReassemblyConfig::default()).expect("config");
        reassembler.ingest(&packets[0], 0).expect("first");
        assert_eq!(
            reassembler.ingest(&overlapping, 1),
            Err(TransportError::FragmentOverlap)
        );
        assert_eq!(reassembler.inflight_frames(), 0);
    }

    #[test]
    fn simulator_is_reproducible() {
        let profile = NetworkProfile {
            loss_per_million: 100_000,
            duplicate_per_million: 100_000,
            reorder_per_million: 100_000,
            ..NetworkProfile::default()
        };
        let run = |seed| {
            let mut simulator = NetworkSimulator::new(profile, seed).expect("profile");
            for id in 0..100 {
                let _ = simulator.submit(SimPacket {
                    id,
                    lane: NetworkLane::RealtimeMedia,
                    send_ns: id * 100_000,
                    deadline_ns: 1_000_000_000,
                    bytes: vec![id as u8; 100],
                });
            }
            let delivered: Vec<u64> = simulator
                .poll(2_000_000_000)
                .into_iter()
                .map(|delivered| delivered.packet.id)
                .collect();
            (simulator.stats(), delivered)
        };
        assert_eq!(run(42), run(42));
        assert_ne!(run(42), run(43));
    }

    #[test]
    fn expired_packet_never_reaches_application() {
        let mut simulator = NetworkSimulator::new(
            NetworkProfile {
                base_delay_ns: 10_000,
                jitter_ns: 0,
                ..NetworkProfile::default()
            },
            1,
        )
        .expect("profile");
        simulator
            .submit(SimPacket {
                id: 1,
                lane: NetworkLane::RealtimeMedia,
                send_ns: 0,
                deadline_ns: 1,
                bytes: vec![1],
            })
            .expect("submit");
        assert!(simulator.poll(100_000).is_empty());
        assert_eq!(simulator.stats().expired, 1);
    }

    #[test]
    fn mtu_validation_bounds() {
        assert!(validate_datagram_mtu(1_199).is_err());
        assert!(validate_datagram_mtu(1_200).is_ok());
        assert!(validate_datagram_mtu(1_400).is_ok());
        assert!(validate_datagram_mtu(1_450).is_ok());
        assert!(validate_datagram_mtu(1_451).is_err());
    }

    #[test]
    fn fragment_frame_validates_mtu_bounds() {
        let frame = [1u8; 100];
        assert_eq!(
            fragment_frame(spec(1), &frame, 1_199),
            Err(TransportError::DatagramMtu(1_199))
        );
        assert!(fragment_frame(spec(1), &frame, 1_200).is_ok());
        assert!(fragment_frame(spec(1), &frame, 1_450).is_ok());
        assert_eq!(
            fragment_frame(spec(1), &frame, 1_451),
            Err(TransportError::DatagramMtu(1_451))
        );
    }

    #[test]
    fn fragment_frame_with_packet_budget_validates_bounds() {
        let frame = [1_u8; 100];
        assert_eq!(
            fragment_frame_with_packet_budget(spec(1), &frame, MEDIA_HEADER_LEN),
            Err(TransportError::DatagramMtu(MEDIA_HEADER_LEN))
        );
        assert_eq!(
            fragment_frame_with_packet_budget(spec(1), &frame, MEDIA_HEADER_LEN - 1),
            Err(TransportError::DatagramMtu(MEDIA_HEADER_LEN - 1))
        );
        assert!(fragment_frame_with_packet_budget(spec(1), &frame, MEDIA_HEADER_LEN + 1).is_ok());
        assert_eq!(
            fragment_frame_with_packet_budget(spec(1), &frame, MAX_DATAGRAM_MTU + 1),
            Err(TransportError::DatagramMtu(MAX_DATAGRAM_MTU + 1))
        );
        assert_eq!(
            fragment_frame(spec(1), &frame, 1_199),
            Err(TransportError::DatagramMtu(1_199))
        );
    }

    #[test]
    fn reassembler_rejects_oversized_datagram() {
        let config = ReassemblyConfig {
            max_datagram_bytes: 1_300,
            ..Default::default()
        };
        let mut reassembler = Reassembler::new(config).expect("config");
        let oversized = vec![0_u8; 1_301];
        assert_eq!(
            reassembler.ingest(&oversized, 0),
            Err(TransportError::DatagramMtu(1_301))
        );
    }

    #[test]
    fn reassembler_handles_codec_epoch_stale_and_bump() {
        let mut reassembler = Reassembler::new(ReassemblyConfig::default()).expect("config");
        assert_eq!(reassembler.active_codec_epoch(), 1);

        // Frame with epoch 2 (bump)
        let mut spec2 = spec(10);
        spec2.codec_epoch = 2;
        let frame_bytes = vec![0xAA_u8; 3_000];
        let packets2 = fragment_frame(spec2, &frame_bytes, 1_200).expect("fragment");

        // Ingest first fragment of epoch 2
        let outcome = reassembler.ingest(&packets2[0], 1_000).expect("ingest");
        assert!(matches!(outcome, IngestOutcome::Pending { .. }));
        assert_eq!(reassembler.active_codec_epoch(), 2);
        assert_eq!(reassembler.stats().epoch_bumps, 1);

        // Ingest fragment of stale epoch 1 -> must be rejected
        let mut spec1 = spec(5);
        spec1.codec_epoch = 1;
        let packets1 = fragment_frame(spec1, &vec![0xBB_u8; 1_000], 1_200).expect("fragment");
        assert_eq!(
            reassembler.ingest(&packets1[0], 2_000),
            Err(TransportError::StaleCodecEpoch {
                packet_epoch: 1,
                current_epoch: 2,
            })
        );
        assert_eq!(reassembler.stats().stale_epoch_datagrams, 1);

        // Complete epoch 2 frame
        let mut completed = None;
        for packet in &packets2[1..] {
            if let IngestOutcome::Complete(res) = reassembler.ingest(packet, 3_000).expect("ingest")
            {
                completed = Some(res.bytes);
            }
        }
        assert_eq!(completed, Some(frame_bytes));
    }

    #[test]
    fn adaptive_congestion_controller_adaptation() {
        let config = AdaptiveCongestionConfig {
            initial_bitrate_bps: 10_000_000,
            initial_fps: 60,
            min_bitrate_bps: 500_000,
            max_bitrate_bps: 100_000_000,
            min_fps: 15,
            max_fps: 120,
            ..Default::default()
        };
        let mut controller = AdaptiveCongestionController::new(config).expect("controller");
        assert_eq!(controller.target_bitrate_bps(), 10_000_000);
        assert_eq!(controller.target_fps(), 60);

        // High loss / congestion sample: 15% loss
        let dec = controller.on_sample(80_000_000, 150_000, 20_000_000, 1_000);
        assert!(dec.target_bitrate_bps < 10_000_000);
        assert!(dec.target_bitrate_bps >= 500_000);

        // Multiple severe loss signals should throttle FPS and trigger keyframe
        for i in 2..10 {
            controller.on_sample(100_000_000, 200_000, 30_000_000, i * 1_000);
        }
        assert!(controller.target_fps() < 60);
        assert!(controller.target_fps() >= 15);
        assert!(controller.target_bitrate_bps() >= 500_000);

        // Clean, low-loss channel -> additive increase
        let before = controller.target_bitrate_bps();
        let before_fps = controller.target_fps();
        for i in 10..50 {
            controller.on_sample(15_000_000, 0, 1_000_000, i * 1_000);
        }
        assert!(controller.target_bitrate_bps() > before);
        assert!(controller.target_fps() >= before_fps);
    }

    #[test]
    fn congestion_controller_loss_event_and_epoch_bump() {
        let mut controller =
            AdaptiveCongestionController::new(AdaptiveCongestionConfig::default()).expect("ctrl");

        let loss_dec = controller.on_loss_event(1_000);
        assert!(loss_dec.requires_codec_reconfigure);
        assert!(loss_dec.force_keyframe);

        let bump_dec = controller.on_epoch_bump(2, 2_000);
        assert!(bump_dec.requires_codec_reconfigure);
        assert!(bump_dec.force_keyframe);

        let signal = CodecReconfigureSignal {
            stream_id: 1,
            codec_epoch: 2,
            target_bitrate_bps: bump_dec.target_bitrate_bps,
            max_bitrate_bps: bump_dec.max_bitrate_bps,
            target_fps: bump_dec.target_fps,
            force_keyframe: true,
            reason: ReconfigureReason::EpochBump,
        };
        let msg = signal.to_rate_update_message();
        assert_eq!(msg.stream_id, 1);
        assert_eq!(msg.codec_epoch, 2);
        assert!(msg.flags & rate_flags::FORCE_KEYFRAME != 0);
        assert!(msg.flags & rate_flags::EPOCH_BUMP != 0);
    }
}
