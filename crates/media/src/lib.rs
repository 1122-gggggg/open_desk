//! Codec-continuity primitives and capture-surface ownership contracts.

/// Conservative inter-frame dependency metadata supplied by an encoder provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedFrameMeta {
    /// Decoder configuration/continuity generation.
    pub codec_epoch: u32,
    /// Monotonic encoded frame identifier.
    pub frame_id: u64,
    /// Required previously decoded frame. `None` means independently decodable.
    pub dependency_frame_id: Option<u64>,
    /// Provider guarantees this frame resets decoder continuity.
    pub recovery_point: bool,
}

/// Action returned by [`DecoderContinuity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityAction {
    /// Decode normally.
    Decode,
    /// Reset decoder state/configuration and decode this recovery point.
    ResetAndDecode,
    /// Drop the access unit and send a rate-limited recovery request.
    DropAndRequestRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinuityCommitError {
    InvalidDecodedDependency,
}

/// Client-side conservative continuity tracker.
#[derive(Debug, Default, Clone)]
pub struct DecoderContinuity {
    epoch: Option<u32>,
    last_decoded_frame: Option<u64>,
    recovery_outstanding: bool,
}

impl DecoderContinuity {
    /// Classifies an encoded frame without claiming that native decode succeeded.
    #[must_use]
    pub fn classify(&self, frame: EncodedFrameMeta) -> ContinuityAction {
        if frame.recovery_point {
            return ContinuityAction::ResetAndDecode;
        }
        let same_epoch = self.epoch == Some(frame.codec_epoch);
        let dependency_present = frame.dependency_frame_id == self.last_decoded_frame;
        if same_epoch && dependency_present && !self.recovery_outstanding {
            ContinuityAction::Decode
        } else {
            ContinuityAction::DropAndRequestRecovery
        }
    }

    /// Commits continuity only after the matching native decoder output exists.
    pub fn commit_decoded(&mut self, frame: EncodedFrameMeta) -> Result<(), ContinuityCommitError> {
        if frame.recovery_point {
            self.epoch = Some(frame.codec_epoch);
            self.last_decoded_frame = Some(frame.frame_id);
            self.recovery_outstanding = false;
            return Ok(());
        }
        let valid = self.epoch == Some(frame.codec_epoch)
            && frame.dependency_frame_id == self.last_decoded_frame
            && self
                .last_decoded_frame
                .is_none_or(|decoded| frame.frame_id > decoded);
        if !valid {
            return Err(ContinuityCommitError::InvalidDecodedDependency);
        }
        self.last_decoded_frame = Some(frame.frame_id);
        Ok(())
    }

    /// Marks a frame as lost before decode. Later dependent frames must not decode.
    pub fn note_loss(&mut self) {
        self.recovery_outstanding = true;
    }

    #[must_use]
    pub const fn last_decoded_frame_id(&self) -> Option<u64> {
        self.last_decoded_frame
    }

    /// Whether a recovery request should remain outstanding.
    #[must_use]
    pub const fn recovery_outstanding(&self) -> bool {
        self.recovery_outstanding
    }
}

/// Memory domain of a captured or imported surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryDomain {
    Cpu,
    D3D11,
    DmaBuf,
    VendorOpaque,
}

/// Minimal frame descriptor shared across platform-provider boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameDescriptor {
    pub width: u32,
    pub height: u32,
    pub format_fourcc: u32,
    pub memory_domain: MemoryDomain,
    pub capture_sequence: u64,
    /// Host-local monotonic timestamp. Never directly subtract from client time.
    pub capture_timestamp_ns: u64,
}

impl FrameDescriptor {
    /// Rejects dimensions that could cause accidental unbounded allocation.
    pub fn validate(&self) -> Result<(), FrameDescriptorError> {
        const MAX_DIMENSION: u32 = 16_384;
        const MAX_PIXELS: u64 = 134_217_728;
        if self.width == 0
            || self.height == 0
            || self.width > MAX_DIMENSION
            || self.height > MAX_DIMENSION
        {
            return Err(FrameDescriptorError::Dimension);
        }
        let pixels = u64::from(self.width) * u64::from(self.height);
        if pixels > MAX_PIXELS {
            return Err(FrameDescriptorError::PixelCount);
        }
        Ok(())
    }
}

/// Invalid captured-frame descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDescriptorError {
    Dimension,
    PixelCount,
}

/// Actual transfer path reported after a capture lease is safely detached.
///
/// `DirectAlias` is deliberately narrower than "no CPU copy": it means the
/// provider has profiler evidence of same-device, no-application-copy aliasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportPath {
    DirectAlias,
    GpuConvert,
    GpuCopy,
    CpuCopy,
    InternalCopyUnknown,
}

/// Opaque provider-supplied identity for one physical graphics device.
///
/// It never contains a raw handle and is intended for equality and telemetry
/// only. `Unknown` is acceptable only for CPU-copy paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIdentity {
    Unknown,
    Opaque(u64),
}

/// Stable identity of the borrowed capture lease represented by a ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLeaseIdentity {
    pub provider_epoch: u32,
    pub capture_sequence: u64,
}

/// Layout relevant to a cross-provider surface import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceLayout {
    pub memory_domain: MemoryDomain,
    pub format_fourcc: u32,
    pub plane_count: u8,
    pub modifier: Option<u64>,
}

impl SurfaceLayout {
    fn valid(self) -> bool {
        (1..=4).contains(&self.plane_count)
    }
}

/// Pipeline edge that produced this ownership record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferEdge {
    CaptureToEncoder,
    DecodeToPresenter,
}

/// Completion primitive proving a producer buffer may be released or requeued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynchronizationProof {
    CpuSynchronous,
    D3D11EventQuery,
    D3D11Fence,
    VulkanFence,
    ExplicitFence,
    ImplicitFence,
    ProviderSafeDetach,
    Unknown,
}

/// Whether the completion primitive has actually completed for this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseCompletion {
    Pending,
    Proven,
    Failed,
}

/// Evidence supporting the recorded path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CopyEvidenceGrade {
    Unverified,
    ProviderReported,
    CompletionProven,
    ProfilerVerifiedNoApplicationCopy,
}

/// Reason the intended import path used a more conservative fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyFallbackReason {
    FormatConversion,
    CrossAdapter,
    UnsupportedDevice,
    UnsupportedModifier,
    UnsupportedSynchronization,
    ProviderRejected,
    ResourcePressure,
}

/// Per-frame ownership and transfer record emitted by a platform provider.
///
/// The record contains no raw GPU handles, FDs, pixels, or sync payloads. It is
/// safe to retain in bounded telemetry after the backing native objects die.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyLedger {
    pub source_lease: SourceLeaseIdentity,
    pub source_device: DeviceIdentity,
    pub destination_device: DeviceIdentity,
    pub source_layout: SurfaceLayout,
    pub destination_layout: SurfaceLayout,
    pub transfer_edge: TransferEdge,
    pub path: ImportPath,
    pub synchronization: SynchronizationProof,
    pub completion: LeaseCompletion,
    pub fallback_reason: Option<CopyFallbackReason>,
    pub evidence: CopyEvidenceGrade,
}

impl CopyLedger {
    /// Validates a completed ownership handoff before a capture lease is released.
    pub fn validate(&self) -> Result<(), CopyLedgerError> {
        if self.source_lease.provider_epoch == 0 {
            return Err(CopyLedgerError::ProviderEpoch);
        }
        if !self.source_layout.valid() {
            return Err(CopyLedgerError::InvalidSourceLayout);
        }
        if !self.destination_layout.valid() {
            return Err(CopyLedgerError::InvalidDestinationLayout);
        }
        if self.completion != LeaseCompletion::Proven {
            return Err(CopyLedgerError::CompletionNotProven);
        }
        if self.synchronization == SynchronizationProof::Unknown {
            return Err(CopyLedgerError::SynchronizationNotProven);
        }
        if self.evidence < CopyEvidenceGrade::CompletionProven {
            return Err(CopyLedgerError::EvidenceInsufficient);
        }
        match self.path {
            ImportPath::DirectAlias => {
                if !same_known_device(self.source_device, self.destination_device) {
                    return Err(CopyLedgerError::DirectAliasRequiresMatchingDevices);
                }
                if self.source_layout != self.destination_layout {
                    return Err(CopyLedgerError::DirectAliasRequiresMatchingLayout);
                }
                if self.evidence != CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy {
                    return Err(CopyLedgerError::DirectAliasRequiresProfilerEvidence);
                }
                if self.fallback_reason.is_some() {
                    return Err(CopyLedgerError::DirectAliasCannotHaveFallback);
                }
            }
            ImportPath::GpuConvert | ImportPath::GpuCopy => {
                if !known_device(self.source_device) || !known_device(self.destination_device) {
                    return Err(CopyLedgerError::GpuPathRequiresDeviceIdentity);
                }
            }
            ImportPath::CpuCopy | ImportPath::InternalCopyUnknown => {}
        }
        Ok(())
    }

    /// Ensures the ledger names the descriptor that entered this capture lease.
    pub fn validate_capture_source(
        &self,
        descriptor: FrameDescriptor,
    ) -> Result<(), CopyLedgerError> {
        self.validate()?;
        if self.source_lease.capture_sequence != descriptor.capture_sequence {
            return Err(CopyLedgerError::CaptureSequenceMismatch);
        }
        if self.source_layout.memory_domain != descriptor.memory_domain {
            return Err(CopyLedgerError::SourceMemoryDomainMismatch);
        }
        if self.source_layout.format_fourcc != descriptor.format_fourcc {
            return Err(CopyLedgerError::SourceFormatMismatch);
        }
        Ok(())
    }
}

fn known_device(identity: DeviceIdentity) -> bool {
    matches!(identity, DeviceIdentity::Opaque(_))
}

fn same_known_device(source: DeviceIdentity, destination: DeviceIdentity) -> bool {
    matches!(
        (source, destination),
        (DeviceIdentity::Opaque(source), DeviceIdentity::Opaque(destination)) if source == destination
    )
}

/// Invalid or insufficiently evidenced copy-path ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyLedgerError {
    ProviderEpoch,
    InvalidSourceLayout,
    InvalidDestinationLayout,
    CompletionNotProven,
    SynchronizationNotProven,
    EvidenceInsufficient,
    DirectAliasRequiresMatchingDevices,
    DirectAliasRequiresMatchingLayout,
    DirectAliasRequiresProfilerEvidence,
    DirectAliasCannotHaveFallback,
    GpuPathRequiresDeviceIdentity,
    CaptureSequenceMismatch,
    SourceMemoryDomainMismatch,
    SourceFormatMismatch,
}

impl std::fmt::Display for CopyLedgerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CopyLedgerError {}
/// Coordinate of a tile in a 2D tile grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TileCoord {
    pub x: u32,
    pub y: u32,
}

impl TileCoord {
    #[must_use]
    pub const fn new(x: u32, y: u32) -> Self {
        Self { x, y }
    }
}

/// Metadata describing a discrete lossless tile refinement packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TileRefinementMeta {
    /// Display/configuration epoch. Mismatches invalidate client cache.
    pub display_epoch: u32,
    /// Monotonic generation sequence of this refinement unit.
    pub generation: u64,
    /// Tile coordinates in the active tile grid.
    pub coord: TileCoord,
    /// Pixel dimensions of the tile (may be smaller on display borders).
    pub width: u32,
    pub height: u32,
    /// Exact 64-bit checksum of the lossless uncompressed pixel data.
    pub hash: u64,
}

/// Status of the static idle refinement policy for a display stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleRefinementStatus {
    /// Motion detected; tile refinement is suppressed to prioritize base video.
    ActiveMotion,
    /// Display has remained static but has not yet exceeded the idle threshold.
    StaticPending { idle_duration_ns: u64 },
    /// Display has exceeded the idle threshold (>100ms) and is actively refining.
    Refining {
        idle_duration_ns: u64,
        remaining_tiles: usize,
    },
    /// Display is fully refined to lossless quality.
    FullyRefined { idle_duration_ns: u64 },
}

/// Observable counters and memory metrics for a tile refinement cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TileCacheStats {
    pub cached_tiles: usize,
    pub memory_bytes: usize,
    pub max_memory_bytes: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub stale_rejections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_does_not_advance_before_decode_commit() {
        let mut continuity = DecoderContinuity::default();
        let idr = EncodedFrameMeta {
            codec_epoch: 1,
            frame_id: 10,
            dependency_frame_id: None,
            recovery_point: true,
        };
        let p = EncodedFrameMeta {
            codec_epoch: 1,
            frame_id: 11,
            dependency_frame_id: Some(10),
            recovery_point: false,
        };
        assert_eq!(continuity.classify(idr), ContinuityAction::ResetAndDecode);
        assert_eq!(continuity.last_decoded_frame_id(), None);
        assert_eq!(
            continuity.classify(p),
            ContinuityAction::DropAndRequestRecovery
        );
        continuity.commit_decoded(idr).expect("decoded IDR");
        assert_eq!(continuity.classify(p), ContinuityAction::Decode);
        assert_eq!(continuity.last_decoded_frame_id(), Some(10));
        continuity.commit_decoded(p).expect("decoded P");
        assert_eq!(continuity.last_decoded_frame_id(), Some(11));
    }

    #[test]
    fn decode_failure_blocks_dependents_until_recovery_commit() {
        let mut continuity = DecoderContinuity::default();
        continuity
            .commit_decoded(EncodedFrameMeta {
                codec_epoch: 1,
                frame_id: 10,
                dependency_frame_id: None,
                recovery_point: true,
            })
            .expect("decoded IDR");
        continuity.note_loss();
        assert_eq!(
            continuity.classify(EncodedFrameMeta {
                codec_epoch: 1,
                frame_id: 12,
                dependency_frame_id: Some(10),
                recovery_point: false,
            }),
            ContinuityAction::DropAndRequestRecovery
        );
        let recovery = EncodedFrameMeta {
            codec_epoch: 2,
            frame_id: 20,
            dependency_frame_id: None,
            recovery_point: true,
        };
        assert_eq!(
            continuity.classify(recovery),
            ContinuityAction::ResetAndDecode
        );
        assert!(continuity.recovery_outstanding());
        continuity
            .commit_decoded(recovery)
            .expect("decoded recovery");
        assert!(!continuity.recovery_outstanding());
        assert_eq!(continuity.last_decoded_frame_id(), Some(20));
    }

    #[test]
    fn frame_dimensions_are_bounded() {
        let frame = FrameDescriptor {
            width: 100_000,
            height: 1,
            format_fourcc: 0,
            memory_domain: MemoryDomain::Cpu,
            capture_sequence: 0,
            capture_timestamp_ns: 0,
        };
        assert_eq!(frame.validate(), Err(FrameDescriptorError::Dimension));
    }

    #[test]
    fn direct_alias_requires_profiler_evidence_and_completion() {
        let mut ledger = CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: 1,
                capture_sequence: 9,
            },
            source_device: DeviceIdentity::Opaque(7),
            destination_device: DeviceIdentity::Opaque(7),
            source_layout: SurfaceLayout {
                memory_domain: MemoryDomain::D3D11,
                format_fourcc: u32::from_le_bytes(*b"BGRA"),
                plane_count: 1,
                modifier: None,
            },
            destination_layout: SurfaceLayout {
                memory_domain: MemoryDomain::D3D11,
                format_fourcc: u32::from_le_bytes(*b"BGRA"),
                plane_count: 1,
                modifier: None,
            },
            transfer_edge: TransferEdge::CaptureToEncoder,
            path: ImportPath::DirectAlias,
            synchronization: SynchronizationProof::D3D11EventQuery,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: CopyEvidenceGrade::CompletionProven,
        };
        assert_eq!(
            ledger.validate(),
            Err(CopyLedgerError::DirectAliasRequiresProfilerEvidence)
        );
        ledger.evidence = CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy;
        assert_eq!(ledger.validate(), Ok(()));
    }

    #[test]
    fn direct_alias_requires_an_identical_surface_layout() {
        let ledger = CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: 1,
                capture_sequence: 9,
            },
            source_device: DeviceIdentity::Opaque(7),
            destination_device: DeviceIdentity::Opaque(7),
            source_layout: SurfaceLayout {
                memory_domain: MemoryDomain::D3D11,
                format_fourcc: u32::from_le_bytes(*b"BGRA"),
                plane_count: 1,
                modifier: None,
            },
            destination_layout: SurfaceLayout {
                memory_domain: MemoryDomain::D3D11,
                format_fourcc: u32::from_le_bytes(*b"NV12"),
                plane_count: 2,
                modifier: None,
            },
            transfer_edge: TransferEdge::CaptureToEncoder,
            path: ImportPath::DirectAlias,
            synchronization: SynchronizationProof::D3D11EventQuery,
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy,
        };
        assert_eq!(
            ledger.validate(),
            Err(CopyLedgerError::DirectAliasRequiresMatchingLayout)
        );
    }

    #[test]
    fn tile_coord_ordering_and_equality() {
        let c1 = TileCoord::new(0, 0);
        let c2 = TileCoord::new(1, 0);
        let c3 = TileCoord::new(0, 1);
        assert_eq!(c1, TileCoord { x: 0, y: 0 });
        assert!(c1 < c2);
        assert!(c1 < c3);
    }

    #[test]
    fn tile_refinement_meta_fields() {
        let meta = TileRefinementMeta {
            display_epoch: 1,
            generation: 100,
            coord: TileCoord::new(2, 3),
            width: 64,
            height: 64,
            hash: 0x1234_5678_9abc_def0,
        };
        assert_eq!(meta.display_epoch, 1);
        assert_eq!(meta.generation, 100);
        assert_eq!(meta.coord.x, 2);
        assert_eq!(meta.coord.y, 3);
        assert_eq!(meta.width, 64);
        assert_eq!(meta.height, 64);
        assert_eq!(meta.hash, 0x1234_5678_9abc_def0);
    }

    #[test]
    fn idle_refinement_status_variants() {
        let motion = IdleRefinementStatus::ActiveMotion;
        let pending = IdleRefinementStatus::StaticPending {
            idle_duration_ns: 50_000_000,
        };
        let refining = IdleRefinementStatus::Refining {
            idle_duration_ns: 120_000_000,
            remaining_tiles: 12,
        };
        let fully = IdleRefinementStatus::FullyRefined {
            idle_duration_ns: 300_000_000,
        };
        assert_ne!(motion, pending);
        assert_ne!(refining, fully);
    }

    #[test]
    fn tile_cache_stats_default() {
        let stats = TileCacheStats::default();
        assert_eq!(stats.cached_tiles, 0);
        assert_eq!(stats.memory_bytes, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.evictions, 0);
        assert_eq!(stats.stale_rejections, 0);
    }
}
