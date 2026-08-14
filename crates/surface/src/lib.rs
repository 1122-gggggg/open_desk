//! Bounded surface ownership and capture-lease contracts.
//!
//! A native capture buffer must never be retained indefinitely. Providers import
//! or copy it into this encoder-owned pool before returning from the capture
//! callback. RAII tokens guarantee release on every error path.

use latencydesk_media::{
    CopyLedger, CopyLedgerError, DeviceIdentity, FrameDescriptor, ImportPath, SurfaceLayout,
};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

/// Opaque native allocation retained by an [`OwnedSurface`].
///
/// The payload represents the exact encoder/decoder-owned resource created by
/// a platform bridge. It is dropped before its pool slot becomes reusable.
pub trait SurfacePayload: fmt::Debug + Send + 'static {
    #[must_use]
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Stable slot identifier within one pool generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SurfaceId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Available,
    CaptureLeased,
    Owned,
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    generation: u64,
    state: SlotState,
    descriptor: Option<FrameDescriptor>,
    destination: Option<DestinationSurfaceSpec>,
    copy_ledger: Option<CopyLedger>,
}

/// Exact engine-owned destination reserved before a native capture copy.
///
/// This is data-only: the device identity is opaque and the backing native
/// allocation remains owned by the pool/bridge implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationSurfaceSpec {
    descriptor: FrameDescriptor,
    device: DeviceIdentity,
    layout: SurfaceLayout,
}

impl DestinationSurfaceSpec {
    pub fn new(
        descriptor: FrameDescriptor,
        device: DeviceIdentity,
        layout: SurfaceLayout,
    ) -> Result<Self, SurfaceError> {
        descriptor
            .validate()
            .map_err(|_| SurfaceError::InvalidDescriptor)?;
        if layout.memory_domain != descriptor.memory_domain
            || layout.format_fourcc != descriptor.format_fourcc
            || !(1..=4).contains(&layout.plane_count)
        {
            return Err(SurfaceError::InvalidDestination);
        }
        Ok(Self {
            descriptor,
            device,
            layout,
        })
    }

    #[must_use]
    pub const fn descriptor(self) -> FrameDescriptor {
        self.descriptor
    }

    #[must_use]
    pub const fn device(self) -> DeviceIdentity {
        self.device
    }

    #[must_use]
    pub const fn layout(self) -> SurfaceLayout {
        self.layout
    }
}

#[derive(Debug)]
struct PoolInner {
    slots: Vec<Slot>,
    in_use: usize,
    stats: SurfacePoolStats,
}

/// Observable pool counters. These are required soak-test telemetry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SurfacePoolStats {
    pub acquisition_attempts: u64,
    pub acquisitions: u64,
    pub pool_exhaustions: u64,
    pub imports_direct_alias: u64,
    pub imports_gpu_convert: u64,
    pub imports_gpu_copy: u64,
    pub imports_cpu_copy: u64,
    pub imports_internal_copy_unknown: u64,
    pub releases: u64,
    pub invalid_transitions: u64,
    pub high_watermark: usize,
}

/// Thread-safe, fixed-capacity surface pool.
#[derive(Debug, Clone)]
pub struct SurfacePool {
    inner: Arc<Mutex<PoolInner>>,
}

impl SurfacePool {
    /// Creates every slot up front. Capacity can never grow during a session.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "surface capacity must be nonzero");
        assert!(capacity <= 4_096, "surface capacity exceeds hard limit");
        let slots = (0..capacity)
            .map(|_| Slot {
                generation: 0,
                state: SlotState::Available,
                descriptor: None,
                destination: None,
                copy_ledger: None,
            })
            .collect();
        Self {
            inner: Arc::new(Mutex::new(PoolInner {
                slots,
                in_use: 0,
                stats: SurfacePoolStats::default(),
            })),
        }
    }

    /// Acquires a slot representing a provider-owned native capture lease.
    /// Dropping the returned guard without import releases the slot immediately.
    pub fn acquire_capture(
        &self,
        descriptor: FrameDescriptor,
    ) -> Result<CaptureLease, SurfaceError> {
        self.acquire(descriptor, None)
    }

    /// Reserves the exact destination allocation/layout that a native capture
    /// callback must populate before its borrowed input can be released.
    pub fn reserve_destination(
        &self,
        destination: DestinationSurfaceSpec,
    ) -> Result<CaptureLease, SurfaceError> {
        self.acquire(destination.descriptor(), Some(destination))
    }

    fn acquire(
        &self,
        descriptor: FrameDescriptor,
        destination: Option<DestinationSurfaceSpec>,
    ) -> Result<CaptureLease, SurfaceError> {
        descriptor
            .validate()
            .map_err(|_| SurfaceError::InvalidDescriptor)?;
        let mut inner = lock(&self.inner)?;
        inner.stats.acquisition_attempts = inner.stats.acquisition_attempts.saturating_add(1);
        let Some((index, slot)) = inner
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.state == SlotState::Available)
        else {
            inner.stats.pool_exhaustions = inner.stats.pool_exhaustions.saturating_add(1);
            return Err(SurfaceError::PoolExhausted);
        };
        slot.generation = slot.generation.wrapping_add(1).max(1);
        slot.state = SlotState::CaptureLeased;
        slot.descriptor = Some(descriptor);
        slot.destination = destination;
        slot.copy_ledger = None;
        let generation = slot.generation;
        inner.in_use = inner.in_use.saturating_add(1);
        inner.stats.acquisitions = inner.stats.acquisitions.saturating_add(1);
        inner.stats.high_watermark = inner.stats.high_watermark.max(inner.in_use);
        drop(inner);
        Ok(CaptureLease {
            pool: Arc::clone(&self.inner),
            id: SurfaceId(index as u32),
            generation,
            active: true,
        })
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        lock_unpoisoned(&self.inner).slots.len()
    }

    #[must_use]
    pub fn in_use(&self) -> usize {
        lock_unpoisoned(&self.inner).in_use
    }

    #[must_use]
    pub fn stats(&self) -> SurfacePoolStats {
        lock_unpoisoned(&self.inner).stats
    }
}

/// Native-capture lease that must be imported/copied before callback return.
#[derive(Debug)]
pub struct CaptureLease {
    pool: Arc<Mutex<PoolInner>>,
    id: SurfaceId,
    generation: u64,
    active: bool,
}

impl CaptureLease {
    #[must_use]
    pub const fn id(&self) -> SurfaceId {
        self.id
    }

    pub fn descriptor(&self) -> Result<FrameDescriptor, SurfaceError> {
        let inner = lock(&self.pool)?;
        let slot = checked_slot(&inner, self.id, self.generation)?;
        if slot.state != SlotState::CaptureLeased {
            return Err(SurfaceError::InvalidState);
        }
        slot.descriptor.ok_or(SurfaceError::InvalidState)
    }

    /// Completes synchronous import/copy and transfers the slot to asynchronous
    /// encoder/decoder ownership. The capture lease is released only after the
    /// ledger records a completed, evidenced safe-detach edge.
    pub fn import(self, ledger: CopyLedger) -> Result<OwnedSurface, SurfaceError> {
        self.import_with_optional_payload(ledger, None)
    }

    /// Completes import while retaining an opaque native allocation for the
    /// exact lifetime of the resulting owned surface.
    pub fn import_with_payload(
        self,
        ledger: CopyLedger,
        payload: Box<dyn SurfacePayload>,
    ) -> Result<OwnedSurface, SurfaceError> {
        self.import_with_optional_payload(ledger, Some(payload))
    }

    fn import_with_optional_payload(
        mut self,
        ledger: CopyLedger,
        payload: Option<Box<dyn SurfacePayload>>,
    ) -> Result<OwnedSurface, SurfaceError> {
        let descriptor = self.descriptor()?;
        if self.destination()?.is_some() {
            return Err(SurfaceError::InvalidState);
        }
        ledger
            .validate_capture_source(descriptor)
            .map_err(SurfaceError::CopyLedger)?;
        self.finish_import(ledger, payload)
    }

    /// Completes a copy from a borrowed capture input into this exact reserved
    /// destination. The resulting surface descriptor is the destination
    /// descriptor, never the borrowed source descriptor.
    pub fn import_from_capture(
        self,
        source_descriptor: FrameDescriptor,
        ledger: CopyLedger,
    ) -> Result<OwnedSurface, SurfaceError> {
        self.import_from_capture_with_optional_payload(source_descriptor, ledger, None)
    }

    /// Completes a reserved capture import while retaining the exact native
    /// destination allocation until the owned surface is released.
    pub fn import_from_capture_with_payload(
        self,
        source_descriptor: FrameDescriptor,
        ledger: CopyLedger,
        payload: Box<dyn SurfacePayload>,
    ) -> Result<OwnedSurface, SurfaceError> {
        self.import_from_capture_with_optional_payload(source_descriptor, ledger, Some(payload))
    }

    fn import_from_capture_with_optional_payload(
        mut self,
        source_descriptor: FrameDescriptor,
        ledger: CopyLedger,
        payload: Option<Box<dyn SurfacePayload>>,
    ) -> Result<OwnedSurface, SurfaceError> {
        source_descriptor
            .validate()
            .map_err(|_| SurfaceError::InvalidDescriptor)?;
        let destination = self.destination()?.ok_or(SurfaceError::InvalidState)?;
        ledger
            .validate_capture_source(source_descriptor)
            .map_err(SurfaceError::CopyLedger)?;
        if ledger.destination_device != destination.device()
            || ledger.destination_layout != destination.layout()
            || self.descriptor()? != destination.descriptor()
            || source_descriptor.width != destination.descriptor().width
            || source_descriptor.height != destination.descriptor().height
            || source_descriptor.capture_sequence != destination.descriptor().capture_sequence
            || source_descriptor.capture_timestamp_ns
                != destination.descriptor().capture_timestamp_ns
        {
            return Err(SurfaceError::DestinationMismatch);
        }
        self.finish_import(ledger, payload)
    }

    fn destination(&self) -> Result<Option<DestinationSurfaceSpec>, SurfaceError> {
        let inner = lock(&self.pool)?;
        let slot = checked_slot(&inner, self.id, self.generation)?;
        if slot.state != SlotState::CaptureLeased {
            return Err(SurfaceError::InvalidState);
        }
        Ok(slot.destination)
    }

    fn finish_import(
        &mut self,
        ledger: CopyLedger,
        payload: Option<Box<dyn SurfacePayload>>,
    ) -> Result<OwnedSurface, SurfaceError> {
        {
            let mut inner = lock(&self.pool)?;
            let slot = checked_slot_mut(&mut inner, self.id, self.generation)?;
            if slot.state != SlotState::CaptureLeased {
                inner.stats.invalid_transitions = inner.stats.invalid_transitions.saturating_add(1);
                return Err(SurfaceError::InvalidState);
            }
            slot.state = SlotState::Owned;
            slot.copy_ledger = Some(ledger);
            match ledger.path {
                ImportPath::DirectAlias => {
                    inner.stats.imports_direct_alias =
                        inner.stats.imports_direct_alias.saturating_add(1);
                }
                ImportPath::GpuConvert => {
                    inner.stats.imports_gpu_convert =
                        inner.stats.imports_gpu_convert.saturating_add(1);
                }
                ImportPath::GpuCopy => {
                    inner.stats.imports_gpu_copy = inner.stats.imports_gpu_copy.saturating_add(1);
                }
                ImportPath::CpuCopy => {
                    inner.stats.imports_cpu_copy = inner.stats.imports_cpu_copy.saturating_add(1);
                }
                ImportPath::InternalCopyUnknown => {
                    inner.stats.imports_internal_copy_unknown =
                        inner.stats.imports_internal_copy_unknown.saturating_add(1);
                }
            }
        }
        self.active = false;
        Ok(OwnedSurface {
            pool: Arc::clone(&self.pool),
            id: self.id,
            generation: self.generation,
            active: true,
            payload,
        })
    }
}

impl Drop for CaptureLease {
    fn drop(&mut self) {
        if self.active {
            release_slot(
                &self.pool,
                self.id,
                self.generation,
                SlotState::CaptureLeased,
            );
            self.active = false;
        }
    }
}

/// Encoder/decoder-owned surface. Dropping it releases its native allocation
/// before returning the fixed slot to the pool.
#[derive(Debug)]
pub struct OwnedSurface {
    pool: Arc<Mutex<PoolInner>>,
    id: SurfaceId,
    generation: u64,
    active: bool,
    payload: Option<Box<dyn SurfacePayload>>,
}

impl OwnedSurface {
    #[must_use]
    pub const fn id(&self) -> SurfaceId {
        self.id
    }

    pub fn descriptor(&self) -> Result<FrameDescriptor, SurfaceError> {
        let inner = lock(&self.pool)?;
        let slot = checked_slot(&inner, self.id, self.generation)?;
        if slot.state != SlotState::Owned {
            return Err(SurfaceError::InvalidState);
        }
        slot.descriptor.ok_or(SurfaceError::InvalidState)
    }

    pub fn import_path(&self) -> Result<ImportPath, SurfaceError> {
        Ok(self.copy_ledger()?.path)
    }

    pub fn copy_ledger(&self) -> Result<CopyLedger, SurfaceError> {
        let inner = lock(&self.pool)?;
        let slot = checked_slot(&inner, self.id, self.generation)?;
        if slot.state != SlotState::Owned {
            return Err(SurfaceError::InvalidState);
        }
        slot.copy_ledger.ok_or(SurfaceError::InvalidState)
    }

    #[must_use]
    pub fn payload<T: SurfacePayload>(&self) -> Option<&T> {
        self.payload
            .as_deref()
            .and_then(|payload| payload.as_any().downcast_ref())
    }
}

impl Drop for OwnedSurface {
    fn drop(&mut self) {
        drop(self.payload.take());
        if self.active {
            release_slot(&self.pool, self.id, self.generation, SlotState::Owned);
            self.active = false;
        }
    }
}

fn release_slot(
    pool: &Arc<Mutex<PoolInner>>,
    id: SurfaceId,
    generation: u64,
    expected_state: SlotState,
) {
    let mut inner = lock_unpoisoned(pool);
    let index = id.0 as usize;
    let valid = inner
        .slots
        .get(index)
        .is_some_and(|slot| slot.generation == generation && slot.state == expected_state);
    if !valid {
        inner.stats.invalid_transitions = inner.stats.invalid_transitions.saturating_add(1);
        return;
    }
    let slot = &mut inner.slots[index];
    slot.state = SlotState::Available;
    slot.descriptor = None;
    slot.destination = None;
    slot.copy_ledger = None;
    inner.in_use = inner.in_use.saturating_sub(1);
    inner.stats.releases = inner.stats.releases.saturating_add(1);
}

fn checked_slot(inner: &PoolInner, id: SurfaceId, generation: u64) -> Result<&Slot, SurfaceError> {
    let slot = inner
        .slots
        .get(id.0 as usize)
        .ok_or(SurfaceError::UnknownSurface)?;
    if slot.generation != generation {
        return Err(SurfaceError::StaleGeneration);
    }
    Ok(slot)
}

fn checked_slot_mut(
    inner: &mut PoolInner,
    id: SurfaceId,
    generation: u64,
) -> Result<&mut Slot, SurfaceError> {
    let slot = inner
        .slots
        .get_mut(id.0 as usize)
        .ok_or(SurfaceError::UnknownSurface)?;
    if slot.generation != generation {
        return Err(SurfaceError::StaleGeneration);
    }
    Ok(slot)
}

fn lock(inner: &Arc<Mutex<PoolInner>>) -> Result<MutexGuard<'_, PoolInner>, SurfaceError> {
    inner.lock().map_err(|_| SurfaceError::Poisoned)
}

fn lock_unpoisoned(inner: &Arc<Mutex<PoolInner>>) -> MutexGuard<'_, PoolInner> {
    inner
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceError {
    InvalidDescriptor,
    InvalidDestination,
    DestinationMismatch,
    PoolExhausted,
    UnknownSurface,
    StaleGeneration,
    InvalidState,
    Poisoned,
    CopyLedger(CopyLedgerError),
}

impl fmt::Display for SurfaceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SurfaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CopyLedger(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use latencydesk_media::{
        CopyEvidenceGrade, DeviceIdentity, LeaseCompletion, MemoryDomain, SourceLeaseIdentity,
        SurfaceLayout, SynchronizationProof, TransferEdge,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn copy_ledger(descriptor: FrameDescriptor, path: ImportPath) -> CopyLedger {
        let device = match path {
            ImportPath::CpuCopy | ImportPath::InternalCopyUnknown => DeviceIdentity::Unknown,
            ImportPath::DirectAlias | ImportPath::GpuConvert | ImportPath::GpuCopy => {
                DeviceIdentity::Opaque(1)
            }
        };
        CopyLedger {
            source_lease: SourceLeaseIdentity {
                provider_epoch: 1,
                capture_sequence: descriptor.capture_sequence,
            },
            source_device: device,
            destination_device: device,
            source_layout: SurfaceLayout {
                memory_domain: descriptor.memory_domain,
                format_fourcc: descriptor.format_fourcc,
                plane_count: 1,
                modifier: None,
            },
            destination_layout: SurfaceLayout {
                memory_domain: descriptor.memory_domain,
                format_fourcc: descriptor.format_fourcc,
                plane_count: 1,
                modifier: None,
            },
            transfer_edge: TransferEdge::CaptureToEncoder,
            path,
            synchronization: match path {
                ImportPath::CpuCopy => SynchronizationProof::CpuSynchronous,
                _ => SynchronizationProof::D3D11EventQuery,
            },
            completion: LeaseCompletion::Proven,
            fallback_reason: None,
            evidence: match path {
                ImportPath::DirectAlias => CopyEvidenceGrade::ProfilerVerifiedNoApplicationCopy,
                _ => CopyEvidenceGrade::CompletionProven,
            },
        }
    }

    #[derive(Debug)]
    struct DropSignal {
        drops: Arc<AtomicUsize>,
        pool: SurfacePool,
    }

    impl Drop for DropSignal {
        fn drop(&mut self) {
            assert_eq!(self.pool.in_use(), 1);
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl SurfacePayload for DropSignal {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn descriptor(sequence: u64) -> FrameDescriptor {
        FrameDescriptor {
            width: 1_920,
            height: 1_080,
            format_fourcc: u32::from_le_bytes(*b"BGRA"),
            memory_domain: MemoryDomain::D3D11,
            capture_sequence: sequence,
            capture_timestamp_ns: sequence * 1_000,
        }
    }

    #[test]
    fn dropped_capture_lease_returns_slot() {
        let pool = SurfacePool::new(1);
        {
            let _lease = pool.acquire_capture(descriptor(1)).expect("lease");
            assert_eq!(pool.in_use(), 1);
            assert_eq!(
                pool.acquire_capture(descriptor(2)).expect_err("full"),
                SurfaceError::PoolExhausted
            );
        }
        assert_eq!(pool.in_use(), 0);
        assert!(pool.acquire_capture(descriptor(3)).is_ok());
    }

    #[test]
    fn imported_surface_remains_owned_until_drop() {
        let pool = SurfacePool::new(1);
        let descriptor = descriptor(1);
        let lease = pool.acquire_capture(descriptor).expect("lease");
        let owned = lease
            .import(copy_ledger(descriptor, ImportPath::GpuCopy))
            .expect("import");
        assert_eq!(owned.import_path().expect("path"), ImportPath::GpuCopy);
        assert_eq!(
            owned.copy_ledger().expect("ledger").path,
            ImportPath::GpuCopy
        );
        assert_eq!(pool.in_use(), 1);
        drop(owned);
        assert_eq!(pool.in_use(), 0);
        assert_eq!(pool.stats().imports_gpu_copy, 1);
        assert_eq!(pool.stats().releases, 1);
    }

    #[test]
    fn ledger_must_describe_the_active_capture_lease() {
        let pool = SurfacePool::new(1);
        let descriptor = descriptor(1);
        let mut ledger = copy_ledger(descriptor, ImportPath::GpuCopy);
        ledger.source_lease.capture_sequence = 2;
        let error = pool
            .acquire_capture(descriptor)
            .expect("lease")
            .import(ledger)
            .expect_err("mismatched ledger");
        assert_eq!(
            error,
            SurfaceError::CopyLedger(CopyLedgerError::CaptureSequenceMismatch)
        );
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn destination_reservation_owns_the_exact_requested_layout() {
        let pool = SurfacePool::new(1);
        let source = descriptor(7);
        let destination = FrameDescriptor {
            format_fourcc: u32::from_le_bytes(*b"NV12"),
            ..source
        };
        let destination_layout = SurfaceLayout {
            memory_domain: MemoryDomain::D3D11,
            format_fourcc: destination.format_fourcc,
            plane_count: 2,
            modifier: None,
        };
        let reservation = DestinationSurfaceSpec::new(
            destination,
            DeviceIdentity::Opaque(19),
            destination_layout,
        )
        .expect("valid destination");
        let lease = pool
            .reserve_destination(reservation)
            .expect("destination reservation");
        let mut ledger = copy_ledger(source, ImportPath::GpuConvert);
        ledger.destination_device = reservation.device();
        ledger.destination_layout = reservation.layout();

        let owned = lease
            .import_from_capture(source, ledger)
            .expect("copy into reserved destination");

        assert_eq!(owned.descriptor().expect("descriptor"), destination);
        assert_eq!(owned.copy_ledger().expect("ledger"), ledger);
    }

    #[test]
    fn destination_reservation_rejects_unreserved_device_or_layout() {
        let pool = SurfacePool::new(1);
        let source = descriptor(8);
        let destination = FrameDescriptor {
            format_fourcc: u32::from_le_bytes(*b"NV12"),
            ..source
        };
        let reservation = DestinationSurfaceSpec::new(
            destination,
            DeviceIdentity::Opaque(19),
            SurfaceLayout {
                memory_domain: MemoryDomain::D3D11,
                format_fourcc: destination.format_fourcc,
                plane_count: 2,
                modifier: None,
            },
        )
        .expect("valid destination");
        let mut ledger = copy_ledger(source, ImportPath::GpuConvert);
        ledger.destination_device = DeviceIdentity::Opaque(20);
        ledger.destination_layout = reservation.layout();

        let error = pool
            .reserve_destination(reservation)
            .expect("destination reservation")
            .import_from_capture(source, ledger)
            .expect_err("unreserved destination device");

        assert_eq!(error, SurfaceError::DestinationMismatch);
        assert_eq!(pool.in_use(), 0);
    }

    #[test]
    fn owned_surface_releases_its_native_payload_with_the_pool_slot() {
        let pool = SurfacePool::new(1);
        let descriptor = descriptor(9);
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = pool
            .acquire_capture(descriptor)
            .expect("lease")
            .import_with_payload(
                copy_ledger(descriptor, ImportPath::GpuCopy),
                Box::new(DropSignal {
                    drops: Arc::clone(&drops),
                    pool: pool.clone(),
                }),
            )
            .expect("import");

        assert!(owned.payload::<DropSignal>().is_some());
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(owned);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(pool.in_use(), 0);
    }
    #[test]
    fn pool_never_grows_during_soak() {
        let pool = SurfacePool::new(3);
        for sequence in 0..100_000 {
            let descriptor = descriptor(sequence);
            let owned = pool
                .acquire_capture(descriptor)
                .expect("capture")
                .import(copy_ledger(descriptor, ImportPath::DirectAlias))
                .expect("import");
            drop(owned);
        }
        assert_eq!(pool.capacity(), 3);
        assert_eq!(pool.in_use(), 0);
        assert_eq!(pool.stats().high_watermark, 1);
    }
}
