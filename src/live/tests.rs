use std::sync::{Arc, Mutex};

use super::*;
use crate::cancellation::is_cancellation_error;

#[derive(Default)]
struct FixtureState {
    byte: u8,
    reads: Vec<(u64, usize)>,
    partial_at: Option<u64>,
    invalid: bool,
    invalidate_after_read: bool,
    cancel_after_read: Option<CancellationToken>,
    closed: bool,
}

struct Fixture(Arc<Mutex<FixtureState>>);

impl Drop for Fixture {
    fn drop(&mut self) {
        self.0.lock().unwrap().closed = true;
    }
}

impl ProcessReader for Fixture {
    fn validate(&self, _: &VmwareRegion) -> Result<()> {
        ensure!(
            !self.0.lock().unwrap().invalid,
            "fixture process exited or mapping changed"
        );
        Ok(())
    }

    fn read(&self, host_address: u64, output: &mut [u8]) -> HostRead {
        let mut state = self.0.lock().unwrap();
        state.reads.push((host_address, output.len()));
        let partial = state.partial_at == Some(host_address);
        let copied = if partial {
            output.len() / 2
        } else {
            output.len()
        };
        output[..copied].fill(state.byte);
        if state.invalidate_after_read {
            state.invalid = true;
        }
        if let Some(token) = &state.cancel_after_read {
            token.request_cancel();
        }
        HostRead {
            copied,
            error: partial.then(|| "fixture partial read".to_owned()),
        }
    }
}

const HOST_BASE: u64 = 0x20_0000_0000;

#[test]
fn mapped_bridge_reads_fresh_bytes_and_enforces_bounds_and_stop() {
    let (reader, state) = reader(PAGE_SIZE);
    let bridge = LiveImageReader::new(reader, CancellationToken::new());
    let mut bytes = [0; 4];
    bridge.read_source(8, &mut bytes).unwrap();
    state.lock().unwrap().byte = 55;
    bridge.read_source(8, &mut bytes).unwrap();
    assert_eq!(bytes, [55; 4]);
    assert!(bridge.read_source(PAGE_SIZE - 3, &mut bytes).is_err());
    bridge.stop().unwrap();
    assert!(bridge.read_source(8, &mut bytes).is_err());
}

#[test]
fn small_alias_mappings_do_not_replace_the_unique_ram_candidate() {
    let mut candidate = target(PAGE_SIZE);
    candidate.regions.insert(
        0,
        VmwareRegion {
            host_address: HOST_BASE + 0x10000,
            length: PAGE_SIZE,
            mapped_file: "alias.vmem".into(),
            supported: false,
        },
    );
    let state = Arc::new(Mutex::new(FixtureState::default()));
    let reader = VmwareLiveReader::from_process(
        candidate,
        VmwareLayout::Workstation3GbHole,
        Box::new(Fixture(state)),
    )
    .unwrap();
    assert_eq!(reader.source().region.host_address, HOST_BASE);
    assert_eq!(reader.source().target.regions.len(), 2);
}

fn target(length: u64) -> VmwareTarget {
    VmwareTarget {
        process: VmwareProcessIdentity {
            pid: 42,
            created_filetime: 123456,
            executable: PathBuf::from("vmware-vmx.exe"),
        },
        regions: vec![VmwareRegion {
            host_address: HOST_BASE,
            length,
            mapped_file: "fixture.vmem".to_owned(),
            supported: true,
        }],
    }
}

fn reader(length: u64) -> (VmwareLiveReader, Arc<Mutex<FixtureState>>) {
    let state = Arc::new(Mutex::new(FixtureState::default()));
    let reader = VmwareLiveReader::from_process(
        target(length),
        VmwareLayout::Workstation3GbHole,
        Box::new(Fixture(state.clone())),
    )
    .unwrap();
    (reader, state)
}

fn request(address: u64, length: usize) -> LiveReadRequest {
    LiveReadRequest {
        physical_address: address,
        length,
    }
}

#[test]
fn live_reads_observe_changes_without_reusing_bytes() {
    let (mut reader, state) = reader(2 * PAGE_SIZE);
    let token = CancellationToken::new();
    let range = [request(4, 10)];
    let first = reader.read_batch(&range, &token).unwrap();
    assert_eq!(first.ranges[0].comparison, LiveComparison::NoBaseline);
    state.lock().unwrap().byte = 0x41;
    let second = reader.read_batch(&range, &token).unwrap();
    assert_eq!(second.ranges[0].fragments[0].bytes, vec![0x41; 10]);
    assert_eq!(second.ranges[0].comparison, LiveComparison::DifferentBytes);
    assert_eq!(second.ranges[0].previous_sequence, Some(1));
    let third = reader.read_batch(&range, &token).unwrap();
    assert_eq!(third.ranges[0].comparison, LiveComparison::SameBytes);
    assert_eq!(third.ranges[0].previous_sequence, Some(2));
    assert_eq!(state.lock().unwrap().reads.len(), 3);
    assert!(!third.atomic_snapshot);
    assert!(!third.source.layout_verified);
    assert_eq!(first.source.session_id, third.source.session_id);
    assert!(third.finished_unix_ms >= third.started_unix_ms);
}

#[test]
fn hole_and_end_of_ram_are_missing_not_zero_filled() {
    let (mut reader, state) = reader(LOW_MEMORY_END + PAGE_SIZE);
    let batch = reader
        .read_batch(
            &[
                request(LOW_MEMORY_END - 2, 4),
                request(HIGH_MEMORY_START, 4),
                request(HIGH_MEMORY_START + PAGE_SIZE - 2, 4),
            ],
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(!batch.complete);
    assert_eq!(batch.ranges[0].fragments[0].bytes.len(), 2);
    assert!(batch.ranges[0].fragments[1].bytes.is_empty());
    assert!(batch.ranges[1].complete);
    assert!(batch.ranges[2].fragments[1].bytes.is_empty());
    assert_eq!(
        state.lock().unwrap().reads.as_slice(),
        &[
            (HOST_BASE + LOW_MEMORY_END - 2, 2),
            (HOST_BASE + LOW_MEMORY_END, 4),
            (HOST_BASE + LOW_MEMORY_END + PAGE_SIZE - 2, 2),
        ]
    );
    assert_eq!(batch.ranges[0].comparison, LiveComparison::Incomplete);
    assert!(batch.ranges[0].sha256.is_none());
}

#[test]
fn partial_page_preserves_coverage_and_does_not_hide_later_pages() {
    let (mut reader, state) = reader(2 * PAGE_SIZE);
    state.lock().unwrap().partial_at = Some(HOST_BASE);
    let requests = [request(0, PAGE_SIZE as usize + 2)];
    let batch = reader
        .read_batch(&requests, &CancellationToken::new())
        .unwrap();
    assert_eq!(
        batch.ranges[0].fragments[0].bytes.len(),
        PAGE_SIZE as usize / 2
    );
    assert!(batch.ranges[0].fragments[0].error.is_some());
    assert_eq!(batch.ranges[0].fragments[1].bytes.len(), 2);
    assert!(!batch.complete);
    state.lock().unwrap().partial_at = None;
    let recovered = reader
        .read_batch(&requests, &CancellationToken::new())
        .unwrap();
    assert_eq!(recovered.ranges[0].comparison, LiveComparison::NoBaseline);
    assert!(recovered.ranges[0].previous_sequence.is_none());
}

#[test]
fn cancellation_mid_batch_discards_the_batch_and_breaks_comparison() {
    let (mut reader, state) = reader(2 * PAGE_SIZE);
    let requests = [request(0, PAGE_SIZE as usize + 1)];
    let token = CancellationToken::new();
    reader.read_batch(&requests, &token).unwrap();
    state.lock().unwrap().cancel_after_read = Some(token.clone());
    let error = reader.read_batch(&requests, &token).unwrap_err();
    assert!(is_cancellation_error(&error));
    assert_eq!(state.lock().unwrap().reads.len(), 3);
    state.lock().unwrap().cancel_after_read = None;
    let recovered = reader
        .read_batch(&requests, &CancellationToken::new())
        .unwrap();
    assert_eq!(recovered.sequence, 3);
    assert_eq!(recovered.ranges[0].comparison, LiveComparison::NoBaseline);
}

#[test]
fn change_during_last_page_invalidates_result_and_closes_handle() {
    let (mut reader, state) = reader(PAGE_SIZE);
    state.lock().unwrap().invalidate_after_read = true;
    let error = reader
        .read_batch(&[request(0, 5)], &CancellationToken::new())
        .unwrap_err();
    assert!(error.to_string().contains("STARMEM_LIVE_SOURCE_CHANGED"));
    assert!(!reader.is_open());
    assert!(state.lock().unwrap().closed);
}

#[test]
fn stopped_or_exited_sources_are_never_read() {
    let (mut reader, state) = reader(PAGE_SIZE);
    state.lock().unwrap().invalid = true;
    assert!(
        reader
            .read_batch(&[request(0, 1)], &CancellationToken::new())
            .is_err()
    );
    reader.stop();
    reader.stop();
    assert!(state.lock().unwrap().closed);
    assert!(state.lock().unwrap().reads.is_empty());
    assert!(
        reader
            .read_batch(&[request(0, 1)], &CancellationToken::new())
            .unwrap_err()
            .to_string()
            .contains("STARMEM_LIVE_CLOSED")
    );
}

#[test]
fn invalid_requests_are_rejected_before_io() {
    let (mut reader, state) = reader(PAGE_SIZE);
    for requests in [
        vec![],
        vec![request(0, 0)],
        vec![request(u64::MAX, 1)],
        vec![request(0, MAX_LIVE_BATCH_BYTES + 1)],
        vec![request(0, 1); MAX_LIVE_REQUESTS + 1],
    ] {
        assert!(
            reader
                .read_batch(&requests, &CancellationToken::new())
                .is_err()
        );
    }
    let token = CancellationToken::new();
    token.request_cancel();
    assert!(is_cancellation_error(
        &reader.read_batch(&[request(0, 1)], &token).unwrap_err()
    ));
    assert!(state.lock().unwrap().reads.is_empty());
}

#[test]
fn new_attachments_and_different_ranges_do_not_share_baselines() {
    let (mut first, _) = reader(PAGE_SIZE);
    let (mut second, _) = reader(PAGE_SIZE);
    assert_ne!(first.source().session_id, second.source().session_id);
    let token = CancellationToken::new();
    first.read_batch(&[request(0, 4)], &token).unwrap();
    assert_eq!(
        first.read_batch(&[request(0, 5)], &token).unwrap().ranges[0].comparison,
        LiveComparison::NoBaseline
    );
    assert_eq!(
        second.read_batch(&[request(0, 4)], &token).unwrap().ranges[0].comparison,
        LiveComparison::NoBaseline
    );
    assert_eq!(first.previous.len(), 1);
}

#[test]
fn ambiguous_unsupported_and_overflowing_maps_are_rejected() {
    let state = Arc::new(Mutex::new(FixtureState::default()));
    let mut ambiguous = target(PAGE_SIZE);
    ambiguous.regions.push(ambiguous.regions[0].clone());
    assert!(
        VmwareLiveReader::from_process(
            ambiguous,
            VmwareLayout::Workstation3GbHole,
            Box::new(Fixture(state.clone()))
        )
        .is_err()
    );
    let mut unsupported = target(PAGE_SIZE);
    unsupported.regions[0].supported = false;
    assert!(
        VmwareLiveReader::from_process(
            unsupported,
            VmwareLayout::Workstation3GbHole,
            Box::new(Fixture(state))
        )
        .is_err()
    );
    let mut bad = target(PAGE_SIZE).regions.remove(0);
    bad.host_address = u64::MAX - PAGE_SIZE + 1;
    assert!(physical_ranges(&bad, VmwareLayout::Workstation3GbHole).is_err());
    bad.host_address = 1;
    assert!(physical_ranges(&bad, VmwareLayout::Workstation3GbHole).is_err());
}
