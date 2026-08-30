use latencydesk_scheduler::{DeadlineScheduler, PriorityClass, PushOutcome, ScheduledItem};
use latencydesk_testkit::{run_lab, LabConfig};
use latencydesk_transport::NetworkProfile;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const CONCURRENT_SESSION_COUNT: usize = 8;
const PROFILES_PER_SESSION: usize = 4;
const MAX_CONCURRENT_SESSIONS: usize = 64;
const VIDEO_ITEMS_PER_SESSION: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConcurrentSessionConfig {
    session_id: u64,
    profile_index: usize,
    seed: u64,
}

#[derive(Debug, Clone, Copy)]
struct ConcurrentSessionResult {
    session_id: u64,
    profile_index: usize,
    report: latencydesk_testkit::LabReport,
    input_service_pops: usize,
}

#[derive(Debug)]
struct StressError(String);

impl fmt::Display for StressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for StressError {}

fn network_profiles() -> [NetworkProfile; PROFILES_PER_SESSION] {
    [
        NetworkProfile::default(),
        NetworkProfile {
            base_delay_ns: 10_000_000,
            jitter_ns: 2_000_000,
            duplicate_per_million: 100_000,
            reorder_per_million: 200_000,
            ..NetworkProfile::default()
        },
        NetworkProfile {
            base_delay_ns: 25_000_000,
            jitter_ns: 5_000_000,
            loss_per_million: 10_000,
            duplicate_per_million: 10_000,
            reorder_per_million: 50_000,
            ..NetworkProfile::default()
        },
        NetworkProfile {
            base_delay_ns: 50_000_000,
            jitter_ns: 10_000_000,
            loss_per_million: 50_000,
            corrupt_per_million: 5_000,
            bandwidth_bps: 20_000_000,
            ..NetworkProfile::default()
        },
    ]
}

fn concurrent_session_configs(
    session_count: usize,
) -> Result<Vec<ConcurrentSessionConfig>, StressError> {
    if session_count == 0 || session_count > MAX_CONCURRENT_SESSIONS {
        return Err(StressError(format!(
            "concurrent session count must be within 1..={MAX_CONCURRENT_SESSIONS}"
        )));
    }
    Ok((0..session_count)
        .map(|index| ConcurrentSessionConfig {
            session_id: index as u64 + 1,
            profile_index: index % PROFILES_PER_SESSION,
            seed: (index as u64 + 1) ^ ((index as u64) << 32),
        })
        .collect())
}

fn input_service_pop_bound(session_id: u64) -> Result<usize, StressError> {
    if session_id == 0 {
        return Err(StressError("session id must be nonzero".into()));
    }

    let now = Instant::now();
    let deadline = now + Duration::from_secs(1);
    let mut scheduler = DeadlineScheduler::new(
        VIDEO_ITEMS_PER_SESSION,
        VIDEO_ITEMS_PER_SESSION.saturating_mul(1_024),
    );
    for video_index in 0..VIDEO_ITEMS_PER_SESSION {
        let outcome = scheduler.push(
            ScheduledItem {
                id: (session_id << 32) | video_index as u64,
                class: PriorityClass::RealtimeVideo,
                deadline,
                payload_bytes: 1_024,
            },
            now,
        );
        if outcome != (PushOutcome::Inserted { evicted: 0 }) {
            return Err(StressError(format!(
                "session {session_id} could not establish saturated video pressure: {outcome:?}"
            )));
        }
    }

    let input_id = (session_id << 32) | u64::from(u32::MAX);
    let outcome = scheduler.push(
        ScheduledItem {
            id: input_id,
            class: PriorityClass::Input,
            deadline,
            payload_bytes: 64,
        },
        now,
    );
    if outcome != (PushOutcome::Inserted { evicted: 1 }) {
        return Err(StressError(format!(
            "session {session_id} did not admit input by evicting stale video work: {outcome:?}"
        )));
    }

    for pop_count in 1..=scheduler.len() {
        let item = scheduler
            .pop_next(now)
            .ok_or_else(|| StressError("scheduler emptied before input was serviced".into()))?;
        if item.id == input_id {
            return Ok(pop_count);
        }
    }
    Err(StressError(format!(
        "session {session_id} starved input behind saturated video"
    )))
}

fn run_concurrent_sessions(
    session_count: usize,
) -> Result<Vec<ConcurrentSessionResult>, StressError> {
    let configs = concurrent_session_configs(session_count)?;
    let profiles = network_profiles();
    let barrier = Arc::new(Barrier::new(configs.len()));
    let mut workers = Vec::with_capacity(configs.len());

    for config in configs {
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            let mut results = Vec::with_capacity(PROFILES_PER_SESSION);
            for profile_offset in 0..PROFILES_PER_SESSION {
                let profile_index = (config.profile_index + profile_offset) % PROFILES_PER_SESSION;
                let lab_config = LabConfig {
                    frames: 40,
                    width: 96,
                    height: 64,
                    network: profiles[profile_index],
                    seed: config.seed ^ ((profile_index as u64) << 48),
                    frame_deadline_ns: 750_000_000,
                    ..LabConfig::default()
                };
                let (report, _) = run_lab(lab_config).map_err(|error| {
                    StressError(format!(
                        "session {} profile {profile_index} failed: {error}",
                        config.session_id
                    ))
                })?;
                if profile_index < 2 && !report.lossless_passed() {
                    return Err(StressError(format!(
                        "session {} lossless profile {profile_index} failed: {report:?}",
                        config.session_id
                    )));
                }
                if report.completed_frames + report.incomplete_frames + report.exact_mismatches
                    != report.submitted_frames
                {
                    return Err(StressError(format!(
                        "session {} profile {profile_index} violated frame accounting",
                        config.session_id
                    )));
                }
                results.push(ConcurrentSessionResult {
                    session_id: config.session_id,
                    profile_index,
                    report,
                    input_service_pops: input_service_pop_bound(config.session_id)?,
                });
            }
            Ok::<_, StressError>(results)
        }));
    }

    let mut results = Vec::with_capacity(session_count.saturating_mul(PROFILES_PER_SESSION));
    for worker in workers {
        let session_results = worker
            .join()
            .map_err(|_| StressError("concurrent session worker panicked".into()))??;
        results.extend(session_results);
    }
    Ok(results)
}

fn aggregate_json(session_count: usize, results: &[ConcurrentSessionResult]) -> String {
    let submitted_frames = results
        .iter()
        .map(|result| result.report.submitted_frames)
        .sum::<u64>();
    let completed_frames = results
        .iter()
        .map(|result| result.report.completed_frames)
        .sum::<u64>();
    let incomplete_frames = results
        .iter()
        .map(|result| result.report.incomplete_frames)
        .sum::<u64>();
    let exact_mismatches = results
        .iter()
        .map(|result| result.report.exact_mismatches)
        .sum::<u64>();
    let max_input_service_pops = results
        .iter()
        .map(|result| result.input_service_pops)
        .max()
        .unwrap_or(0);
    let unique_session_profile_runs = {
        let mut pairs = results
            .iter()
            .map(|result| (result.session_id, result.profile_index))
            .collect::<Vec<_>>();
        pairs.sort_unstable();
        pairs.dedup();
        pairs.len()
    };
    format!(
        concat!(
            "{{\"schema\":1,\"concurrent_sessions\":{},\"profile_runs\":{},",
            "\"unique_session_profile_runs\":{},\"submitted_frames\":{},",
            "\"completed_frames\":{},\"incomplete_frames\":{},",
            "\"exact_mismatches\":{},\"max_input_service_pops\":{}}}"
        ),
        session_count,
        results.len(),
        unique_session_profile_runs,
        submitted_frames,
        completed_frames,
        incomplete_frames,
        exact_mismatches,
        max_input_service_pops,
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    let results = run_concurrent_sessions(CONCURRENT_SESSION_COUNT)?;
    println!("{}", aggregate_json(CONCURRENT_SESSION_COUNT, &results));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_matrix_assigns_eight_unique_isolated_sessions() {
        let configs = concurrent_session_configs(8).expect("valid session matrix");
        assert_eq!(configs.len(), 8);

        let mut session_ids = configs
            .iter()
            .map(|config| config.session_id)
            .collect::<Vec<_>>();
        session_ids.sort_unstable();
        session_ids.dedup();
        assert_eq!(session_ids.len(), 8);
        assert!(configs.iter().any(|config| config.profile_index == 0));
        assert!(configs.iter().any(|config| config.profile_index == 3));
    }

    #[test]
    fn input_is_the_first_item_serviced_under_video_saturation() {
        for session_id in 1..=8 {
            assert_eq!(
                input_service_pop_bound(session_id).expect("priority gate"),
                1
            );
        }
    }
}
