use latencydesk_testkit::{run_lab, LabConfig};
use latencydesk_transport::NetworkProfile;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let profiles = [
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
    ];

    for seed in 1..=8_u64 {
        for (profile_index, network) in profiles.into_iter().enumerate() {
            let config = LabConfig {
                frames: 40,
                width: 96,
                height: 64,
                network,
                seed: seed ^ ((profile_index as u64) << 32),
                frame_deadline_ns: 750_000_000,
                ..LabConfig::default()
            };
            let (report, _) = run_lab(config)?;
            if profile_index < 2 && !report.lossless_passed() {
                return Err(format!(
                    "lossless stress gate failed: seed={seed}, profile={profile_index}, report={report:?}"
                )
                .into());
            }
            if report.completed_frames + report.incomplete_frames + report.exact_mismatches
                != report.submitted_frames
            {
                return Err("frame accounting invariant failed".into());
            }
        }
    }
    println!("stress profiles passed");
    Ok(())
}
