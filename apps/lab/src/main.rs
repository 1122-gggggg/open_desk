use latencydesk_testkit::{report_json, run_lab, summary_json, LabConfig};
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
struct Cli {
    config: LabConfig,
    json_output: PathBuf,
    csv_output: PathBuf,
    report_output: PathBuf,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            config: LabConfig::default(),
            json_output: PathBuf::from("artifacts/lab-trace.json"),
            csv_output: PathBuf::from("artifacts/lab-trace.csv"),
            report_output: PathBuf::from("artifacts/lab-report.json"),
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_args()?;
    let (report, traces) = run_lab(cli.config)?;
    for output in [&cli.json_output, &cli.csv_output, &cli.report_output] {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&cli.json_output, traces.to_json())?;
    fs::write(&cli.csv_output, traces.to_csv())?;
    let commit = git_commit();
    fs::write(
        &cli.report_output,
        report_json(cli.config, report, traces.summary(), commit.as_deref()),
    )?;
    println!("{}", summary_json(report, traces.summary()));
    if cli.config.network.loss_per_million == 0
        && cli.config.network.corrupt_per_million == 0
        && !report.lossless_passed()
    {
        return Err("lossless laboratory gate failed".into());
    }
    Ok(())
}

fn parse_args() -> Result<Cli, Box<dyn Error>> {
    let mut cli = Cli::default();
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        let value = match argument.as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => args
                .next()
                .ok_or_else(|| format!("missing value for {argument}"))?,
        };
        match argument.as_str() {
            "--frames" => cli.config.frames = value.parse()?,
            "--width" => cli.config.width = value.parse()?,
            "--height" => cli.config.height = value.parse()?,
            "--loss-ppm" => cli.config.network.loss_per_million = value.parse()?,
            "--duplicate-ppm" => cli.config.network.duplicate_per_million = value.parse()?,
            "--reorder-ppm" => cli.config.network.reorder_per_million = value.parse()?,
            "--corrupt-ppm" => cli.config.network.corrupt_per_million = value.parse()?,
            "--bandwidth-bps" => cli.config.network.bandwidth_bps = value.parse()?,
            "--json" => cli.json_output = PathBuf::from(value),
            "--csv" => cli.csv_output = PathBuf::from(value),
            "--report" => cli.report_output = PathBuf::from(value),
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    cli.config.network.validate()?;
    Ok(cli)
}

fn print_help() {
    println!(
        "latencydesk-lab [--frames N] [--width W] [--height H] \\\n         [--loss-ppm N] [--duplicate-ppm N] [--reorder-ppm N] \\\n         [--corrupt-ppm N] [--bandwidth-bps N] [--json PATH] [--csv PATH] [--report PATH]"
    );
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    (!commit.is_empty()).then(|| commit.to_owned())
}
