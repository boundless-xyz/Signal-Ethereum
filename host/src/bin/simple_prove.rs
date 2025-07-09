use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use risc0_zkvm::{ExecutorEnv, ProverOpts, default_prover};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    input: PathBuf,
    #[clap(long)]
    program: PathBuf,
    /// Log level (error, warn, info, debug, trace)
    #[clap(long, env = "LOG_LEVEL", global = true, default_value = "info")]
    log_level: LevelFilter,
}

fn main() -> anyhow::Result<()> {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(err) => {
            if err.kind() == clap::error::ErrorKind::DisplayHelp {
                // If it's a help request, print the help and exit successfully
                err.print()?;
                return Ok(());
            }
            if err.kind() == clap::error::ErrorKind::DisplayVersion {
                // If it's a version request, print the version and exit successfully
                err.print()?;
                return Ok(());
            }
            return Err(err.into());
        }
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(args.log_level.into())
                .from_env_lossy(),
        )
        .init();

    let program = fs::read(args.program).context("failed to read program")?;
    let env = ExecutorEnv::builder()
        .write_slice(&fs::read(args.input).context("failed to read input file")?)
        .build()
        .context("failed to buidl ExecutorEnv")?;

    let prover = default_prover();
    tracing::info!("Proving with prover: {}", prover.get_name());

    let proof_info = prover
        .prove_with_opts(env, &program, &ProverOpts::succinct())
        .context("failed to produce proof")?;

    tracing::info!("Completed proof with states: {:?}", proof_info.stats);

    Ok(())
}
