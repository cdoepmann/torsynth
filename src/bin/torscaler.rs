use highlevel::{
    cutoff_lower_and_redistribute, scale_flag_groups_vertically, scale_horizontally,
    scale_vertically_by_bandwidth_rank,
};
use torscaler::highlevel;
// mod parser;

mod history;

use std::fs::File;
use std::io::prelude::*;

use highlevel::asn::AsnDb;

use clap::{Args, Parser, Subcommand};
use tordoc;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Seed for the random number generators. If 0 or omitted, generate and print
    /// a random seed.
    #[clap(long, default_value_t = 0)]
    seed: u64,
    /// Command to execute
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Scale(ScaleArgs),
    History(history::HistoryArgs),
}

#[derive(Args)]
struct ScaleArgs {
    /// Input consensus to sample from.
    #[clap(long)]
    consensus: String,
    /// Descriptor database for relay descriptors. If not given, try to load
    /// descriptors from folders relative to the consensus file.
    #[clap(long)]
    descriptors: Option<String>,
    /// AS IP ranges database CSV file
    #[clap(long)]
    asn_db: String,
    /// Verify that the bandwidth weights are correct
    #[clap(long)]
    verify_weights: bool,
    /// Directory to save the generated consensus to.
    #[clap(long, short)]
    output_dir: Option<String>,
    /// Scale the consensus horizontally by this factor
    #[clap(long, requires = "prob-family-new")]
    horz: Option<f32>,
    /// when scaling the consensus horizontally, apply this factor to exits
    #[clap(long, requires = "horz")]
    horz_exit_factor: Option<f32>,
    /// when scaling the consensus horizontally, apply this factor to guards
    #[clap(long, requires = "horz")]
    horz_guard_factor: Option<f32>,
    /// when scaling the consensus horizontally, favor growing families or
    /// creating new ones [0...1] (0 = only existing, 1 = only new)
    #[clap(long, requires = "horz")]
    prob_family_new: Option<f32>,
    /// Scale each relay's bandwidth in the network by this factor. This can
    /// also be a comma-separated list of float values. In this case, this
    /// defines different scale factors for relays of different bandwidth rank.
    /// Each of the N value then denotes the scale for the respective N-quantile.
    #[clap(long)]
    scale_vert_by_bw_quantiles: Option<String>,
    /// When scaling vertically, remove the the lower share X of the relays and
    /// give their bandwidth to the remaining, faster relays.
    /// If this option is used, the given quantiles refer to the relays that
    /// remain AFTER removing the specified share of slow relays.
    #[clap(long, requires = "scale-vert-by-bw-quantiles")]
    scale_vert_cutoff_lower: Option<f32>,
    /// Scale the bandwidth of each middle relay by this factor
    #[clap(long, conflicts_with = "scale-vert-by-bw-quantiles")]
    vert_middle_scale: Option<f32>,
    /// Scale the bandwidth of each exit relay by this factor
    #[clap(long, conflicts_with = "scale-vert-by-bw-quantiles")]
    vert_exit_scale: Option<f32>,
    /// Scale the bandwidth of each guard relay by this factor
    #[clap(long, conflicts_with = "scale-vert-by-bw-quantiles")]
    vert_guard_scale: Option<f32>,
    /// Remove relays that have an observed bandwidth of zero. This is done
    /// plainly by ignoring the respective descriptors if they are observed.
    #[clap(long)]
    remove_idle_relays: bool,
}

fn command_scale(cli: Cli) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let cli_scale = if let Command::Scale(x) = cli.command {
        x
    } else {
        panic!("wrong command");
    };

    let asn_db = AsnDb::new(&cli_scale.asn_db)?;

    let consensus: highlevel::UnpackedConsensus = {
        let mut raw = String::new();
        let mut file = File::open(&cli_scale.consensus).unwrap();
        file.read_to_string(&mut raw).unwrap();
        let raw_consensus = tordoc::Consensus::from_str(&raw)?;
        raw_consensus.try_into()?
    };

    let descriptors = match cli_scale.descriptors {
        Some(ref desc_path) => {
            // Descriptors are given as a file
            let mut raw = String::new();
            let mut file = File::open(desc_path).unwrap();
            file.read_to_string(&mut raw).unwrap();
            tordoc::Descriptor::many_from_str(&raw)?
        }
        None => {
            // Load descriptors from files relative to the consensus file
            highlevel::lookup_descriptors(&consensus, cli_scale.consensus)?
        }
    };

    // println!("{:?}", descriptors);
    let consensus = highlevel::Consensus::combine_documents(consensus, descriptors, &asn_db);
    // println!("{:?}", consensus);

    let mut consensus = consensus?;

    if cli_scale.remove_idle_relays {
        let mut removed = 0;

        consensus.remove_relays_by(|r| {
            let remove = r.bw_observed_was_zero;
            if remove {
                removed += 1;
            }
            remove
        });
        println!("Removed {removed} relays that have an observed bandwidth of zero...")
    }

    if cli_scale.verify_weights {
        println!("verifying bw weights...");
        match consensus.verify_weights() {
            Ok(_) => {
                println!("bw weights match.");
            }
            Err(s) => {
                println!("bw weights do not match:");
                println!("{}", s);
            }
        }
    }

    if let Some(scale) = cli_scale.horz {
        scale_horizontally(
            &mut consensus,
            scale,
            cli_scale.horz_exit_factor,
            cli_scale.horz_guard_factor,
            &asn_db,
            cli_scale
                .prob_family_new
                .expect("--prob-family-new needs to be specified"),
        );
        consensus.print_stats();
    }
    if let Some(raw) = cli_scale.scale_vert_by_bw_quantiles {
        if let Some(cutoff) = cli_scale.scale_vert_cutoff_lower {
            // consensus.print_stats();
            cutoff_lower_and_redistribute(&mut consensus, cutoff);
            // consensus.print_stats();
        }

        let scales: Vec<f32> = raw.split(',').map(|x| x.parse().unwrap()).collect();
        scale_vertically_by_bandwidth_rank(&mut consensus, scales);
        consensus.print_stats();
    } else if cli_scale.vert_middle_scale.is_some()
        || cli_scale.vert_exit_scale.is_some()
        || cli_scale.vert_guard_scale.is_some()
    {
        scale_flag_groups_vertically(
            &mut consensus,
            cli_scale.vert_middle_scale.unwrap_or(1.0),
            cli_scale.vert_exit_scale.unwrap_or(1.0),
            cli_scale.vert_guard_scale.unwrap_or(1.0),
        );
        consensus.print_stats();
    }

    if let Some(output_dir) = cli_scale.output_dir {
        highlevel::output::save_to_dir(&consensus, &output_dir)?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    let cli = Cli::parse();

    seeded_rand::set_seed(if cli.seed == 0 {
        let new_seed = seeded_rand::generate_random_seed();
        println!(
            "No seed was given. Call with \"--seed {}\" to reproduce this run.",
            new_seed
        );
        new_seed
    } else {
        cli.seed
    });

    match cli.command {
        Command::Scale(_) => command_scale(cli),
        Command::History(_) => history::command_history(cli),
    }
}
