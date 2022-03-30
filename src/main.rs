mod highlevel;
use highlevel::{
    scale_flag_groups_vertically, scale_horizontally, scale_vertically_by_bandwidth_rank,
};
mod parser;
mod seeded_rand;

use std::fs::File;
use std::io::prelude::*;

use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Seed for the random number generators
    #[clap(long, default_value_t = 1)]
    seed: u64,
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
    /// Scale the bandwidth of each middle relay by this factor
    #[clap(long, conflicts_with = "scale-vert-by-bw-quantiles")]
    vert_middle_scale: Option<f32>,
    /// Scale the bandwidth of each exit relay by this factor
    #[clap(long, conflicts_with = "scale-vert-by-bw-quantiles")]
    vert_exit_scale: Option<f32>,
    /// Scale the bandwidth of each guard relay by this factor
    #[clap(long, conflicts_with = "scale-vert-by-bw-quantiles")]
    vert_guard_scale: Option<f32>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    seeded_rand::set_seed(cli.seed);

    let asn_db = parser::asn::AsnDb::new(&cli.asn_db)?;

    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(&cli.consensus).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_consensus(&raw, &asn_db)?
    };

    let descriptors = match cli.descriptors {
        Some(ref desc_path) => {
            // Descriptors are given as a file
            let mut raw = String::new();
            let mut file = File::open(desc_path).unwrap();
            file.read_to_string(&mut raw).unwrap();
            parser::parse_descriptors(&raw)?
        }
        None => {
            // Load descriptors from files relative to the consensus file
            highlevel::lookup_descriptors(&consensus, cli.consensus)?
        }
    };

    // println!("{:?}", descriptors);
    let consensus = highlevel::Consensus::combine_documents(consensus, descriptors);
    // println!("{:?}", consensus);

    let mut consensus = consensus?;

    if cli.verify_weights {
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

    if let Some(scale) = cli.horz {
        scale_horizontally(
            &mut consensus,
            scale,
            cli.horz_exit_factor,
            cli.horz_guard_factor,
            &asn_db,
            cli.prob_family_new
                .expect("--prob-family-new needs to be specified"),
        );
        consensus.print_stats();
    }
    if let Some(raw) = cli.scale_vert_by_bw_quantiles {
        let scales: Vec<f32> = raw.split(',').map(|x| x.parse().unwrap()).collect();
        scale_vertically_by_bandwidth_rank(&mut consensus, scales);
        consensus.print_stats();
    } else if cli.vert_middle_scale.is_some()
        || cli.vert_exit_scale.is_some()
        || cli.vert_guard_scale.is_some()
    {
        scale_flag_groups_vertically(
            &mut consensus,
            cli.vert_middle_scale.unwrap_or(1.0),
            cli.vert_exit_scale.unwrap_or(1.0),
            cli.vert_guard_scale.unwrap_or(1.0),
        );
        consensus.print_stats();
    }

    Ok(())
}
