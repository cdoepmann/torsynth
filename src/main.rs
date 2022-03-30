mod highlevel;
use highlevel::scale_horizontally;
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
    #[clap(long)]
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

    Ok(())
}
