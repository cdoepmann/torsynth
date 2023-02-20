//! Tool to validate the model behavior of torscaler.
//!
//! Given two consensuses A and B, scale A to a new consensus A',
//! and compare A' to B.

use std::fs::File;
use std::io::prelude::*;

use torscaler::highlevel::{self, asn::AsnDb, Consensus};

use anyhow;
use clap::{Args, Parser, Subcommand};
use seeded_rand;
use tordoc;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Seed for the random number generators. If 0 or omitted, generate and print
    /// a random seed.
    #[clap(long, default_value_t = 0)]
    seed: u64,
    /// First (earlier) consensus (file path).
    #[clap(long)]
    first_consensus: String,
    /// Second (later) consensus (file path).
    #[clap(long)]
    second_consensus: String,
    /// AS IP ranges database CSV file
    #[clap(long)]
    asn_db: String,
}

fn main() -> anyhow::Result<()> {
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

    // load AS database
    let asn_db = AsnDb::new(&cli.asn_db)?;

    let mut first_consensus = load_consensus(&cli.first_consensus, &asn_db)?;
    let second_consensus = load_consensus(&cli.second_consensus, &asn_db)?;

    let growth_h = second_consensus.relays.len() as f64 / first_consensus.relays.len() as f64;
    let growth_v = second_consensus
        .relays
        .values()
        .map(|r| r.bandwidth_weight)
        .sum::<u64>() as f64
        / first_consensus
            .relays
            .values()
            .map(|r| r.bandwidth_weight)
            .sum::<u64>() as f64;

    dbg!(growth_h);
    dbg!(growth_v);

    assert!(growth_h >= 1.0);
    assert!(growth_v >= 1.0);

    // Scale the first consensus accordingly
    println!(
        "Scaling the consensus horizontally by factor {}...",
        growth_h
    );
    highlevel::scale_horizontally(
        &mut first_consensus,
        growth_h as f32,
        None,
        None,
        &asn_db,
        0.5, // TODO P_new_family
    );

    println!("Scaling the consensus vertically by factor {}...", growth_v);
    highlevel::scale_vertically_by_bandwidth_rank(&mut first_consensus, vec![growth_v as f32]);

    // first_consensus is now scaled and ready for comparison with second_consensus

    assert_eq!(first_consensus.relays.len(), second_consensus.relays.len());

    Ok(())
}

// fn determine_p_family(first: &Consensus, second: &Consensus) -> f64 {
//     // number of relays
//     let relays_old = first.relays.len();
//     let relays_new = second.relays.len();
//     // number of families
//     let families_old = first.families.len();
//     let families_new = second.families.len();

//     (families_new - families_old) as f64 / (relays_old - relays_new) as f64
// }

fn load_consensus(path: &str, asn_db: &AsnDb) -> anyhow::Result<Consensus> {
    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(path)?;
        file.read_to_string(&mut raw).unwrap();
        tordoc::Consensus::from_str(&raw)?
    };

    // Load descriptors from files relative to the consensus file
    let descriptors =
        highlevel::lookup_descriptors(&consensus, path).map_err(|e| anyhow::anyhow!(e))?;

    // println!("{:?}", descriptors);
    let consensus = highlevel::Consensus::combine_documents(consensus, descriptors, &asn_db);
    // println!("{:?}", consensus);

    Ok(consensus?)
}
