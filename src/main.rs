mod parser;

use std::fs::File;
use std::io::prelude::*;

use clap::Parser;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Input consensus to sample from.
    #[clap(long)]
    consensus: String,
    /// Input consensus to sample from.
    #[clap(long)]
    descriptors: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(cli.consensus).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_consensus(&raw)?
    };

    let descriptors = {
        let mut raw = String::new();
        let mut file = File::open(cli.descriptors).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_descriptors(&raw)?
    };

    // println!("{:?}", descriptors);

    let mut total = 0u32;
    let mut found = 0u32;
    for relay in consensus.relays {
        total += 1;
        if let Some(_) = descriptors.get(&relay.digest) {
            found += 1;
        }
    }

    println!("Found {found}/{total} consensus relays.");

    Ok(())
}
