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
    /// Descriptor database for relay descriptors.
    #[clap(long)]
    descriptors: String,
    /// AS IP ranges database CSV file
    #[clap(long)]
    asn_db: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let asn_db = parser::asn::AsnDb::new(&cli.asn_db)?;

    let consensus = {
        let mut raw = String::new();
        let mut file = File::open(cli.consensus).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_consensus(&raw, asn_db)?
    };

    let descriptors = {
        let mut raw = String::new();
        let mut file = File::open(cli.descriptors).unwrap();
        file.read_to_string(&mut raw).unwrap();
        parser::parse_descriptors(&raw)?
    };

    // println!("{:?}", descriptors);
    let consensus = parser::highlevel::Consensus::combine_documents(consensus, descriptors);
    println!("{:?}", consensus);

    Ok(())
}
