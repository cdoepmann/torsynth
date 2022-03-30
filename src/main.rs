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
}

fn main() {
    let cli = Cli::parse();

    let mut consensus_raw = String::new();
    let mut file = File::open(cli.consensus).unwrap();
    file.read_to_string(&mut consensus_raw).unwrap();

    // run our parser tests
    println!("{:?}", parser::parse_consensus(&consensus_raw));
}