use super::parser;
use super::{Cli, Command};
use parser::consensus::ConsensusDocument;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{offset::TimeZone, DateTime, Utc};
use clap::Args;
use csv;
use glob::glob;
use serde::Serialize;

#[derive(Args)]
pub(crate) struct HistoryArgs {
    /// Folder structure containing historical consensuses
    consensus_dir: String,
    /// Output CSV file to store the per-consensus aggregate data
    #[clap(long)]
    csv_out: String,
}

pub(crate) fn command_history(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let cli_history = if let Command::History(x) = cli.command {
        x
    } else {
        panic!("wrong command");
    };

    // Find the available consensuses
    let glob_expr = Path::new(&cli_history.consensus_dir)
        .join("consensuses-*-*/*/*-consensus")
        .to_str()
        .unwrap()
        .to_owned();

    let files = glob(&glob_expr)?
        .filter_map(|x| match x {
            Err(e) => {
                eprintln!("[Warning] When searching for consensuses: {:?}", e);
                None
            }
            Ok(x) => Some(x),
        })
        .collect::<Vec<_>>();

    if files.len() == 0 {
        panic!("no consensus files found");
    }

    // Associate files with their UTC date and time.
    // Also filter out too old consensuses.
    let files: BTreeMap<DateTime<Utc>, PathBuf> = files
        .into_iter()
        .filter_map(|f| {
            let dt = Utc
                .datetime_from_str(
                    &f.file_name().unwrap().to_str().unwrap()[..19],
                    "%Y-%m-%d-%H-%M-%S",
                )
                .unwrap();

            // only retain a period of 10 years
            if (dt >= Utc.ymd(2012, 5, 1).and_hms(0, 0, 0))
                && (dt < Utc.ymd(2022, 5, 1).and_hms(0, 0, 0))
            {
                Some((dt, f))
            } else {
                None
            }
        })
        .collect();

    // open output file
    let mut wtr = csv::Writer::from_path(&cli_history.csv_out)?;

    // let pb = indicatif::ProgressBar::new(files.len() as u64);

    // parse and save the consensuses
    for (dt, fpath) in files {
        let mut raw = String::new();
        let mut file = File::open(&fpath).unwrap();
        file.read_to_string(&mut raw).unwrap();
        // dbg!(fpath);
        let cons = parser::parse_consensus(&raw)?;

        // create CSV record
        let record = CsvRecord {
            valid_after: cons.valid_after.timestamp() as u64,
            num_relays: cons.relays.len(),
            avg_bandwidth: cons.relays.iter().map(|r| r.bandwidth_weight).sum::<u64>() as f64
                / cons.relays.len() as f64,
        };

        // write to file
        wtr.serialize(record)?;
    }

    drop(wtr);

    Ok(())
}

#[derive(Serialize)]
struct CsvRecord {
    valid_after: u64,
    num_relays: usize,
    avg_bandwidth: f64,
}
