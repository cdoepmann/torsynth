use super::{Cli, Command};

use tordoc::Consensus;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::{offset::TimeZone, DateTime, Utc};
use clap::Args;
use csv;
use fromsuper::FromSuper;
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

#[derive(Debug, FromSuper)]
#[fromsuper(from_type = "tordoc::consensus::Relay", unpack = true)]
struct MyRelay {
    bandwidth_weight: u64,
}

struct MyConsensus {
    valid_after: DateTime<Utc>,
    relays: Vec<MyRelay>,
}

impl TryFrom<Consensus> for MyConsensus {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn try_from(value: Consensus) -> Result<Self, Self::Error> {
        Ok(MyConsensus {
            valid_after: value
                .valid_after
                .ok_or_else(|| "missing valid_after value")?,
            relays: value
                .relays
                .into_iter()
                .map(|r| r.try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

pub(crate) fn command_history(cli: Cli) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
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
            if (dt >= Utc.ymd(2013, 2, 1).and_hms(0, 0, 0))
                && (dt < Utc.ymd(2023, 2, 1).and_hms(0, 0, 0))
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
    for (i, (_dt, fpath)) in files.into_iter().enumerate() {
        if i % 24 == 0 {
            println!("{:7}: {}", i, fpath.display());
        }
        let mut raw = String::new();
        let mut file = File::open(&fpath).unwrap();
        file.read_to_string(&mut raw).unwrap();
        let cons = Consensus::from_str(&raw)?;
        let cons: MyConsensus = cons.try_into()?;

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
