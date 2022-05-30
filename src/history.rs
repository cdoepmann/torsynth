use super::parser;
use super::{Cli, Command};
use parser::consensus::ConsensusDocument;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use chrono::{offset::TimeZone, DateTime, Utc};
use clap::Args;
use glob::glob;
use indicatif;

#[derive(Args)]
pub(crate) struct HistoryArgs {
    /// Folder structure containing historical consensuses
    consensus_dir: String,
    /// Output CSV file to store the per-consensus aggregate data
    out_file: String,
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
    let files: BTreeMap<DateTime<Utc>, PathBuf> = files
        .into_iter()
        .map(|f| {
            let dt = Utc
                .datetime_from_str(
                    &f.file_name().unwrap().to_str().unwrap()[..19],
                    "%Y-%m-%d-%H-%M-%S",
                )
                .unwrap();

            (dt, f)
        })
        .collect();

    // TODO filter
    let thresh_date = Utc.ymd(2010, 7, 19).and_hms(0, 0, 0);

    let pb = indicatif::ProgressBar::new(files.len() as u64);
    // pb.inc(114200);
    let cons: Result<Vec<Option<ConsensusDocument>>, parser::DocumentParseError> = files
        .iter()
        .map(
            |(dt, fpath)| -> Result<Option<ConsensusDocument>, parser::DocumentParseError> {
                //).skip(114200) {
                pb.inc(1);

                if dt < &thresh_date {
                    return Ok(None);
                }

                // println!("{:?}", fpath);
                let mut raw = String::new();
                let mut file = File::open(&fpath).unwrap();
                file.read_to_string(&mut raw).unwrap();
                Ok(match parser::parse_consensus(&raw) {
                    Err(parser::DocumentParseError::RelayIncomplete(
                        parser::consensus::ShallowRelayBuilderError::UninitializedField(
                            "bandwidth_weight",
                        ),
                    )) => {
                        println!("ignoring (relabw) {:?}", fpath);
                        None
                    }
                    // Err(parser::DocumentParseError::ConsensusWeightsMissing) => {
                    //     println!("ignoring (consbw) {:?}", fpath);
                    //     None
                    // }
                    x => Some(x?),
                })
            },
        )
        .collect();

    // TODO aggregate etc.

    Ok(())
}
