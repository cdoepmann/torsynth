//! Dump a highlevel consensus to Tor descriptor files

use std::fmt;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;

use chrono::Duration;
use thiserror;

use super::Consensus;
use crate::parser::consensus::Flag;
use crate::parser::descriptor::Descriptor;

#[derive(thiserror::Error, Debug)]
pub enum OutputError {
    #[error("The output directory could not be accessed")]
    DirAccess,
    #[error("The output directory isn't empty")]
    DirNotEmpty,
    #[error("The output path isn't a directory")]
    NotADir,
    #[error("General I/O error")]
    IoError(#[from] io::Error),
    #[error("Formatting error")]
    FmtError(#[from] fmt::Error),
}

pub fn save_to_dir<P: AsRef<Path>>(consensus: &Consensus, dir: P) -> Result<(), OutputError> {
    let dir = dir.as_ref();

    // check output dir
    if !fs::metadata(dir)
        .map_err(|_| OutputError::DirAccess)?
        .is_dir()
    {
        return Err(OutputError::NotADir);
    }
    if let Some(_) = fs::read_dir(dir)
        .map_err(|_| OutputError::DirAccess)?
        .next()
    {
        return Err(OutputError::DirNotEmpty);
    }

    // create output dir tree
    let consensus_dir_path = dir.join("consensus");
    fs::create_dir(&consensus_dir_path)?;

    let descriptors_dir_path = dir.join("descriptors");
    fs::create_dir(&descriptors_dir_path)?;

    // output meta info
    let mut f_consensus = File::create(consensus_dir_path.join("consensus"))?;

    writeln!(&mut f_consensus, "@type network-status-consensus-3 1.0")?;
    writeln!(&mut f_consensus, "network-status-version 3")?;
    writeln!(&mut f_consensus, "vote-status consensus")?;
    writeln!(&mut f_consensus, "consensus-method 31")?;
    writeln!(
        &mut f_consensus,
        "valid-after {}",
        (consensus.valid_after.date().and_hms(0, 0, 0) - Duration::hours(1))
            .format("%Y-%m-%d %H:%M:%S")
    )?;
    writeln!(
        &mut f_consensus,
        "known-flags {}",
        Flag::known_flags_string()
    )?;

    // output relays
    for relay in consensus.relays.values() {
        // First, generate the server descriptor
        let mut desc = String::new();
        {
            use std::fmt::Write;
            writeln!(&mut desc, "@type server-descriptor 1.0")?;
            writeln!(
                &mut desc,
                "router {} {} {} {} {}",
                relay.nickname,
                relay.address,
                9001, // TODO or_port
                0,
                0 // TODO dir_port
            )?;
            writeln!(
                &mut desc,
                "published {}",
                (consensus.valid_after.date().and_hms(0, 0, 0) - Duration::hours(1))
                    .format("%Y-%m-%d %H:%M:%S")
            )?;
            writeln!(
                &mut desc,
                "fingerprint {}",
                relay.fingerprint.to_string_hex_blocks(),
            )?;
            writeln!(
                &mut desc,
                "bandwidth {} {} {}",
                (relay.bandwidth_weight as f32 * relay.bw_ratio_avg as f32) as u64,
                (relay.bandwidth_weight as f32 * relay.bw_ratio_burst as f32) as u64,
                (relay.bandwidth_weight as f32 * relay.bw_ratio_observed as f32) as u64,
            )?;
            if let Some(ref fam) = relay.family {
                writeln!(
                    &mut desc,
                    "family {}",
                    fam.members
                        .iter()
                        .map(|fp| format!("${}", fp.to_string_hex()))
                        .collect::<Vec<_>>()
                        .join(" "),
                )?;
            }
            writeln!(&mut desc, "router-signature")?;
            writeln!(&mut desc, "-----BEGIN SIGNATURE-----")?;
            writeln!(&mut desc, "AAAA")?;
            writeln!(&mut desc, "-----END SIGNATURE-----")?;
        }
        let desc_digest = {
            let from = "router";
            let to = "\nrouter-signature\n";
            let from_idx = desc.find(from).unwrap();
            let to_idx = desc.find(to).unwrap() + to.len();
            Descriptor::digest_from_raw(&desc[from_idx..to_idx])
        };
        fs::write(
            descriptors_dir_path.join(desc_digest.to_string_hex()),
            &desc,
        )?;

        // Now print the consensus entry
        writeln!(
            &mut f_consensus,
            "r {} {} {} {} {} {} {}",
            relay.nickname,
            relay.fingerprint.to_string_b64(),
            desc_digest.to_string_b64(),
            (consensus.valid_after.date().and_hms(0, 0, 0) - Duration::hours(1))
                .format("%Y-%m-%d %H:%M:%S"),
            relay.address,
            9001, // TODO or_port
            0,    // TODO dir_port
        )?;
        writeln!(
            &mut f_consensus,
            "s {}",
            relay
                .flags
                .iter()
                .map(|f| <&'static str>::from(f))
                .collect::<Vec<_>>()
                .join(" ")
                .to_string()
        )?;
        writeln!(&mut f_consensus, "v Tor 0.4.6.10")?; // TODO version
        writeln!(
            &mut f_consensus,
            "pr {}",
            relay
                .protocols
                .iter()
                .map(|(protocol, version)| {
                    format!("{} {}", <&'static str>::from(protocol), version.to_string())
                })
                .collect::<Vec<_>>()
                .join(" ")
        )?;
        writeln!(&mut f_consensus, "w Bandwidth={}", relay.bandwidth_weight)?;
        writeln!(&mut f_consensus, "p {}", relay.exit_policy)?;
    }

    writeln!(&mut f_consensus, "directory-footer")?;
    writeln!(
        &mut f_consensus,
        "bandwidth-weights {}",
        consensus
            .weights
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(" ")
    )?;

    Ok(())
}
