//! Dump a highlevel consensus to Tor descriptor files

use std::cmp::min;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use chrono::Duration;
use serde::Serialize;
use serde_json;
use thiserror;

use super::Consensus;

use sha1::{Digest, Sha1};
use tordoc::{consensus::Flag, Fingerprint};

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
    #[error("JSON serialization error")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct JsonConsensus {
    relays: Vec<JsonRelay>,
}

#[derive(Serialize)]
struct JsonRelay {
    nickname: String,
    fingerprint: String,
    weight: u64,
    is_guard: bool,
    is_exit: bool,
    asn: u32,
}

fn save_consensus_json<P: AsRef<Path>>(consensus: &Consensus, fpath: P) -> Result<(), OutputError> {
    let relays: Vec<JsonRelay> = consensus
        .relays
        .iter()
        .map(|(fp, r)| JsonRelay {
            fingerprint: fp.to_string_hex(),
            nickname: r.nickname.clone(),
            weight: r.bandwidth_weight,
            is_guard: r.has_flag(Flag::Guard),
            is_exit: r.has_flag(Flag::Exit),
            asn: r.asn.as_ref().map(|x| x.number).unwrap_or(0),
        })
        .collect();
    let result = JsonConsensus { relays };

    let mut f = File::create(fpath.as_ref())?;
    write!(&mut f, "{}", serde_json::to_string_pretty(&result)?)?;

    Ok(())
}

pub fn save_to_dir(consensus: &Consensus, dir: impl AsRef<Path>) -> Result<(), OutputError> {
    let dir: &Path = dir.as_ref();

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
    let consensus_dir = dir.join("consensus");
    fs::create_dir(&consensus_dir)?;
    let consensus_path = consensus_dir.join("consensus");
    let consensus_json_path = consensus_dir.join("consensus.json");

    let descriptor_dir = dir.join("descriptors");
    fs::create_dir(&descriptor_dir)?;
    let descriptor_path = |fp: &Fingerprint| -> Result<PathBuf, OutputError> {
        Ok(descriptor_dir.join(fp.to_string_hex()))
    };

    save_to(
        consensus,
        consensus_path,
        Some(consensus_json_path),
        descriptor_path,
    )
}

pub fn save_to_tordata_dir(
    consensus: &Consensus,
    dir: impl AsRef<Path>,
) -> Result<(), OutputError> {
    let dir: &Path = dir.as_ref();

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

    // consensus file
    let consensus_dir = dir.join(
        consensus
            .valid_after
            .format("consensuses-%Y-%m")
            .to_string(),
    );
    fs::create_dir(&consensus_dir)?;
    let consensus_dir = consensus_dir.join(consensus.valid_after.format("%m").to_string());
    fs::create_dir(&consensus_dir)?;

    let consensus_path = consensus_dir.join(
        consensus
            .valid_after
            .format("%Y-%m-%d-%H-%M-%S-consensus")
            .to_string(),
    );

    // descriptor files
    let descriptor_dir = dir.join(
        consensus
            .valid_after
            .format("server-descriptors-%Y-%m")
            .to_string(),
    );
    fs::create_dir(&descriptor_dir)?;

    let descriptor_path = |fp: &Fingerprint| -> Result<PathBuf, OutputError> {
        let digest = fp.to_string_hex();
        let first_char = digest.chars().nth(0).unwrap().to_string();
        let second_char = digest.chars().nth(1).unwrap().to_string();

        let desc_subdir = descriptor_dir.join(first_char).join(second_char);
        fs::create_dir_all(&desc_subdir)?;

        Ok(desc_subdir.join(fp.to_string_hex()))
    };

    save_to(
        consensus,
        consensus_path,
        None as Option<PathBuf>,
        descriptor_path,
    )
}

fn save_to(
    consensus: &Consensus,
    consensus_path: impl AsRef<Path>,
    consensus_json_path: Option<impl AsRef<Path>>,
    descriptor_path: impl FnMut(&Fingerprint) -> Result<PathBuf, OutputError>,
) -> Result<(), OutputError> {
    let consensus_path = consensus_path.as_ref();
    let mut descriptor_path = descriptor_path;

    // output meta info
    let mut f_consensus = File::create(consensus_path)?;

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
                min(
                    (relay.bandwidth_weight as f32 * relay.bw_ratio_avg as f32) as u64,
                    2147483500
                ),
                min(
                    (relay.bandwidth_weight as f32 * relay.bw_ratio_burst as f32) as u64,
                    2147483500
                ),
                min(
                    (relay.bandwidth_weight as f32 * relay.bw_ratio_observed as f32) as u64,
                    2147483500
                ),
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

            for line in relay.exit_policy.to_descriptor_lines() {
                writeln!(&mut desc, "{}", line)?;
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
            digest_from_raw(&desc[from_idx..to_idx])
        };
        fs::write(descriptor_path(&desc_digest)?, &desc)?;

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
            match relay.protocols {
                Some(ref protocols) => {
                    protocols
                        .iter()
                        .map(|(protocol, version)| {
                            format!("{}={}", <&'static str>::from(protocol), version.to_string())
                        })
                        .collect::<Vec<_>>()
                        .join(" ")
                }
                None => "".to_string(),
            }
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

    // save consensus JSON
    if let Some(consensus_json_path) = consensus_json_path {
        save_consensus_json(consensus, consensus_json_path)?;
    }

    Ok(())
}

/// Compute the digest given the extracted raw content
pub fn digest_from_raw<R: AsRef<[u8]>>(raw: R) -> Fingerprint {
    let raw = raw.as_ref();
    let mut hasher = Sha1::new();
    hasher.update(raw);
    let result = hasher.finalize();
    Fingerprint::from_u8(&result)
}
