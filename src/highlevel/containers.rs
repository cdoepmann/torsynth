//! Helpers to work with parsed Tor data on a high level.

// std
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::path::Path;
use std::rc::Rc;

// external dependencies
use chrono::{DateTime, Utc};
use regex::Regex;

// local modules
use super::bwweights;
use crate::parser;
use crate::parser::asn::{Asn, AsnDb};
use crate::parser::consensus::ConsensusDocument;
use crate::parser::consensus::{
    CondensedExitPolicy, Flag, Protocol, ShallowRelay, SupportedProtocolVersion,
};
use crate::parser::descriptor::{Descriptor, FamilyMember};
use crate::parser::DocumentCombiningError;
use crate::parser::Fingerprint;

/// A container for the result of merging a consensus document and the
/// respective relay server descriptors.
#[derive(Debug)]
pub struct Consensus {
    pub weights: BTreeMap<String, u64>,
    pub relays: HashMap<Fingerprint, Relay>,
}

/// A relay contained in the consensus
#[derive(Debug, Clone)]
pub struct Relay {
    // from consensus
    pub nickname: String,
    pub fingerprint: Fingerprint,
    pub digest: Fingerprint,
    pub published: DateTime<Utc>,
    pub address: Ipv4Addr,
    pub asn: Option<Rc<Asn>>,
    pub or_port: u16,
    pub dir_port: Option<u16>,
    pub flags: Vec<Flag>,
    pub version_line: String,
    pub protocols: BTreeMap<Protocol, SupportedProtocolVersion>,
    pub exit_policy: CondensedExitPolicy,
    pub bandwidth_weight: u64,
    // from descriptor
    pub family_members: Vec<Fingerprint>,
}

impl Relay {
    fn from_consensus_entry_and_descriptor<F: Fn(FamilyMember) -> Option<Fingerprint>>(
        cons_relay: ShallowRelay,
        desc: Descriptor,
        family_filter: F,
    ) -> Relay {
        Relay {
            // from consensus
            nickname: cons_relay.nickname,
            fingerprint: cons_relay.fingerprint,
            digest: cons_relay.digest,
            published: cons_relay.published,
            address: cons_relay.address,
            asn: cons_relay.asn,
            or_port: cons_relay.or_port,
            dir_port: cons_relay.dir_port,
            flags: cons_relay.flags,
            version_line: cons_relay.version_line,
            protocols: cons_relay.protocols,
            exit_policy: cons_relay.exit_policy,
            bandwidth_weight: cons_relay.bandwidth_weight,
            // from descriptor
            family_members: desc
                .family_members
                .into_iter()
                // keep only family members that do exist, and convert them to
                .filter_map(family_filter)
                .collect(),
        }
    }

    pub fn has_flag(&self, flag: Flag) -> bool {
        self.flags.contains(&flag)
    }
}

impl Consensus {
    /// Construct a high-level consensus object from the lower-level parsed
    /// consensus and descriptors
    pub fn combine_documents(
        consensus: ConsensusDocument,
        descriptors: Vec<Descriptor>,
    ) -> Result<Consensus, DocumentCombiningError> {
        // index descriptors by digest
        let mut descriptors: HashMap<Fingerprint, Descriptor> = descriptors
            .into_iter()
            .map(|d| (d.digest.clone(), d))
            .collect();
        // remember which fingerprints are in the consensus
        let known_fingerprints: HashSet<Fingerprint> = consensus
            .relays
            .iter()
            .map(|r| r.fingerprint.clone())
            .collect();

        // remember **unique** nicknames
        let mut nicknames_to_fingerprints: HashMap<String, Option<Fingerprint>> = HashMap::new();
        {
            for relay in consensus.relays.iter() {
                let nickname = relay.nickname.clone();
                match nicknames_to_fingerprints.entry(nickname) {
                    Entry::Vacant(e) => {
                        e.insert(Some(relay.fingerprint.clone()));
                    }
                    Entry::Occupied(mut e) => {
                        // if this nickname is already known, remember that it is not unique
                        e.insert(None);
                    }
                }
            }
        }

        let filter_family_member = |f: FamilyMember| match f {
            FamilyMember::Fingerprint(fingerprint) => {
                if known_fingerprints.contains(&fingerprint) {
                    Some(fingerprint)
                } else {
                    None
                }
            }
            FamilyMember::Nickname(nickname) => {
                if let Some(entry) = nicknames_to_fingerprints.get(&nickname) {
                    if let Some(fingerprint) = entry {
                        return Some(fingerprint.clone());
                    }
                }
                None
            }
        };

        let mut relays: HashMap<Fingerprint, Relay> = HashMap::new();
        for relay in consensus.relays {
            let descriptor = descriptors.remove(&relay.digest).ok_or_else(|| {
                DocumentCombiningError::MissingDescriptor {
                    digest: relay.digest.clone(),
                }
            })?;

            relays.insert(
                descriptor.fingerprint.clone(),
                Relay::from_consensus_entry_and_descriptor(relay, descriptor, filter_family_member),
            );
        }

        println!("relays in consensus: {}", relays.len());
        println!("unused descriptors: {}", descriptors.len());
        drop(descriptors);
        let with_asn = {
            let mut res = 0;
            for r in relays.values() {
                if let Some(_) = r.asn {
                    res += 1;
                }
            }
            res
        };
        println!("relays with AS: {}", with_asn);
        let mut res = Consensus {
            weights: consensus.weights,
            relays: relays,
        };
        res.clean_families();
        Ok(res)
    }

    /// Make sure that (1) families only contain relays that mirror this relationship, and
    ///                (2) relays do not list themselves as family members
    fn clean_families(&mut self) {
        let tmp_relays_copy = self.relays.clone();
        for (this_fingerprint, relay) in self.relays.iter_mut() {
            relay.family_members.retain(|fp| {
                let remote_family = &tmp_relays_copy[fp].family_members;
                fp != this_fingerprint && remote_family.contains(this_fingerprint)
            })
        }
    }

    fn recompute_bw_weights(&mut self) {
        bwweights::recompute_bw_weights(self)
    }

    /// Recompute and verify the contained bandwidth weights
    pub fn verify_weights(&mut self) -> Result<(), String> {
        let old_weights = self.weights.clone();
        self.recompute_bw_weights();
        let new_weights = &self.weights;

        if old_weights == *new_weights {
            return Ok(());
        } else {
            return Err(format!(
                "old weights: {:?}\nnew weights: {:?}",
                old_weights, new_weights
            ));
        }
    }
}

/// Load descriptors from files relative to the consensus document
pub fn lookup_descriptors<P: AsRef<Path>>(
    consensus: &ConsensusDocument,
    consensus_path: P,
) -> Result<Vec<Descriptor>, Box<dyn std::error::Error>> {
    let consensus_path = consensus_path.as_ref();
    // get year and month
    let fname_regex = Regex::new(r"^(\d{4})-(\d{2})-(\d{2})-").unwrap();
    let fname_match = fname_regex
        .captures(
            consensus_path
                .file_name()
                .ok_or(DocumentCombiningError::InvalidFolderStructure)?
                .to_str()
                .ok_or(DocumentCombiningError::InvalidFolderStructure)?,
        )
        .ok_or(DocumentCombiningError::InvalidFolderStructure)?;
    let this_year: u32 = fname_match.get(1).unwrap().as_str().parse().unwrap();
    let this_month: u32 = fname_match.get(2).unwrap().as_str().parse().unwrap();

    let (previous_year, previous_month) = if this_month == 1 {
        (this_year - 1, 12)
    } else {
        (this_year, this_month - 1)
    };

    // find the corresponding descriptor folders (current month and the one before)
    let current_desc = consensus_path
        .parent()
        .ok_or(DocumentCombiningError::InvalidFolderStructure)?
        .join(format!(
            "../../server-descriptors-{:04}-{:02}/",
            this_year, this_month
        ));
    if !current_desc.exists() {
        return Err(Box::new(DocumentCombiningError::InvalidFolderStructure));
    }
    let previous_desc = consensus_path
        .parent()
        .ok_or(DocumentCombiningError::InvalidFolderStructure)?
        .join(format!(
            "../../server-descriptors-{:04}-{:02}/",
            previous_year, previous_month
        ));

    // Lookup the descriptors
    let mut descriptors = Vec::new();
    for relay in consensus.relays.iter() {
        let digest = format!("{}", relay.digest);
        let first_char = digest.chars().next().unwrap();
        let second_char = digest.chars().skip(1).next().unwrap();

        let subpath = format!("{}/{}/{}", first_char, second_char, digest);
        let current_path = current_desc.join(&subpath);
        let previous_path = previous_desc.join(&subpath);

        let desc_path = if current_path.exists() {
            current_path
        } else if previous_path.exists() {
            previous_path
        } else {
            return Err(Box::new(DocumentCombiningError::MissingDescriptor {
                digest: relay.digest.clone(),
            }));
        };

        let mut raw = String::new();
        let mut file = File::open(desc_path).unwrap();
        file.read_to_string(&mut raw).unwrap();
        descriptors.append(&mut parser::parse_descriptors(&raw)?);
    }

    Ok(descriptors)
}
