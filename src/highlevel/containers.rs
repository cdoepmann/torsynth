//! Helpers to work with parsed Tor data on a high level.

// std
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::path::Path;
use std::rc::Rc;

// external dependencies
use chrono::{DateTime, Utc};
use itertools;
use regex::Regex;

// local modules
use super::asn::{Asn, AsnDb};
use super::bwweights;
use super::families;
use super::families::Family;
use crate::parser;
use crate::parser::consensus::ConsensusDocument;
use crate::parser::consensus::{
    CondensedExitPolicy, Flag, Protocol, ShallowRelay, SupportedProtocolVersion,
};
use crate::parser::descriptor::{Descriptor, FamilyMember};
use crate::parser::DocumentCombiningError;
use crate::parser::Fingerprint;

use seeded_rand::{RHashMap, RHashSet};

/// A container for the result of merging a consensus document and the
/// respective relay server descriptors.
#[derive(Debug)]
pub struct Consensus {
    pub valid_after: DateTime<Utc>,
    pub weights: BTreeMap<String, u64>,
    pub relays: RHashMap<Fingerprint, Relay>,
    pub families: Vec<Rc<Family>>,
    /// Probability that a relay is in a family
    pub prob_family: f32,
    /// Probability that an two relays in a family have the same AS
    pub prob_family_sameas: f32,
    /// Sizes of families: (size, frequency) tuples
    pub family_sizes: Vec<(usize, usize)>,
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
    pub family: Option<Rc<Family>>,
    pub bw_ratio_avg: f32,
    pub bw_ratio_burst: f32,
    pub bw_ratio_observed: f32,
    pub bw_observed_was_zero: bool,
}

impl Relay {
    // TODO name
    fn from_consensus_entry_and_descriptor(
        cons_relay: ShallowRelay,
        descriptor: Descriptor,
        asn_db: &AsnDb,
    ) -> Relay {
        Relay {
            // from consensus
            nickname: cons_relay.nickname,
            fingerprint: cons_relay.fingerprint,
            digest: cons_relay.digest,
            published: cons_relay.published,
            address: cons_relay.address,
            asn: asn_db.lookup(cons_relay.address),
            or_port: cons_relay.or_port,
            dir_port: cons_relay.dir_port,
            flags: cons_relay.flags,
            version_line: cons_relay.version_line,
            protocols: cons_relay.protocols,
            exit_policy: cons_relay.exit_policy,
            bandwidth_weight: cons_relay.bandwidth_weight,
            // from descriptor
            family: None, // do not set now, but later after all relays are known
            bw_ratio_avg: descriptor.bandwidth_avg as f32 / cons_relay.bandwidth_weight as f32,
            bw_ratio_burst: descriptor.bandwidth_burst as f32 / cons_relay.bandwidth_weight as f32,
            bw_ratio_observed: descriptor.bandwidth_observed as f32
                / cons_relay.bandwidth_weight as f32,
            bw_observed_was_zero: descriptor.bandwidth_observed == 0,
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
        asn_db: &AsnDb,
    ) -> Result<Consensus, DocumentCombiningError> {
        // index descriptors by digest
        let mut descriptors: RHashMap<Fingerprint, Descriptor> = descriptors
            .into_iter()
            .map(|d| (d.digest.clone(), d))
            .collect();
        // remember which fingerprints are in the consensus
        let known_fingerprints: RHashSet<Fingerprint> = consensus
            .relays
            .iter()
            .map(|r| r.fingerprint.clone())
            .collect();

        // remember **unique** nicknames
        let mut nicknames_to_fingerprints: RHashMap<String, Option<Fingerprint>> =
            RHashMap::default();
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

        let mut family_relations: RHashMap<Fingerprint, Vec<Fingerprint>> = RHashMap::default();

        let mut relays: RHashMap<Fingerprint, Relay> = RHashMap::default();
        for relay in consensus.relays {
            let descriptor = descriptors.remove(&relay.digest).ok_or_else(|| {
                DocumentCombiningError::MissingDescriptor {
                    digest: relay.digest.clone(),
                }
            })?;

            family_relations.insert(
                relay.fingerprint.clone(),
                descriptor
                    .family_members
                    .iter()
                    // keep only family members that do exist, and convert them to
                    .cloned()
                    .filter_map(filter_family_member)
                    .collect(),
            );
            relays.insert(
                descriptor.fingerprint.clone(),
                Relay::from_consensus_entry_and_descriptor(relay, descriptor, asn_db),
            );
        }
        // only keep symmetric family relations etc.
        families::clean_families(&mut family_relations);

        // {
        //     let count: usize = family_relations.values().map(|x| x.len()).sum();
        //     println!("Old number of family relations: {}", count);
        // }
        // Make proper family objects
        let (family_cliques, family_objects) = families::make_cliques(family_relations);
        for (fp, relay) in relays.iter_mut() {
            let family = family_cliques[fp].clone(); // cheap due to Rc
            relay.family = family;
        }
        // {
        //     let count: usize = family_cliques
        //         .values()
        //         .map(|x| x.as_ref().map(|x| &(*x).members).unwrap_or(&vec![]).len())
        //         .sum();
        //     println!("Old number of family relations: {}", count);
        // }

        println!("relays in consensus: {}", relays.len());
        println!("unused descriptors: {}", descriptors.len());
        drop(descriptors);

        // compute stats
        let prob_family = prob_family(&relays);
        let prob_family_sameas = prob_family_sameas(&family_objects, &relays);
        let family_sizes = family_sizes(&family_objects);

        // for relay in relays.values() {
        //     if !relay.has_flag(Flag::Valid) {
        //         println!("not valid: {}", relay.nickname);
        //     }
        // }

        let res = Consensus {
            valid_after: consensus.valid_after,
            weights: consensus.weights,
            relays: relays,
            families: family_objects,
            prob_family,
            prob_family_sameas,
            family_sizes,
        };
        res.print_stats();

        Ok(res)
    }

    pub fn recompute_bw_weights(&mut self) {
        bwweights::recompute_bw_weights(self)
    }

    pub fn print_stats(&self) {
        let with_asn = {
            let mut res = 0;
            for r in self.relays.values() {
                if let Some(_) = r.asn {
                    res += 1;
                }
            }
            res
        };
        println!("relays with AS: {}", with_asn);
        println!("number of families: {}", self.families.len());
        println!("share of relays with family: {}", self.prob_family);
        println!(
            "Pairwise probability for family members to have the same AS: {}",
            self.prob_family_sameas
        );

        println!("Sizes of families:");
        for (size, n) in self.family_sizes.iter() {
            println!(
                "- size {:3} -> {:3} families ({:4.3} of families)",
                size,
                *n,
                *n as f32 / self.families.len() as f32
            );
        }

        println!(
            "Total bandwidth: {:8.3} GB/s",
            self.relays
                .values()
                .map(|r| r.bandwidth_weight)
                .sum::<u64>() as f32
                / (1024 * 1024) as f32
        );
        println!(
            "Exit bandwidth:  {:8.3} GB/s",
            self.relays
                .values()
                .filter(|r| r.has_flag(Flag::Exit))
                .map(|r| r.bandwidth_weight)
                .sum::<u64>() as f32
                / (1024 * 1024) as f32
        );
        println!(
            "Guard bandwidth: {:8.3} GB/s",
            self.relays
                .values()
                .filter(|r| r.has_flag(Flag::Guard))
                .map(|r| r.bandwidth_weight)
                .sum::<u64>() as f32
                / (1024 * 1024) as f32
        );
    }

    pub fn recompute_stats(&mut self) {
        self.prob_family = prob_family(&self.relays);
        self.prob_family_sameas = prob_family_sameas(&self.families, &self.relays);
        self.family_sizes = family_sizes(&self.families);
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

    /// Remove all relays from the consensus that meet a certain condition
    pub fn remove_relays_by<F: FnMut(&Relay) -> bool>(&mut self, mut condition: F) {
        // remove relays
        self.relays.retain(|_, v| !condition(v));

        // adjust family objects
        self.families = families::recompute_families(&mut self.relays);

        // recompute weights and stats
        self.recompute_bw_weights();
        self.recompute_stats();
    }
}

fn prob_family(relays: &RHashMap<Fingerprint, Relay>) -> f32 {
    relays.values().filter(|x| x.family.is_some()).count() as f32 / relays.len() as f32
}

fn prob_family_sameas(
    family_objects: &Vec<Rc<Family>>,
    relays: &RHashMap<Fingerprint, Relay>,
) -> f32 {
    family_objects
        .iter()
        .map(|rc| &(*rc).members)
        .map(|members| {
            let asns: Vec<u32> = members
                .iter()
                .map(|fp| relays[fp].asn.as_ref().map(|a| a.number).unwrap_or(0))
                .collect();
            let total = asns.len() * asns.len();

            use itertools::Itertools;
            let same: usize = asns
                .iter()
                .cartesian_product(asns.iter())
                .map(|(x, y)| if x == y { 1 } else { 0 })
                .sum();
            same as f32 / total as f32
        })
        .sum::<f32>()
        / family_objects.len() as f32
}

fn family_sizes(family_objects: &Vec<Rc<Family>>) -> Vec<(usize, usize)> {
    families::size_histogram(&family_objects)
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
