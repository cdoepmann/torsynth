//! Tor consensus documents

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::num::ParseIntError;
use std::rc::Rc;
use std::str::FromStr;

use super::DocumentParseError;

use super::asn::{Asn, AsnDb};
use super::meta;
use meta::{Document, Fingerprint};

//
// External dependencies
//
use chrono::{offset::TimeZone, DateTime, Utc};
use derive_builder::Builder;
use strum::EnumString;

/// A relay flag in the consensus
#[derive(Debug, Clone, EnumString)]
pub enum Flag {
    Authority,
    BadExit,
    Exit,
    Fast,
    Guard,
    HSDir,
    NoEdConsensus,
    Running,
    Stable,
    StaleDesc,
    Sybil,
    V2Dir,
    Valid,
}

/// A Tor sub-protocol
#[derive(Debug, Clone, EnumString, PartialEq, PartialOrd, Eq, Ord)]
pub enum Protocol {
    Cons,
    Desc,
    DirCache,
    FlowCtrl,
    HSDir,
    HSIntro,
    HSRend,
    Link,
    LinkAuth,
    Microdesc,
    Padding,
    Relay,
}

/// A range of supported protocol versions
#[derive(Debug, Clone)]
pub struct SupportedProtocolVersion {
    versions: Vec<u8>,
}

impl SupportedProtocolVersion {
    fn supports(&self, v: u8) -> bool {
        self.versions.contains(&v)
    }
}

impl FromStr for SupportedProtocolVersion {
    type Err = DocumentParseError;

    /// Parse from "3" or "2-5".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut versions = Vec::new();
        for component in s.split(',') {
            match component.split_once('-') {
                Some((min, max)) => {
                    let min = u8::from_str_radix(min, 10)?;
                    let max = u8::from_str_radix(max, 10)?;

                    for i in min..=max {
                        versions.push(i);
                    }
                }
                None => {
                    let elem = u8::from_str_radix(component, 10)?;
                    versions.push(elem);
                }
            }
        }
        Ok(SupportedProtocolVersion { versions })
    }
}

/// Exit policy type
#[derive(Debug, Clone, Copy)]
enum PolicyType {
    Accept,
    Reject,
}

/// Exit port entry
#[derive(Debug, Clone, Copy)]
enum PolicyEntry {
    SinglePort(u16),
    PortRange { min: u16, max: u16 },
}

impl PolicyEntry {
    fn matches_port(&self, port: u16) -> bool {
        match self {
            PolicyEntry::SinglePort(a) => *a == port,
            PolicyEntry::PortRange { min, max } => port >= *min && port <= *max,
        }
    }
}

impl FromStr for PolicyEntry {
    type Err = DocumentParseError;

    /// Parse from "3" or "2-5".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('-') {
            Some((min, max)) => Ok(PolicyEntry::PortRange {
                min: u16::from_str_radix(min, 10)?,
                max: u16::from_str_radix(max, 10)?,
            }),
            None => Ok(PolicyEntry::SinglePort(u16::from_str_radix(s, 10)?)),
        }
        .map_err(
            |_: ParseIntError| DocumentParseError::InvalidExitPolicyEntry { raw: s.to_string() },
        )
    }
}

/// A relay's condensed exit policy (ports for "most" target IP addresses)
#[derive(Debug, Clone)]
pub struct CondensedExitPolicy {
    policy_type: PolicyType,
    entries: Vec<PolicyEntry>,
}

impl FromStr for CondensedExitPolicy {
    type Err = DocumentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (cmd, ports) = s
            .split_once(' ')
            .ok_or(DocumentParseError::MalformedExitPolicy)?;
        let policy_type = match cmd {
            "accept" => PolicyType::Accept,
            "reject" => PolicyType::Reject,
            _ => return Err(DocumentParseError::MalformedExitPolicy),
        };
        let entries = ports
            .split(',')
            .map(|x| x.parse::<PolicyEntry>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CondensedExitPolicy {
            policy_type,
            entries,
        })
    }
}

/// A parsed consensus document ("network status").
#[derive(Debug)]
pub struct ConsensusDocument {
    pub relays: Vec<ShallowRelay>,
    pub weights: BTreeMap<String, u64>,
}

/// A relay entry within the consensus, containing only these sparse information
/// instead of the full server descriptor
#[derive(Debug, Builder)]
pub struct ShallowRelay {
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
}

///

impl ConsensusDocument {
    /// Parse a consensus document from raw text.
    pub fn from_str(text: &str, asn_db: AsnDb) -> Result<ConsensusDocument, DocumentParseError> {
        let doc = Document::parse_single(text)?;
        Self::from_doc(doc, asn_db)
    }
    /// Parse a consensus document from an already-parsed Tor meta document
    pub fn from_doc(doc: Document, asn_db: AsnDb) -> Result<ConsensusDocument, DocumentParseError> {
        // the current relay we're constructing
        let mut relay: Option<ShallowRelayBuilder> = None;

        // collected relays
        let mut relays: Vec<ShallowRelay> = Vec::new();

        // collect relays
        for item in doc.items.iter().skip_while(|&x| x.keyword != "r") {
            match item.keyword {
                "r" => {
                    // if another relay was in process, finish it
                    if let Some(old) = relay.take() {
                        relays.push(old.build()?);
                    }
                    // start a new relay
                    relay = Some(ShallowRelayBuilder::default());
                    let relay = relay.as_mut().unwrap();

                    // parse entries
                    let splits = item.split_arguments()?;
                    match splits[..] {
                        [nickname, identity, digest, published_1, published_2, ip, or_port, dir_port, ..] =>
                        {
                            relay.nickname(nickname.to_string());
                            relay.fingerprint(Fingerprint::from_str_b64(identity)?);
                            relay.digest(Fingerprint::from_str_b64(digest)?);
                            relay.published(Utc.datetime_from_str(
                                &format!("{published_1} {published_2}"),
                                "%Y-%m-%d %H:%M:%S",
                            )?);
                            let address = Ipv4Addr::from_str(ip).map_err(|_| {
                                DocumentParseError::InvalidIpAddress(ip.to_string())
                            })?;
                            relay.address(address);
                            let asn = asn_db.lookup(address);
                            relay.asn(asn);
                            relay.or_port(u16::from_str_radix(or_port, 10)?);
                            relay.dir_port(match u16::from_str_radix(dir_port, 10)? {
                                0 => None,
                                x => Some(x),
                            });
                        }
                        _ => {
                            return Err(DocumentParseError::ItemArgumentsMissing {
                                keyword: item.keyword.to_string(),
                            })
                        }
                    }
                }
                "s" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;

                    // parse flags
                    let splits = item.split_arguments()?;
                    let flags: Vec<Flag> = splits
                        .iter()
                        .map(|x| {
                            x.parse::<Flag>()
                                .map_err(|_| DocumentParseError::UnknownFlag {
                                    flag: x.to_string(),
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    relay.flags(flags);
                }
                "v" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;
                    relay.version_line(item.arguments.unwrap_or("").to_string());
                }
                "pr" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;
                    // parse flags
                    let mut protocols = BTreeMap::new();
                    let splits = item.split_arguments()?;
                    for split in splits.iter() {
                        let (left, right) = split
                            .split_once('=')
                            .ok_or(DocumentParseError::InvalidArgumentDict)?;
                        let prot = left.parse::<Protocol>().map_err(|_| {
                            DocumentParseError::UnknownProtocol {
                                protocol: left.to_string(),
                            }
                        })?;
                        let vers = right.parse::<SupportedProtocolVersion>().map_err(|_| {
                            DocumentParseError::InvalidProtocolVersion {
                                raw: right.to_string(),
                            }
                        })?;
                        protocols.insert(prot, vers);
                    }
                    relay.protocols(protocols);
                }
                "p" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;

                    // parse policy
                    relay.exit_policy(item.get_argument()?.parse::<CondensedExitPolicy>()?);
                }
                "w" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;
                    // parse bandwidth weight
                    if !item.get_argument()?.starts_with("Bandwidth=") {
                        return Err(DocumentParseError::InvalidBandwidthWeight);
                    }
                    let arguments = item.split_arguments()?;
                    for arg in arguments.iter() {
                        let (k, v) = arg
                            .split_once('=')
                            .ok_or(DocumentParseError::InvalidBandwidthWeight)?;
                        match k {
                            "Bandwidth" => {
                                relay.bandwidth_weight(
                                    u64::from_str_radix(v, 10)
                                        .map_err(|_| DocumentParseError::InvalidBandwidthWeight)?,
                                );
                            }
                            _ => {}
                        }
                    }
                }
                "a" => {
                    // IPv6 addresses, not implemented
                    // TODO
                }
                _ => {
                    if let Some(last) = relay.take() {
                        relays.push(last.build()?);
                    }
                    break;
                }
            }
        }

        // collect weights
        let weights = {
            let item = doc
                .items
                .iter()
                .skip_while(|&x| x.keyword != "bandwidth-weights")
                .next()
                .ok_or(DocumentParseError::ConsensusWeightsMissing)?;
            let mut weights = BTreeMap::new();

            let args = item.split_arguments()?;
            for arg in args.iter() {
                let (k, v) = arg
                    .split_once('=')
                    .ok_or(DocumentParseError::MalformedConsensusWeights)?;
                let v = u64::from_str_radix(v, 10)
                    .map_err(|_| DocumentParseError::MalformedConsensusWeights)?;
                weights.insert(k.to_string(), v);
            }

            weights
        };
        // return everything
        Ok(ConsensusDocument { relays, weights })
    }
}
