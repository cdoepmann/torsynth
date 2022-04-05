use std::num::ParseIntError;

use thiserror;

/// Custom Error Type
#[derive(thiserror::Error, Debug)]
pub enum DocumentParseError {
    #[error("an internal parsing error occured (raised by nom)")]
    Internal(#[from] nom::error::Error<String>),
    #[error("Parsing stopped after {index} characters before input was complete (line {line}, character {character})")]
    InputRemaining {
        index: usize,
        line: usize,
        character: usize,
    },
    #[error("When parsing a consensus, a relay did not have all necessary information")]
    RelayIncomplete(#[from] super::consensus::ShallowRelayBuilderError),
    #[error("When parsing a descriptor, the relay did not have all necessary information")]
    DescriptorIncomplete(#[from] super::descriptor::DescriptorBuilderError),
    #[error("An item with keyword '{keyword}' unexpectedly had no or not enough arguments")]
    ItemArgumentsMissing { keyword: String },
    #[error("An item with keyword '{keyword}' was not expected at this position")]
    UnexpectedKeyword { keyword: String },
    #[error("Could not decode string as base64")]
    InvalidBase64(#[from] base64::DecodeError),
    #[error("Could not parse date/time")]
    InvalidDate(#[from] chrono::format::ParseError),
    #[error("Could not parse integer")]
    InvalidInt(#[from] ParseIntError),
    #[error("Unknown flag '{flag}'")]
    UnknownFlag { flag: String },
    #[error("Unknown protocol '{protocol}'")]
    UnknownProtocol { protocol: String },
    #[error("Invalid protocol version '{raw}'")]
    InvalidProtocolVersion { raw: String },
    #[error("Invalid exit policy entry '{raw}'")]
    InvalidExitPolicyEntry { raw: String },
    #[error("Malformed exit policy")]
    MalformedExitPolicy,
    #[error("Invalid argument dictionary")]
    InvalidArgumentDict,
    #[error("Invalid bandwidth weight entry")]
    InvalidBandwidthWeight,
    #[error("Consensus weights missing")]
    ConsensusWeightsMissing,
    #[error("Consensus weights cannot be parsed")]
    MalformedConsensusWeights,
    #[error("valid-after missing")]
    ValidAfterMissing,
    #[error("Content range '{from}'...'{to}' not found")]
    ContentRangeNotFound { from: String, to: String },
    #[error("Invalid IP address of relay: {0}")]
    InvalidIpAddress(String),
}

impl DocumentParseError {
    /// Create a new error of variant `InputRemaining`, based on the
    /// observed parser inputs.
    pub fn remaining(total_input: &str, remaining_input: &str) -> DocumentParseError {
        if remaining_input.len() > total_input.len() {
            panic!(
                "More input remaining ({}) than was available before parsing ({}) of Tor document.",
                remaining_input.len(),
                total_input.len()
            );
        }
        let consumed = total_input.len() - remaining_input.len();
        let line = total_input[..consumed].matches('\n').count() + 1;
        let character = match total_input[..consumed].rfind('\n') {
            Some(index) => consumed - index,
            None => consumed + 1,
        };
        DocumentParseError::InputRemaining {
            index: consumed,
            line,
            character,
        }
    }
}

/// Error when combining consensus and descriptors
#[derive(thiserror::Error, Debug)]
pub enum DocumentCombiningError {
    #[error("No descriptor with digest {digest} found.")]
    MissingDescriptor { digest: super::meta::Fingerprint },
    #[error("Descriptors cannot be found because the consensus file is not in a suitable folder structure")]
    InvalidFolderStructure,
}
