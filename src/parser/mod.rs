//! Parser for Tor docs.

// other local modules
mod error;
pub use error::DocumentCombiningError;
pub use error::DocumentParseError;

mod meta;
pub use meta::{Document, Fingerprint};

pub mod consensus;
use consensus::ConsensusDocument;

pub mod descriptor;
use descriptor::Descriptor;

pub mod asn;

pub fn parse_consensus(
    text: &str,
    asn_db: asn::AsnDb,
) -> Result<ConsensusDocument, DocumentParseError> {
    ConsensusDocument::from_str(text, asn_db)
}

pub fn parse_descriptors(text: &str) -> Result<Vec<Descriptor>, DocumentParseError> {
    let docs = Document::parse_many(text)?;
    let descriptors = docs
        .into_iter()
        .map(Descriptor::from_doc)
        .collect::<Result<_, _>>()?;
    Ok(descriptors)
}
