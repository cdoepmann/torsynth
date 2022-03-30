//! Parser for Tor docs.

// other local modules
mod error;
pub use error::DocumentParseError;

mod meta;
pub use meta::Document;

mod consensus;
pub use consensus::ConsensusDocument;

pub fn parse_consensus(text: &str) -> Result<ConsensusDocument, DocumentParseError> {
    ConsensusDocument::from_str(text)
}

pub fn parse_descriptors(text: &str) -> Result<Vec<Document>, DocumentParseError> {
    Document::parse_many(text)
}
