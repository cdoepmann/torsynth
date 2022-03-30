//! Parser for Tor docs.

// other local modules
mod error;
pub use error::DocumentParseError;

mod meta;
pub use meta::Document;

#[derive(Debug)]
pub struct ConsensusDocument {}

pub fn parse_consensus(text: &str) -> Result<Document, DocumentParseError> {
    Document::parse_single(text)
}

pub fn parse_descriptors(text: &str) -> Result<Vec<Document>, DocumentParseError> {
    Document::parse_many(text)
}
