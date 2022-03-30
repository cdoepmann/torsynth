//! Parser for Tor docs.

// other local modules
mod error;
pub use error::DocumentParseError;

mod meta;
pub use meta::{Document, Fingerprint};

mod consensus;
pub use consensus::ConsensusDocument;

mod descriptor;
pub use descriptor::Descriptor;

// dependencies
use std::collections::hash_map::Entry;
use std::collections::HashMap;

pub fn parse_consensus(text: &str) -> Result<ConsensusDocument, DocumentParseError> {
    ConsensusDocument::from_str(text)
}

pub fn parse_descriptors(
    text: &str,
) -> Result<HashMap<Fingerprint, Descriptor>, DocumentParseError> {
    let mut res = HashMap::new();
    let docs = Document::parse_many(text)?;

    for doc in docs {
        let descriptor = Descriptor::from_doc(doc)?;

        // index by descriptor digest
        res.insert(descriptor.digest.clone(), descriptor);

        // // only keep the most up-to-date descriptor per fingerprint
        // match res.entry(descriptor.fingerprint.clone()) {
        //     Entry::Vacant(e) => {
        //         e.insert(descriptor);
        //     }
        //     Entry::Occupied(mut e) => {
        //         if descriptor.published > e.get().published {
        //             e.insert(descriptor);
        //         }
        //     }
        // }
    }

    Ok(res)
}
