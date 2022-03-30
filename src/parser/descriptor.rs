//! Tor server descriptor documents

use super::DocumentParseError;

use super::meta;
use meta::{Document, Fingerprint};

//
// External dependencies
//
use chrono::{offset::TimeZone, DateTime, Utc};
use derive_builder::Builder;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub enum FamilyMember {
    Fingerprint(Fingerprint),
    Nickname(String),
}

/// A relay server descriptor.
///
/// We here only focus on pieces of information that aren't present in the
/// consensus yet.
#[derive(Debug, Clone, Builder)]
pub struct Descriptor {
    pub nickname: String,
    pub fingerprint: Fingerprint,
    pub digest: Fingerprint,
    pub published: DateTime<Utc>,
    #[builder(default)]
    pub family_members: Vec<FamilyMember>,
}

impl Descriptor {
    /// Construct from an already-parsed Document object
    pub fn from_doc(doc: Document) -> Result<Descriptor, DocumentParseError> {
        let mut builder = DescriptorBuilder::default();

        // compute digest
        builder.digest({
            let content = doc.get_raw_content_between("router", "\nrouter-signature\n")?;
            let mut hasher = Sha1::new();
            hasher.update(content);
            let result = hasher.finalize();
            Fingerprint::from_u8(&result)
        });

        for item in doc.items.iter() {
            match item.keyword {
                "router" => {
                    let splits = item.split_arguments()?;
                    match splits[..] {
                        // nickname address ORPort SOCKSPort DirPort
                        [nickname, _ip, _or_port, _socks_port, _dir_port, ..] => {
                            builder.nickname(nickname.to_string());
                        }
                        _ => {
                            return Err(DocumentParseError::ItemArgumentsMissing {
                                keyword: item.keyword.to_string(),
                            })
                        }
                    }
                }
                "fingerprint" => {
                    let arg = item.get_argument()?;
                    builder.fingerprint(Fingerprint::from_str_hex(arg)?);
                }
                "family" => {
                    let args = item.split_arguments()?;
                    let family_members: Vec<FamilyMember> = args
                        .iter()
                        .map(|x| {
                            if x.starts_with('$') {
                                Ok(FamilyMember::Fingerprint(Fingerprint::from_str_hex(
                                    &x[1..],
                                )?))
                            } else {
                                Ok(FamilyMember::Nickname(x.to_string()))
                            }
                        })
                        .collect::<Result<Vec<FamilyMember>, DocumentParseError>>()?;
                    builder.family_members(family_members);
                }
                "published" => {
                    let arg = item.get_argument()?;
                    builder.published(Utc.datetime_from_str(arg, "%Y-%m-%d %H:%M:%S")?);
                }
                _ => {}
            }
        }

        Ok(builder.build()?)
    }
}
