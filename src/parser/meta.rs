//! The general meta format for Tor documents

use std::fmt;

use super::error::DocumentParseError;

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::{alphanumeric1, line_ending, not_line_ending, space0, space1};
use nom::combinator::{map, opt, peek, recognize};
use nom::multi::many0;
use nom::sequence::tuple;
use nom::Finish;
use nom::IResult;

// use nom::bytes::complete::{ take_while1};
// use nom::character::complete::{
//     alpha1, digit1,
// };
// use nom::combinator::{all_consuming, map_res};
// use nom::multi::{many1};

use base64;
use phf::phf_map;

/// The type of a Tor document (consensus, router descriptors, etc.)
#[derive(Debug, Clone)]
#[non_exhaustive]
enum DocumentType {
    Consensus,
    ServerDescriptor,
}

static DOCUMENT_TYPE_KEYWORDS: phf::Map<&'static str, DocumentType> = phf_map! {
    "network-status-consensus-3" => DocumentType::Consensus,
    "server-descriptor" => DocumentType::ServerDescriptor,
};

impl DocumentType {
    fn from_str(s: &str) -> Option<DocumentType> {
        DOCUMENT_TYPE_KEYWORDS.get(s).cloned()
    }
}

#[derive(Debug)]
pub struct VersionedDocumentType {
    doctype: DocumentType,
    version: String,
}

impl VersionedDocumentType {
    fn from_str(s: &str) -> VersionedDocumentType {
        let parts: Vec<&str> = s.split(' ').collect();

        VersionedDocumentType {
            doctype: DocumentType::from_str(parts[0]).unwrap(),
            version: parts[1].to_owned(),
        }
    }
}

/// An unspecific Tor document, based on the Tor doc meta format.
/// It does not contain any notion of one of the specific document types
#[derive(Debug)]
pub struct Document<'a> {
    pub doctype: VersionedDocumentType,
    pub items: Vec<Item<'a>>,
    raw_content: &'a str,
}

impl<'a> Document<'a> {
    pub fn parse_single(text: &'a str) -> Result<Document<'a>, DocumentParseError> {
        let (i, doc) = Document::nom_parse(text)
            .map_err(|e| e.to_owned())
            .finish()?;

        if !i.is_empty() {
            return Err(DocumentParseError::remaining(text, i));
        }

        Ok(doc)
    }

    pub fn parse_many(text: &'a str) -> Result<Vec<Document<'a>>, DocumentParseError> {
        let mut docs = Vec::new();
        let mut i = text;
        while !i.is_empty() {
            let (new_i, doc) = Document::nom_parse(i).map_err(|e| e.to_owned()).finish()?;
            i = new_i;

            docs.push(doc);
        }

        Ok(docs)
    }

    fn nom_parse(text: &'a str) -> IResult<&'a str, Document<'a>> {
        let i = text;
        let (i, _) = tag("@")(i)?;
        let (i, _) = peek(tag("type"))(i)?;
        let (i, first_item) = Item::nom_parse(i)?;
        assert_eq!(first_item.keyword, "type");

        let (i, items) = many0(Item::nom_parse)(i)?;
        Ok((
            i,
            Document {
                doctype: VersionedDocumentType::from_str(first_item.arguments.unwrap()),
                items: items,
                raw_content: text,
            },
        ))
    }

    pub fn get_raw_content_between(
        &'a self,
        start: &str,
        end: &str,
    ) -> Result<&'a [u8], DocumentParseError> {
        let start_pos = self.raw_content.find(start).ok_or_else(|| {
            DocumentParseError::ContentRangeNotFound {
                from: start.to_string(),
                to: end.to_string(),
            }
        })?;
        let end_pos =
            self.raw_content
                .find(end)
                .ok_or_else(|| DocumentParseError::ContentRangeNotFound {
                    from: start.to_string(),
                    to: end.to_string(),
                })?;
        Ok(&self.raw_content.as_bytes()[start_pos..end_pos + end.len()])
    }
}

/// A generic item within a Tor doc.
#[derive(Debug)]
pub struct Item<'a> {
    pub keyword: &'a str,
    pub arguments: Option<&'a str>,
    pub objects: Vec<Object<'a>>,
}

impl<'a> Item<'a> {
    fn nom_parse(i: &'a str) -> IResult<&str, Item<'a>> {
        // first line (keyword and, optionally, args)
        let (i, kw) = nom_parse_keyword(i)?;
        let (i, _) = space0(i)?;
        let (i, args) = opt(not_line_ending)(i)?;
        let (i, _) = line_ending(i)?;

        // get objects following the first line
        let (i, objs) = many0(Object::nom_parse)(i)?;

        // return everything
        Ok((
            i,
            Item {
                keyword: kw,
                arguments: args,
                objects: objs,
            },
        ))
    }

    pub fn split_arguments(&self) -> Result<Vec<&str>, DocumentParseError> {
        self.arguments
            .ok_or_else(|| DocumentParseError::ItemArgumentsMissing {
                keyword: self.keyword.to_string(),
            })
            .map(|x| x.split(' ').collect())
    }

    pub fn get_argument(&self) -> Result<&str, DocumentParseError> {
        self.arguments
            .ok_or_else(|| DocumentParseError::ItemArgumentsMissing {
                keyword: self.keyword.to_string(),
            })
    }
}

fn nom_parse_keyword(i: &str) -> IResult<&str, &str> {
    // `recognize` is used to aggregate the different steps and turn their
    // consumed input into the overall output
    recognize(|i| {
        let (i, _) = alphanumeric1(i)?;
        let (i, _) = take_while(|c| char::is_alphanumeric(c) || c == '-')(i)?;
        Ok((i, ()))
    })(i)
}

/// A multi-line object within a Tor document (e.g. a cryptographic key).
#[derive(Debug)]
pub struct Object<'a> {
    pub keyword: &'a str,
    pub lines: Vec<&'a str>,
}

impl<'a> Object<'a> {
    fn nom_parse(i: &'a str) -> IResult<&'a str, Object<'a>> {
        let (i, _) = tag("-----BEGIN ")(i)?;
        let (i, keyword) = recognize(many0(alt((alphanumeric1, space1))))(i)?;
        let (i, _) = tag("-----")(i)?;
        let (i, _) = line_ending(i)?;

        // helper function to get either the next object line or find the end
        let line_or_end = |i: &'a str| -> IResult<&'a str, Option<&'a str>> {
            let (i, line) = alt((
                // If this line ends the object, return None
                map(
                    tuple((tag("-----END "), tag(keyword), tag("-----"))),
                    |_| None,
                ),
                // Otherwise, return this line as Some(...)
                map(not_line_ending, |x: &str| Some(x)),
            ))(i)?;
            let (i, _) = line_ending(i)?;
            Ok((i, line))
        };

        let mut lines = Vec::new();
        let (i, _) = {
            let mut i = i;
            loop {
                let (this_i, this_line) = line_or_end(i)?;
                i = this_i;
                if let Some(l) = this_line {
                    lines.push(l);
                } else {
                    break;
                }
            }
            (i, ())
        };

        Ok((i, Object { keyword, lines }))
    }
}

/// A relay fingerprint
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    blob: Vec<u8>,
}

impl Fingerprint {
    pub fn from_str_b64(raw_b64: &str) -> Result<Fingerprint, DocumentParseError> {
        Ok(Fingerprint {
            blob: base64::decode(raw_b64)?,
        })
    }
    pub fn from_str_hex(mut raw_hex: &str) -> Result<Fingerprint, DocumentParseError> {
        let mut blob = Vec::new();
        while raw_hex.len() > 0 {
            raw_hex = raw_hex.trim_start();
            let byte = u8::from_str_radix(&raw_hex[..2], 16)?;
            blob.push(byte);
            raw_hex = &raw_hex[2..];
        }

        Ok(Fingerprint { blob })
    }
    pub fn from_u8(raw: &[u8]) -> Fingerprint {
        Fingerprint { blob: raw.to_vec() }
    }

    pub fn to_string_b64(&self) -> String {
        base64::encode(&self.blob).trim_end_matches('=').to_string()
    }

    pub fn to_string_hex(&self) -> String {
        format!("{}", self)
    }

    pub fn to_string_hex_blocks(&self) -> String {
        use std::fmt::Write;

        let mut res = String::new();
        let mut iter = self.blob.chunks(2).peekable();

        loop {
            let chunk = match iter.next() {
                Some(x) => x,
                None => {
                    break;
                }
            };

            for byte in chunk {
                write!(&mut res, "{:02X}", byte).unwrap();
            }
            if let Some(_) = iter.peek() {
                write!(&mut res, " ").unwrap();
            }
        }
        res
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.blob {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_item_with_objects() {
        let doc = concat!(
            "directory-signature 0232AF901C31A04EE9848595AF9BB7620D4C5B2E 491466AA6B52156E455D9B545242C21D16A6880A\n",
            "-----BEGIN SIGNATURE-----\n",
            "PlYR25xXpuO75eQTnqUx/FX3ZDayW4Ciy5YwF0p0yEv/ApfkZfg6frfwILgm/U/c\n",
            "uJ26tHJFgbd51D4FdWg7aFrcfi82X4b/Qm9tpBnsYwBA0+fR9k/EoUtLCIu3gjRk\n",
            "SvXUGw2MESx/67k2iZe0QltAOUfeARWVv2YA2wWQJzQUiaF65QNaJbl/z1CZVKCe\n",
            "t6VgKT5ausx+9TUxIhU0XY6ZykM4JoOIm+5UT1RpX3j+9GfqiOVgZ5xHsy9Ecpd1\n",
            "GNOMBrvH26DcSWQY8zyINOaJYQJUc32noWvBnauupgcPjnv2H/m1L2LNtR2Z7/MW\n",
            "emvxrFWCWKPT4NZ2uVlkSQ==\n",
            "-----END SIGNATURE-----\n",
            "-----BEGIN RSA PUBLIC KEY-----\n",
            "PlYR25xXpuO75eQTnqUx/FX3ZDayW4Ciy5YwF0p0yEv/ApfkZfg6frfwILgm/U/c\n",
            "uJ26tHJFgbd51D4FdWg7aFrcfi82X4b/Qm9tpBnsYwBA0+fR9k/EoUtLCIu3gjRk\n",
            "SvXUGw2MESx/67k2iZe0QltAOUfeARWVv2YA2wWQJzQUiaF65QNaJbl/z1CZVKCe\n",
            "t6VgKT5ausx+9TUxIhU0XY6ZykM4JoOIm+5UT1RpX3j+9GfqiOVgZ5xHsy9Ecpd1\n",
            "GNOMBrvH26DcSWQY8zyINOaJYQJUc32noWvBnauupgcPjnv2H/m1L2LNtR2Z7/MW\n",
            "emvxrFWCWKPT4NZ2uVlkSQ==\n",
            "-----END RSA PUBLIC KEY-----\n"
        );

        let (remaining, item) = Item::nom_parse(doc).unwrap();
        assert_eq!(remaining, "");
        assert_eq!(item.keyword, "directory-signature");
        assert_eq!(item.objects[0].keyword, "SIGNATURE");
        assert_eq!(item.objects[1].keyword, "RSA PUBLIC KEY");
    }

    #[test]
    fn test_fingerprint_hex() {
        assert_eq!(
            Fingerprint::from_str_hex("12FF 0B42").unwrap(),
            Fingerprint {
                blob: vec![0x12, 0xff, 0x0b, 0x42]
            }
        );
    }
}
