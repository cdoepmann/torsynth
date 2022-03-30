//! Parser for Tor docs.

use std::error;

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::character::complete::{
    alpha1, alphanumeric1, digit1, line_ending, not_line_ending, space0, space1,
};
use nom::combinator::{all_consuming, map, map_res, opt, peek, recognize};
use nom::multi::{many0, many1};
use nom::sequence::tuple;
use nom::Finish;
use nom::IResult;

use phf::phf_map;
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
}

impl DocumentParseError {
    fn remaining(total_input: &str, remaining_input: &str) -> DocumentParseError {
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
struct VersionedDocumentType {
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
    doctype: VersionedDocumentType,
    items: Vec<Item<'a>>,
}

impl<'a> Document<'a> {
    fn parse(text: &'a str) -> Result<Document<'a>, DocumentParseError> {
        let (i, doc) = Document::nom_parse(text)
            .map_err(|e| e.to_owned())
            .finish()?;

        if !i.is_empty() {
            return Err(DocumentParseError::remaining(text, i));
        }

        Ok(doc)
    }
    fn nom_parse(i: &'a str) -> IResult<&'a str, Document<'a>> {
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
            },
        ))
    }
}

/// A generic item within a Tor doc.
#[derive(Debug)]
struct Item<'a> {
    keyword: &'a str,
    arguments: Option<&'a str>,
    objects: Vec<Object<'a>>,
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
struct Object<'a> {
    keyword: &'a str,
    lines: Vec<&'a str>,
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

#[derive(Debug)]
pub struct ConsensusDocument {}

// pub fn parse_consensus(text: &str) -> Result<ConsensusDocument, Box<dyn error::Error>> {
pub fn parse_consensus(text: &str) -> Result<Document, DocumentParseError> {
    Document::parse(text)
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

    // #[test]
    // fn tmp_nom() {
    //     let i = " abc";
    //     dbg!(many0(alt((nom_parse_keyword, space1)))(i));
    // }
}