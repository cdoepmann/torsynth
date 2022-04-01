//! Handling of IP -> AS lookup as well as sampling from AS IP ranges.

use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::net::Ipv4Addr;
use std::num::ParseIntError;
use std::path::Path;
use std::rc::Rc;

use crate::seeded_rand::get_rng;

use csv;
use rand;
use thiserror;
use treebitmap::IpLookupTable;

#[derive(thiserror::Error, Debug)]
pub enum AsnDbError {
    #[error("I/O error when reading the ASN database file")]
    IoError(#[from] std::io::Error),
    #[error("CSV format error when reading the ASN database file")]
    CsvError(#[from] csv::Error),
    #[error("ASN database file missing columns no. {0}")]
    MissingCsvEntry(usize),
    #[error("Invalid IP range {0}")]
    InvalidIpRange(String),
    #[error("Invalid AS number {0}")]
    InvalidAsNumber(String),
    #[error("Ambigious AS name {0}")]
    AmbigiousAsName(String),
}

pub struct AsnDb {
    as_lookup: IpLookupTable<Ipv4Addr, u32>,
    as_objects: HashMap<u32, Rc<Asn>>, // We use an Rc<_> so we can give out handles to the Asn struct
}

#[derive(Debug)]
pub struct Asn {
    pub number: u32,
    name: String,
    ranges: RefCell<Vec<IpRange>>, // allow mutation during construction
}

impl Asn {
    pub fn sample_ip(&self) -> Ipv4Addr {
        use rand::distributions::WeightedIndex;
        use rand::prelude::*;

        let ranges = self.ranges.borrow();
        if ranges.len() < 1 {
            panic!(
                "AS {} ({}) has no IP range attached",
                &self.number, &self.name
            );
        }

        let dist = WeightedIndex::new(ranges.iter().map(|x| x.len())).unwrap();
        let mut rng = get_rng();
        ranges[dist.sample(&mut rng)].sample_ip()
    }
}

impl PartialEq for Asn {
    fn eq(&self, other: &Asn) -> bool {
        self.number == other.number
    }
}

#[derive(Debug)]
struct IpRange {
    ip: Ipv4Addr,
    masklen: u32,
}

// fn bitmask_left_ones(length: u32) -> u32 {
//     if length > 32 {
//         panic!("Cannot create an u32 bitmask of length {}", length);
//     }
//     let mut res = 0u32;
//     for i in 0..length {
//         res += 1;
//         res <<= 1;
//     }
//     res
// }

// fn bitmask_right_ones(length: u32) -> u32 {
//     !bitmask_left_ones(length)
// }

impl IpRange {
    pub fn new(ip: Ipv4Addr, masklen: u32) -> IpRange {
        if masklen < 1 || masklen > 32 {
            panic!("masklen must be between 1 and 31, but is {}", masklen);
        }

        IpRange { ip, masklen }
    }

    /// Get the number of contained IP addresses
    pub fn len(&self) -> u32 {
        (32u32 - self.masklen).checked_pow(2).unwrap()
    }

    fn to_u32(&self) -> u32 {
        u32::from_be_bytes(self.ip.octets())
    }

    fn index(&self, i: u32) -> Ipv4Addr {
        if i >= self.len() {
            panic!(
                "Cannot get IP range index {} when masklen is only {}",
                i, self.masklen
            );
        };
        Ipv4Addr::from((self.to_u32() + i).to_be_bytes())
    }

    // pub fn first_ip(&self) -> Ipv4Addr {
    //     self.index(0)
    // }

    // pub fn last_ip(&self) -> Ipv4Addr {
    //     self.index(self.len() - 1)
    // }

    pub fn sample_ip(&self) -> Ipv4Addr {
        use rand::prelude::*;

        let mut rng = get_rng();
        let i: u32 = rng.gen_range(0..self.len());
        self.index(i)
    }
}

impl AsnDb {
    pub fn new<P: AsRef<Path>>(geolite_file: P) -> Result<AsnDb, AsnDbError> {
        let file = File::open(geolite_file.as_ref())?;

        let mut rdr = csv::Reader::from_reader(file);

        let mut as_lookup = IpLookupTable::new();
        let mut as_objects: HashMap<u32, Rc<Asn>> = HashMap::new();

        for result in rdr.records() {
            let record = result?;

            let ip_raw = record
                .get(0)
                .ok_or_else(|| AsnDbError::MissingCsvEntry(0))?;
            let ip_error = || AsnDbError::InvalidIpRange(ip_raw.to_string());

            let (ip, masklen) = ip_raw.split_once('/').ok_or_else(ip_error)?;
            let ip: Ipv4Addr = ip.parse().map_err(|_| ip_error())?;
            let masklen: u32 = masklen.parse().map_err(|_| ip_error())?;

            let as_num: u32 = record
                .get(1)
                .ok_or_else(|| AsnDbError::MissingCsvEntry(1))?
                .parse()
                .map_err(|e: ParseIntError| AsnDbError::InvalidAsNumber(e.to_string()))?;
            let as_name = record
                .get(2)
                .ok_or_else(|| AsnDbError::MissingCsvEntry(2))?
                .to_string();

            as_lookup.insert(ip, masklen, as_num);
            match as_objects.entry(as_num) {
                Entry::Occupied(mut old) => {
                    // make sure we're reading the same AS name
                    if old.get().name != as_name {
                        return Err(AsnDbError::AmbigiousAsName(as_name));
                    }
                    // add the IP range
                    old.get_mut()
                        .ranges
                        .borrow_mut()
                        .push(IpRange::new(ip, masklen));
                }
                Entry::Vacant(e) => {
                    e.insert(Rc::new(Asn {
                        ranges: RefCell::new(vec![IpRange::new(ip, masklen)]),
                        name: as_name,
                        number: as_num,
                    }));
                }
            }
        }

        Ok(AsnDb {
            as_lookup,
            as_objects,
        })
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<Rc<Asn>> {
        let asn: &u32 = self.as_lookup.longest_match(ip).map(|(_, _, asn)| asn)?;
        Some(Rc::clone(self.as_objects.get(asn)?))
    }

    /// Sample a random IP address that isn't part of any known AS
    pub fn sample_unknown_ip(&self) -> Ipv4Addr {
        use rand::prelude::*;
        let mut rng = get_rng();

        loop {
            let sample: u32 = rng.gen();
            let ip = Ipv4Addr::from(sample.to_be_bytes());
            // println!("trying {:?}...", ip);
            if let None = self.as_lookup.longest_match(ip) {
                return ip;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_unknown_ip() {
        crate::seeded_rand::set_seed(42);

        let asn_db = AsnDb::new("GeoLite2-ASN-Blocks-IPv4.csv").unwrap();
        let ip = asn_db.sample_unknown_ip();
        assert_eq!(ip, "240.155.61.22".parse::<Ipv4Addr>().unwrap());
    }
}
