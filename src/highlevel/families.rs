use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;

use super::Relay;
use crate::parser::Fingerprint;

#[derive(Debug)]
pub struct Family {
    pub members: Vec<Fingerprint>,
}

/// Make sure that relays who are "connected" over a path of "same-family" relations
/// are also considered to be part of the same family.
pub fn make_cliques(
    family_relations: HashMap<Fingerprint, Vec<Fingerprint>>,
) -> (HashMap<Fingerprint, Option<Rc<Family>>>, Vec<Rc<Family>>) {
    let mut family_relations = family_relations;
    let mut result = HashMap::new();
    let mut families = Vec::new();

    // iterate over all relays
    loop {
        // get an arbitrary entry or break the loop
        let relay = match family_relations.keys().next() {
            None => {
                break;
            }
            Some(k) => k.clone(),
        };
        let all_family_members = remove_transitively(&mut family_relations, relay.clone());

        if all_family_members.len() == 0 {
            result.insert(relay, None);
        } else {
            // the family members include our relay
            // remember mappings from each relay to the common family object
            let family = Family {
                members: all_family_members.into_iter().collect(),
            };
            let rc = Rc::new(family);
            families.push(rc.clone());
            for x in (*rc).members.iter() {
                result.insert(x.clone(), Some(rc.clone()));
            }
        }
    }

    (result, families)
}

/// Remove a fingerprint from the map as well as all of its family members,
/// their family members etc, returning all the fingerprints if the original relay
/// had family members.
fn remove_transitively(
    map: &mut HashMap<Fingerprint, Vec<Fingerprint>>,
    relay: Fingerprint,
) -> HashSet<Fingerprint> {
    let mut map = map;

    // Get the family members and remove the entry
    let mut family_members: HashSet<Fingerprint> = match map.remove(&relay) {
        None => {
            // If the relay was already removed, return nothing
            return HashSet::new();
        }
        Some(x) => x.into_iter().collect(),
    };

    if family_members.len() > 0 {
        // First, include the relay itself
        family_members.insert(relay);

        for member in family_members.clone().into_iter() {
            family_members.extend(remove_transitively(&mut map, member));
        }
    }

    family_members
}

/// Make sure that (1) families only contain relays that mirror this relationship, and
///                (2) relays do not list themselves as family members
pub fn clean_families(family_relations: &mut HashMap<Fingerprint, Vec<Fingerprint>>) {
    let family_relations_copy = family_relations.clone();
    for (this_fingerprint, relay) in family_relations.iter_mut() {
        relay.retain(|fp| {
            let remote_family = &family_relations_copy[fp];
            fp != this_fingerprint && remote_family.contains(this_fingerprint)
        })
    }
}

pub fn size_histogram(families: &Vec<Rc<Family>>) -> Vec<(usize, usize)> {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for family in families.iter() {
        let k = (*family).members.len();
        *counts.entry(k).or_insert(0) += 1;
    }

    counts.into_iter().collect()
}

/// Compute new family objects based on relays' family references. This, e.g.,
/// grows the families if new relays have "joined" the family by having added
/// a reference pointing to that family to their properties.
/// Modifies all relays and also returns the new family objects
pub fn recompute_families(relays: &mut HashMap<Fingerprint, Relay>) -> Vec<Rc<Family>> {
    let mut members = HashMap::<*const Family, Vec<Fingerprint>>::new();
    // collect the members
    for (fp, relay) in relays.iter() {
        if let Some(fam) = &relay.family {
            members.entry(Rc::as_ptr(fam)).or_default().push(fp.clone());
        }
    }
    // make the new objects
    let mut new_families = HashMap::<*const Family, Rc<Family>>::new();
    for (ptr, members) in members.into_iter() {
        new_families.insert(ptr, Rc::new(Family { members }));
    }

    // change relays to point to the new family objects
    for (_, relay) in relays.iter_mut() {
        if let Some(fam) = relay.family.as_mut() {
            *fam = new_families[&Rc::as_ptr(fam)].clone();
        }
    }

    // return the new family objects
    new_families.into_values().collect()
}
