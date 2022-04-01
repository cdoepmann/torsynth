//! Algorithms for scaling Tor consensuses.

use std::collections::HashMap;
use std::rc::Rc;

use rand::distributions::weighted::WeightedError;
use rand::seq::SliceRandom;
use rand::Rng;

use super::asn::{Asn, AsnDb};
use super::families::{self, Family};
use super::{Consensus, Relay};
use crate::parser::consensus::Flag;
use crate::parser::Fingerprint;
use crate::seeded_rand::get_rng;

pub fn scale_horizontally(
    consensus: &mut Consensus,
    scale: f32,
    exit_factor: Option<f32>,
    guard_factor: Option<f32>,
    asn_db: &AsnDb,
    prob_family_new: f32,
) {
    if scale < 1.0 {
        unimplemented!("For now, horizontal scaling can only scale _up_");
    }

    let mut rng = get_rng();
    let exit_factor = exit_factor.unwrap_or(1.0);
    let guard_factor = guard_factor.unwrap_or(1.0);

    if exit_factor < 0.0 {
        panic!("exit factor cannot be negative.");
    }
    if guard_factor < 0.0 {
        panic!("exit factor cannot be negative.");
    }
    if prob_family_new < 0.0 || prob_family_new > 1.0 {
        panic!("probability for new families must be between 0 and 1.");
    }
    // number of relays
    let num_relays_before = consensus.relays.len() as u32;
    let num_relays_after = (num_relays_before as f32 * scale).round() as u32;
    let num_new_relays = num_relays_after - num_relays_before;

    println!("Current relays: {:7}", num_relays_before);
    println!("Scale:          {:7.3}", scale);
    println!("New relays:     {:7}", num_new_relays);

    // It's easier to work with a Vec of relays...
    let old_relays: Vec<&Relay> = consensus.relays.values().collect();
    // use precomputed family stats from the consensus
    let prob_family = consensus.prob_family;
    let prob_family_sameas = consensus.prob_family_sameas;

    // Determine weights of the relays to accommodate exit and guard weight factors.
    let flag_weights =
        FlagWeights::from_flag_factors_by_number(&old_relays, 1.0, exit_factor, guard_factor);

    // list of results, helpers, etc.
    let mut new_relays_with_family = Vec::new(); // still need customization except for the family
    let mut new_relays_needing_family = Vec::new(); // still need customization incl. family
    let mut created_relays = 0u32;

    // Generate the relays
    while created_relays < num_new_relays {
        // - use bandwdith, flags, exit policy etc. of the selected relay
        // - for controlling the exit and guard scale factor, give the existing
        //   relays with these flags the appropriate weight

        // First, roll the dice on the family properties of our relay

        // should this relay be part of a family?
        let in_family = rng.gen_bool(prob_family as f64);
        // if in a family, should this relay be part of a _new_ family?
        let new_family = rng.gen_bool(prob_family_new as f64);
        // if it should use an existing family, should it be of the same AS?
        let same_as = rng.gen_bool(prob_family_sameas as f64);

        // choose a base relay
        let chosen_relay = RelaySampler::with_flag_weights(&old_relays, &flag_weights).sample();

        if in_family {
            // this relay shall belong to a family
            if new_family {
                // create a family for it later
                new_relays_needing_family.push(chosen_relay.clone());
            } else {
                // The relay should join an existing family. For this, we need a
                // reference relay that has a family and does match our previously
                // decided property of being from the same AS or not.
                let family_ref_relay = if chosen_relay.family.is_some() && same_as {
                    chosen_relay
                } else {
                    let mut sampler = RelaySampler::unbiased(&old_relays).has_family(true);
                    if same_as {
                        // This may fail if there is no relay with a family in this AS.
                        // In this case, start all over again
                        sampler.set_only_from_as(chosen_relay.asn.clone());
                        match sampler.sample_checked() {
                            Ok(r) => r,
                            Err(e) => {
                                assert_eq!(e, WeightedError::AllWeightsZero);
                                // continue without having created a new relay
                                // println!(
                                //     "no relay with family in AS {}",
                                //     chosen_relay.asn.as_ref().map(|x| x.number).unwrap_or(0)
                                // );
                                continue;
                            }
                        }
                    } else {
                        sampler.set_not_from_as(chosen_relay.asn.clone());
                        sampler.sample()
                    }
                };
                let mut new_relay = chosen_relay.clone();
                new_relay.family = family_ref_relay.family.clone();
                new_relays_with_family.push(new_relay);
            }
        } else {
            // this relay shall not belong to a family
            let mut new_relay = chosen_relay.clone();
            new_relay.family = None;
            new_relays_with_family.push(new_relay.clone());
        }
        created_relays += 1;
    }
    // Customize the relays. We need to do this here because they need to have
    // their final fingerprints for constructing families later.
    let mut customizer = Customizer::new(asn_db);
    for haystack in [&mut new_relays_with_family, &mut new_relays_needing_family] {
        for relay in haystack.iter_mut() {
            customizer.customize_relay(relay);
        }
    }
    // Create new families as necessary.
    // Sample sizes of the new families. Repeat as often as necessary until it
    // matches the number of relays. Otherwise, we would discriminate large
    // familly sizes that might only be possible in the beginning
    let new_family_sizes = if new_relays_needing_family.len() > 0 {
        let family_sizes: Vec<_> = consensus
            .family_sizes
            .iter()
            .map(|(x, _)| x)
            .copied()
            .collect();
        let family_size_frequencies =
            HashMap::<usize, usize>::from_iter(consensus.family_sizes.iter().copied());
        'outer: loop {
            let mut remaining = new_relays_needing_family.len();
            let mut sizes = Vec::new();
            loop {
                let size = family_sizes[..]
                    .choose_weighted(&mut rng, |size| family_size_frequencies[size])
                    .unwrap();
                let size = *size;
                if size > remaining {
                    // We have to try again
                    continue 'outer;
                }
                sizes.push(size);
                remaining -= size;
                if remaining == 0 {
                    break 'outer sizes;
                }
            }
        }
    } else {
        // no relays with new family
        Vec::new()
    };

    let mut new_families = Vec::<Rc<Family>>::new();
    for family_size in new_family_sizes {
        // Create a family with a given size
        let mut current_members = Vec::new();
        // Add any relay as the first family member
        current_members.push(new_relays_needing_family.pop().unwrap());
        // Then add the other members
        while current_members.len() < family_size {
            let ref_member = current_members[..].choose(&mut rng).unwrap();
            let same_as = rng.gen_bool(prob_family_sameas as f64);

            // get a new family member that satisfies the AS relation if possible
            let new_relays_needing_family_ref: Vec<_> = new_relays_needing_family.iter().collect();
            let new_member = {
                let mut sampler = RelaySampler::unbiased(&new_relays_needing_family_ref);

                if same_as {
                    sampler.set_only_from_as(ref_member.asn.clone());
                } else {
                    sampler.set_not_from_as(ref_member.asn.clone());
                }
                match sampler.sample_checked() {
                    Ok(r) => r,
                    Err(e) => {
                        assert_eq!(e, WeightedError::AllWeightsZero);
                        // sample again without AS restriction
                        // println!("have to ignore AS restriction once (same AS: {})", same_as);
                        RelaySampler::unbiased(&new_relays_needing_family_ref).sample()
                    }
                }
            };
            let position = new_relays_needing_family
                .iter()
                .position(|x| x as *const Relay == new_member as *const Relay)
                .unwrap();
            let new_member = new_relays_needing_family.swap_remove(position);
            current_members.push(new_member);
        }
        let family = Rc::new(Family {
            members: current_members
                .iter()
                .map(|r| r.fingerprint.clone())
                .collect(),
        });

        for relay in current_members.iter_mut() {
            relay.family = Some(family.clone());
        }
        new_relays_with_family.extend(current_members);
        new_families.push(family);
    }

    // Lastly, integrate the new relays and families into the consensus object
    consensus.families.extend(new_families);
    for relay in new_relays_with_family {
        consensus.relays.insert(relay.fingerprint.clone(), relay);
    }

    // Adapt family objects with new relays, changing the relays' family references
    consensus.families = families::recompute_families(&mut consensus.relays);

    // Make sure all metrics are correct again
    consensus.recompute_bw_weights();
    consensus.recompute_stats();

    // println!(
    //     "New relay: {} {:?}",
    //     &new_relay.fingerprint, &new_relay.flags
    // );
}

struct Customizer<'a> {
    fingerprint_generator: FingerprintGenerator,
    nickname_generator: NicknameGenerator,
    asn_db: &'a AsnDb,
}

impl<'a> Customizer<'a> {
    fn new(asn_db: &'a AsnDb) -> Customizer<'a> {
        Customizer {
            fingerprint_generator: FingerprintGenerator::new(),
            nickname_generator: NicknameGenerator::new(),
            asn_db,
        }
    }

    fn customize_relay(&mut self, relay: &mut Relay) {
        // customize the new relay
        let fingerprint = Fingerprint::from_u8(self.fingerprint_generator.get_fingerprint());
        //  loop {
        //     let x = Fingerprint::from_u8(self.fingerprint_generator.get_fingerprint());
        //     if consensus.relays.contains_key(&x) {
        //         continue;
        //     }
        //     break x;
        // };
        relay.fingerprint = fingerprint;
        relay.nickname = self.nickname_generator.get_nickname();
        relay.address = match &relay.asn {
            Some(asn) => asn.sample_ip(),
            None => self.asn_db.sample_unknown_ip(),
        };
    }
}

struct RelaySampler<'r> {
    relays: &'r Vec<&'r Relay>,
    flag_weights: FlagWeights,
    custom_weights: Vec<Box<dyn 'r + Fn(&Relay) -> Option<f32>>>,
}

impl<'r> RelaySampler<'r> {
    fn unbiased(relays: &'r Vec<&'r Relay>) -> RelaySampler<'r> {
        RelaySampler::with_flag_weights(relays, &FlagWeights::unbiased())
    }

    fn with_flag_weights(
        relays: &'r Vec<&'r Relay>,
        flag_weights: &FlagWeights,
    ) -> RelaySampler<'r> {
        let flag_weights = flag_weights.clone();
        RelaySampler {
            relays,
            flag_weights,
            custom_weights: Vec::new(),
        }
    }

    fn add_custom_weight<F: 'r + Fn(&Relay) -> Option<f32>>(&mut self, f: F) {
        self.custom_weights.push(Box::new(f));
    }

    fn only_from_as(mut self, asn: Option<Rc<Asn>>) -> Self {
        self.set_only_from_as(asn);
        self
    }

    fn set_only_from_as(&mut self, asn: Option<Rc<Asn>>) {
        self.add_custom_weight(move |r| if r.asn == asn { None } else { Some(0.0) });
    }

    fn not_from_as(mut self, asn: Option<Rc<Asn>>) -> Self {
        self.set_not_from_as(asn);
        self
    }

    fn set_not_from_as(&mut self, asn: Option<Rc<Asn>>) {
        self.add_custom_weight(move |r| if r.asn != asn { None } else { Some(0.0) });
    }

    fn has_family(mut self, yesno: bool) -> Self {
        self.set_has_family(yesno);
        self
    }

    fn set_has_family(&mut self, yesno: bool) {
        self.add_custom_weight(move |r| {
            if r.family.is_some() == yesno {
                None
            } else {
                Some(0.0)
            }
        });
    }

    fn sample(&self) -> &'r Relay {
        self.sample_checked().unwrap()
    }

    fn sample_checked(&self) -> Result<&'r Relay, WeightedError> {
        let mut rng = get_rng();
        let chosen_relay = self.relays[..]
            .choose_weighted(&mut rng, |relay| {
                let mut weight = self.flag_weights.get_relay_weight(relay);
                for custom_weight in self.custom_weights.iter() {
                    if let Some(w) = custom_weight(relay) {
                        weight = w;
                    }
                }
                weight
            })
            .map(|x| *x);
        chosen_relay
    }
}

/// Container for relay weights depending on their flags
#[derive(Debug, Clone)]
struct FlagWeights {
    weight_e: f32,
    weight_g: f32,
    weight_d: f32,
    weight_m: f32,
}

impl FlagWeights {
    /// Default weights without favoring any class
    fn unbiased() -> FlagWeights {
        FlagWeights {
            weight_e: 1.0,
            weight_g: 1.0,
            weight_d: 1.0,
            weight_m: 1.0,
        }
    }

    fn from_flag_factors_by_number(
        relays: &Vec<&Relay>,
        middle_factor: f32,
        exit_factor: f32,
        guard_factor: f32,
    ) -> FlagWeights {
        // Count relays per class (E, G, D, M)
        let n_e = relays
            .iter()
            .filter(|x| x.has_flag(Flag::Exit) && !x.has_flag(Flag::Guard))
            .count();
        let n_g = relays
            .iter()
            .filter(|x| !x.has_flag(Flag::Exit) && x.has_flag(Flag::Guard))
            .count();
        let n_d = relays
            .iter()
            .filter(|x| x.has_flag(Flag::Exit) && x.has_flag(Flag::Guard))
            .count();
        let n_m = relays
            .iter()
            .filter(|x| !x.has_flag(Flag::Exit) && !x.has_flag(Flag::Guard))
            .count();

        FlagWeights::from_flag_factors_by_value(
            middle_factor,
            exit_factor,
            guard_factor,
            n_e as f32,
            n_g as f32,
            n_d as f32,
            n_m as f32,
        )
    }

    fn from_flag_factors_by_bandwidth(
        relays: &Vec<&Relay>,
        middle_factor: f32,
        exit_factor: f32,
        guard_factor: f32,
    ) -> FlagWeights {
        // Sum up relay bandwidth per class (E, G, D, M)
        let n_e = relays
            .iter()
            .filter(|x| x.has_flag(Flag::Exit) && !x.has_flag(Flag::Guard))
            .map(|x| x.bandwidth_weight as f32)
            .sum();
        let n_g = relays
            .iter()
            .filter(|x| !x.has_flag(Flag::Exit) && x.has_flag(Flag::Guard))
            .map(|x| x.bandwidth_weight as f32)
            .sum();
        let n_d = relays
            .iter()
            .filter(|x| x.has_flag(Flag::Exit) && x.has_flag(Flag::Guard))
            .map(|x| x.bandwidth_weight as f32)
            .sum();
        let n_m = relays
            .iter()
            .filter(|x| !x.has_flag(Flag::Exit) && !x.has_flag(Flag::Guard))
            .map(|x| x.bandwidth_weight as f32)
            .sum();

        FlagWeights::from_flag_factors_by_value(
            middle_factor,
            exit_factor,
            guard_factor,
            n_e,
            n_g,
            n_d,
            n_m,
        )
    }

    /// Compute weights that accommodate factors for exit and guard growth
    fn from_flag_factors_by_value(
        middle_factor: f32,
        exit_factor: f32,
        guard_factor: f32,
        n_e: f32,
        n_g: f32,
        n_d: f32,
        _n_m: f32,
    ) -> FlagWeights {
        // Determine weights of the relays to accommodate exit and guard weight factors.
        // The ratios can be reached with any value chosen for weight_d (simple example:
        // always set it to 0). However, we also have the constraint that the weights
        // are not allowed to be negative, so we have to choose weight_d accordingly.
        // To do so, first set the _smaller_ of these factors for both of the respective
        // class of relays (G/E and D), then compute the other one so that it works
        // out. By setting the smaller factor first, we can be sure that the other
        // one will not become negative.
        let weight_m = middle_factor;
        let (weight_g, weight_e, weight_d) = if guard_factor <= exit_factor {
            let weight_g = guard_factor;
            let weight_d = guard_factor;
            let weight_e =
                (exit_factor * ((n_e + n_d) as f32) - guard_factor * (n_d as f32)) / (n_e as f32);
            (weight_g, weight_e, weight_d)
        } else {
            let weight_e = exit_factor;
            let weight_d = exit_factor;
            let weight_g =
                (guard_factor * ((n_g + n_d) as f32) - exit_factor * (n_d as f32)) / (n_g as f32);
            (weight_g, weight_e, weight_d)
        };

        FlagWeights {
            weight_e,
            weight_g,
            weight_d,
            weight_m,
        }
    }

    fn get_relay_weight(&self, relay: &Relay) -> f32 {
        if relay.has_flag(Flag::Exit) && !relay.has_flag(Flag::Guard) {
            self.weight_e
        } else if !relay.has_flag(Flag::Exit) && relay.has_flag(Flag::Guard) {
            self.weight_g
        } else if relay.has_flag(Flag::Exit) && relay.has_flag(Flag::Guard) {
            self.weight_d
        } else {
            // !relay.has_flag(Flag::Exit) && !relay.has_flag(Flag::Guard)
            self.weight_m
        }
    }
}

struct FingerprintGenerator {
    state: Vec<u8>,
}

impl FingerprintGenerator {
    fn new() -> FingerprintGenerator {
        FingerprintGenerator {
            state: vec![0u8; 40],
        }
    }

    fn get_fingerprint(&mut self) -> &[u8] {
        self.inc();
        &self.state
    }

    fn inc(&mut self) {
        for digit in self.state.iter_mut().rev() {
            if *digit < u8::MAX {
                *digit += 1;
                return;
            }
            *digit = 0;
        }
        panic!("Fingerprint generator has overflown.")
    }
}

struct NicknameGenerator {
    num: u64,
}

impl NicknameGenerator {
    fn new() -> NicknameGenerator {
        NicknameGenerator { num: 1 }
    }

    fn get_nickname(&mut self) -> String {
        self.inc();
        format!("torscaler-dsi-{}", self.num)
    }

    fn inc(&mut self) {
        self.num += 1;
    }
}

// - total scale
//   - distribution by bandwidth weight (relative)
//   - weigh by flag
// - scale exits
// - scale guards
// - scale middle relays

/*
    --vertical-network-scale
        --weigh-by-bandwidth
        (--weigh-by-flag)
CONFLICT WITH
    --vertical-guard-scale
    --vertical-exit-scale
    --vertical-middle-scale
*/

// pub struct RelativeDistribution {}

pub fn scale_vertically_by_bandwidth_rank(
    consensus: &mut Consensus,
    // bandwidth_distribution: Option<RelativeDistribution>,
    scale_per_bandwidth: Vec<f32>,
) {
    let mut relays: Vec<_> = consensus.relays.values().collect();
    let num_relays = relays.len();
    let num_groups = scale_per_bandwidth.len();

    if num_groups < 1 {
        panic!("For scaling by bandwidth, at least one scale factor is needed.");
    }
    if num_relays < num_groups {
        panic!("Cannot scale with more bandwidth groups than relays.");
    }

    relays.sort_unstable_by_key(|r| r.bandwidth_weight);
    let mut bandwidth_to_scale: HashMap<Fingerprint, f32> = HashMap::new();
    let last_scale = *(scale_per_bandwidth.last().unwrap());
    for (scale, group_relays) in scale_per_bandwidth
        .into_iter()
        .chain([last_scale]) // use the last value for the remaining elements
        .zip(relays.chunks(num_relays / num_groups))
    {
        for r in group_relays {
            bandwidth_to_scale.insert(r.fingerprint.clone(), scale);
        }
    }
    scale_vertically_by(consensus, |relay: &Relay| -> f32 {
        bandwidth_to_scale[&relay.fingerprint]
    });
}

pub fn scale_flag_groups_vertically(
    consensus: &mut Consensus,
    middle_scale: f32,
    exit_scale: f32,
    guard_scale: f32,
) {
    // Calculate the specific weights to accommodate relays that are
    // guards and exits at the same time. We are vertically scaling the
    // _groups_ of relays (their bandwidth).
    let relays: Vec<_> = consensus.relays.values().collect();
    let flag_weights =
        FlagWeights::from_flag_factors_by_bandwidth(&relays, middle_scale, exit_scale, guard_scale);

    let relay_weights = |relay: &Relay| -> f32 { flag_weights.get_relay_weight(relay) };
    scale_vertically_by(consensus, relay_weights);
}

/// Scale a consensus given a function that defines each relay's scale factor
fn scale_vertically_by<F: Fn(&Relay) -> f32>(consensus: &mut Consensus, relay_scale: F) {
    for relay in consensus.relays.values_mut() {
        relay.bandwidth_weight = ((relay.bandwidth_weight as f32) * relay_scale(relay)) as u64;
    }

    // Make sure all metrics are correct again
    consensus.recompute_bw_weights();
    consensus.recompute_stats();
}
