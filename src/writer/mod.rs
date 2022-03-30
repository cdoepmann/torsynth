use std::cmp::{max, min};
use std::collections::BTreeMap;

use crate::parser::highlevel::Consensus;
use crate::parser::Flag;

pub fn recompute_bw_weights(consensus: &mut Consensus) {
    let mut Wmd: i64;
    let mut Wed: i64;
    let mut Wgd: i64;
    let mut Wme: i64;
    let mut Wee: i64;
    let mut Wmg: i64;
    let mut Wgg: i64;
    // First, collect the total bandwidth values
    let mut E = 1i64;
    let mut G = 1i64;
    let mut D = 1i64;
    let mut M = 1i64;
    for (_, relay) in consensus.relays.iter() {
        let is_exit = relay.has_flag(Flag::Exit) && !relay.has_flag(Flag::BadExit);
        if is_exit && relay.has_flag(Flag::Guard) {
            D += relay.bandwidth_weight as i64;
        } else if is_exit {
            E += relay.bandwidth_weight as i64;
        } else if relay.has_flag(Flag::Guard) {
            G += relay.bandwidth_weight as i64;
        } else if relay.has_flag(Flag::Guard) {
            M += relay.bandwidth_weight as i64;
        }
    }
    let T = E + G + D + M;
    let weightscale = 10000;

    if 3 * E >= T && 3 * G >= T {
        // Case 1: Neither are scarce
        // casename = "Case 1 (Wgd=Wmd=Wed)"
        Wmd = weightscale / 3;
        Wed = weightscale / 3;
        Wgd = weightscale / 3;
        Wee = (weightscale * (E + G + M)) / (3 * E);
        Wme = weightscale - Wee;
        Wmg = (weightscale * (2 * G - E - M)) / (3 * G);
        Wgg = weightscale - Wmg
    } else if 3 * E < T && 3 * G < T {
        // Case 2: Both Guards and Exits are scarce
        // Balance D between E and G, depending upon D capacity and
        // scarcity
        let R = min(E, G);
        let S = max(E, G);
        if R + D < S {
            // subcase a
            Wgg = weightscale;
            Wee = weightscale;
            Wmd = 0;
            Wme = 0;
            Wmg = 0;
            if E < G {
                // casename = "Case 2a (E scarce)"
                Wed = weightscale;
                Wgd = 0;
            } else {
                // casename = "Case 2a (G scarce)"
                Wed = 0;
                Wgd = weightscale;
            }
        } else {
            // subcase b R+D >= S
            // casename = "Case 2b1 (Wgg=weightscale, Wmd=Wgd)"
            Wee = (weightscale * (E - G + M)) / E;
            Wed = (weightscale * (D - 2 * E + 4 * G - 2 * M)) / (3 * D);
            Wme = (weightscale * (G - M)) / E;
            Wmg = 0;
            Wgg = weightscale;
            Wgd = (weightscale - Wed) / 2;
            Wmd = (weightscale - Wed) / 2;

            if let Some(_) = check_weights_errors(
                Wgg,
                Wgd,
                Wmg,
                Wme,
                Wmd,
                Wee,
                Wed,
                weightscale,
                G,
                M,
                E,
                D,
                T,
                10,
                true,
            ) {
                // casename = 'Case 2b2 (Wgg=weightscale, Wee=weightscale)'
                Wee = weightscale;
                Wgg = weightscale;
                Wed = (weightscale * (D - 2 * E + G + M)) / (3 * D);
                Wmd = (weightscale * (D - 2 * M + G + E)) / (3 * D);
                Wmg = 0;
                Wme = 0;
                if Wmd < 0 {
                    // Too much bandwidth at middle position
                    // casename = 'case 2b3 (Wmd=0)'
                    Wmd = 0;
                }
                Wgd = weightscale - Wed - Wmd;
            }

            match check_weights_errors(
                Wgg,
                Wgd,
                Wmg,
                Wme,
                Wmd,
                Wee,
                Wed,
                weightscale,
                G,
                M,
                E,
                D,
                T,
                10,
                true,
            ) {
                None | Some(BwwError::BalanceMid) => {}
                _ => {
                    panic!("bw weight error");
                }
            }
        }
    } else {
        // if (E < T/3 or G < T/3)
        // Case 3: Guard or Exit is scarce
        let S = min(E, G);

        if 3 * (S + D) < T {
            // subcase a: S+D < T/3
            if G < E {
                // casename = 'Case 3a (G scarce)'
                Wgd = weightscale;
                Wgg = weightscale;
                Wmg = 0;
                Wed = 0;
                Wmd = 0;

                if E < M {
                    Wme = 0;
                } else {
                    Wme = (weightscale * (E - M)) / (2 * E);
                }
                Wee = weightscale - Wme;
            } else {
                // G >= E
                // casename = "Case 3a (E scarce)"
                Wed = weightscale;
                Wee = weightscale;
                Wme = 0;
                Wgd = 0;
                Wmd = 0;
                if G < M {
                    Wmg = 0;
                } else {
                    Wmg = (weightscale * (G - M)) / (2 * G);
                }
                Wgg = weightscale - Wmg;
            }
        } else {
            // subcase S+D >= T/3
            if G < E {
                // casename = 'Case 3bg (G scarce, Wgg=weightscale, Wmd == Wed'
                Wgg = weightscale;
                Wgd = (weightscale * (D - 2 * G + E + M)) / (3 * D);
                Wmg = 0;
                Wee = (weightscale * (E + M)) / (2 * E);
                Wme = weightscale - Wee;
                Wed = (weightscale - Wgd) / 2;
                Wmd = (weightscale - Wgd) / 2;
            } else {
                // G >= E
                // casename = 'Case 3be (E scarce, Wee=weightscale, Wmd == Wgd'
                Wee = weightscale;
                Wed = (weightscale * (D - 2 * E + G + M)) / (3 * D);
                Wme = 0;
                Wgg = (weightscale * (G + M)) / (2 * G);
                Wmg = weightscale - Wgg;
                Wgd = (weightscale - Wed) / 2;
                Wmd = (weightscale - Wed) / 2;
            }
        }
    }

    consensus.weights = BTreeMap::from_iter(
        [
            ("Wbd", Wmd),
            ("Wbe", Wme),
            ("Wbg", Wmg),
            ("Wbm", weightscale),
            ("Wdb", weightscale),
            ("Web", weightscale),
            ("Wed", Wed),
            ("Wee", Wee),
            ("Weg", Wed),
            ("Wem", Wee),
            ("Wgb", weightscale),
            ("Wgd", Wgd),
            ("Wgg", Wgg),
            ("Wgm", Wgg),
            ("Wmb", weightscale),
            ("Wmd", Wmd),
            ("Wme", Wme),
            ("Wmg", Wmg),
            ("Wmm", weightscale),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v as u64)),
    );
    //    /*
    //    * Provide Wgm=Wgg, Wmm=weight_scale, Wem=Wee, Weg=Wed. May later determine
    //    * that middle nodes need different bandwidth weights for dirport traffic,
    //    * or that weird exit policies need special weight, or that bridges
    //    * need special weight.
    //    *
    //    * NOTE: This list is sorted.
    //    */
    //   smartlist_add_asprintf(chunks,
    //     "bandwidth-weights Wbd=%d Wbe=%d Wbg=%d Wbm=%d "
    //     "Wdb=%d "
    //     "Web=%d Wed=%d Wee=%d Weg=%d Wem=%d "
    //     "Wgb=%d Wgd=%d Wgg=%d Wgm=%d "
    //     "Wmb=%d Wmd=%d Wme=%d Wmg=%d Wmm=%d\n",
    //     (int)Wmd, (int)Wme, (int)Wmg, (int)weight_scale,
    //     (int)weight_scale,
    //     (int)weight_scale, (int)Wed, (int)Wee, (int)Wed, (int)Wee,
    //     (int)weight_scale, (int)Wgd, (int)Wgg, (int)Wgg,
    //     (int)weight_scale, (int)Wmd, (int)Wme, (int)Wmg, (int)weight_scale);
}

fn check_eq(a: i64, b: i64, margin: i64) -> bool {
    if (a - b) >= 0 {
        (a - b) <= margin
    } else {
        (b - a) <= margin
    }
}
fn check_range(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, mx: i64) -> bool {
    a >= 0
        && a <= mx
        && b >= 0
        && b <= mx
        && c >= 0
        && c <= mx
        && d >= 0
        && d <= mx
        && e >= 0
        && e <= mx
        && f >= 0
        && f <= mx
        && g >= 0
        && g <= mx
}

#[derive(Debug, PartialEq, Copy, Clone)]
enum BwwError {
    SumD,
    SumG,
    SumE,
    Range,
    BalanceEg,
    BalanceMid,
}

/// Verify that our weights satify the formulas from dir-spec.txt
fn check_weights_errors(
    Wgg: i64,
    Wgd: i64,
    Wmg: i64,
    Wme: i64,
    Wmd: i64,
    Wee: i64,
    Wed: i64,
    weightscale: i64,
    G: i64,
    M: i64,
    E: i64,
    D: i64,
    T: i64,
    margin: i64,
    do_balance: bool,
) -> Option<BwwError> {
    // # Wed + Wmd + Wgd == weightscale
    if !check_eq(Wed + Wmd + Wgd, weightscale, margin) {
        return Some(BwwError::SumD);
    }
    // # Wmg + Wgg == weightscale
    if !check_eq(Wmg + Wgg, weightscale, margin) {
        return Some(BwwError::SumG);
    }
    // # Wme + Wee == weightscale
    if !check_eq(Wme + Wee, weightscale, margin) {
        return Some(BwwError::SumE);
    }
    // # Verify weights within range 0 -> weightscale
    if !check_range(Wgg, Wgd, Wmg, Wme, Wmd, Wed, Wee, weightscale) {
        return Some(BwwError::Range);
    }
    if do_balance {
        // #Wgg*G + Wgd*D == Wee*E + Wed*D
        if !check_eq(Wgg * G + Wgd * D, Wee * E + Wed * D, (margin * T) / 3) {
            return Some(BwwError::BalanceEg);
        }
        // #Wgg*G+Wgd*D == M*weightscale + Wmd*D + Wme * E + Wmg*G
        if !check_eq(
            Wgg * G + Wgd * D,
            M * weightscale + Wmd * D + Wme * E + Wmg * G,
            (margin * T) / 3,
        ) {
            return Some(BwwError::BalanceMid);
        }
    }

    None
}
