// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The top-level `groups:` block - THE one limit tree (CLEAN-CONFIG S3). A group is a named
//! enforcement bucket: an ordered list of generic LIMITS plus an optional `parent` forming an
//! acyclic chain (depth <= 8, validated). Enforcement (P4) walks the chain and ANDs every bucket;
//! `enabled: false` freezes a group (history kept). Keys are PURE AUTH and carry no limits - a key
//! binds to at most one group (`group:` at mint), and a key with no group is authed + unlimited.
//!
//! A limit is `{ <metric>: <amount>, per: <window> }` with exactly ONE metric key:
//!
//! ```yaml
//! limits:
//!   - { requests: 500, per: minute }
//!   - { budget: 1000000, per: month }
//!   - { concurrent: 5 }              # instantaneous - no `per`
//! ```
//!
//! metrics: `requests` | `tokens` | `budget` | `concurrent`. windows (C8, nouns):
//! `minute` | `hour` | `day` | `month` | `total`. `concurrent` is an in-flight gauge and takes NO
//! `per`; the three windowed metrics REQUIRE one (a windowless cap is ambiguous - fail loudly).

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

/// One `groups:` entry.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupCfg {
    /// Optional parent group, forming the enforcement chain (acyclic, depth <= 8; validated at
    /// boot / `--validate`).
    #[serde(default)]
    pub(crate) parent: Option<String>,
    /// `false` FREEZES the group: every request charging through it is rejected while its history
    /// is kept (C10). Default `true`.
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    /// The group's limits, enforced together (AND). Order preserved (C9: ordered list).
    #[serde(default)]
    pub(crate) limits: Vec<LimitCfg>,
}

fn default_true() -> bool {
    true
}

/// The metric a limit caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitMetric {
    /// Request count per window.
    Requests,
    /// Total tokens (all tiers) per window.
    Tokens,
    /// Spend (cents, abstract minor units, derived from the ledger x rate_card) per window.
    Budget,
    /// In-flight request gauge - instantaneous, no window.
    Concurrent,
}

impl LimitMetric {
    /// The config spelling (also the metrics/error vocabulary).
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            LimitMetric::Requests => "requests",
            LimitMetric::Tokens => "tokens",
            LimitMetric::Budget => "budget",
            LimitMetric::Concurrent => "concurrent",
        }
    }
}

/// A limit's accounting window (C8: nouns only).
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LimitWindow {
    Minute,
    Hour,
    Day,
    Month,
    Total,
}

impl LimitWindow {
    /// The config spelling - ALSO the runtime window-period sentinel (`governance::budget_window`
    /// matches these exact strings) and the metrics/error vocabulary. One vocabulary everywhere.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            LimitWindow::Minute => "minute",
            LimitWindow::Hour => "hour",
            LimitWindow::Day => "day",
            LimitWindow::Month => "month",
            LimitWindow::Total => "total",
        }
    }
}

/// One parsed limit: exactly one metric key + its amount, plus the window for windowed metrics.
/// The `{ <metric>: amount, per: window }` shape is enforced at DESERIALIZE time (not a later
/// validation pass), so a malformed limit fails with a precise error at parse.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct LimitCfg {
    pub(crate) metric: LimitMetric,
    pub(crate) amount: u64,
    /// `Some` for `requests`/`tokens`/`budget` (required); ALWAYS `None` for `concurrent`.
    pub(crate) per: Option<LimitWindow>,
}

impl<'de> Deserialize<'de> for LimitCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LimitVisitor;

        impl<'de> Visitor<'de> for LimitVisitor {
            type Value = LimitCfg;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a limit map `{ <metric>: <amount>, per: <window> }` where <metric> is one of \
                     requests|tokens|budget|concurrent and <window> one of \
                     minute|hour|day|month|total (omit `per` for concurrent)",
                )
            }

            fn visit_map<A>(self, mut map: A) -> Result<LimitCfg, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut metric: Option<(LimitMetric, u64)> = None;
                let mut per: Option<LimitWindow> = None;

                while let Some(key) = map.next_key::<String>()? {
                    let named = match key.as_str() {
                        "requests" => Some(LimitMetric::Requests),
                        "tokens" => Some(LimitMetric::Tokens),
                        "budget" => Some(LimitMetric::Budget),
                        "concurrent" => Some(LimitMetric::Concurrent),
                        "per" => {
                            if per.is_some() {
                                return Err(de::Error::duplicate_field("per"));
                            }
                            per = Some(map.next_value()?);
                            None
                        }
                        other => {
                            return Err(de::Error::unknown_field(
                                other,
                                &["requests", "tokens", "budget", "concurrent", "per"],
                            ));
                        }
                    };
                    if let Some(m) = named {
                        if let Some((prev, _)) = metric {
                            return Err(de::Error::custom(format!(
                                "a limit takes exactly ONE metric key; found both '{}' and '{}'",
                                prev.as_str(),
                                m.as_str()
                            )));
                        }
                        metric = Some((m, map.next_value()?));
                    }
                }

                let Some((metric, amount)) = metric else {
                    return Err(de::Error::custom(
                        "a limit needs exactly one metric key \
                         (requests | tokens | budget | concurrent)",
                    ));
                };

                match (metric, per) {
                    (LimitMetric::Concurrent, Some(_)) => Err(de::Error::custom(
                        "`concurrent` is an instantaneous in-flight cap and takes NO `per:` \
                         window; remove `per`",
                    )),
                    (LimitMetric::Concurrent, None) => Ok(LimitCfg {
                        metric,
                        amount,
                        per: None,
                    }),
                    (_, None) => Err(de::Error::custom(format!(
                        "a `{}` limit requires a `per:` window \
                         (minute | hour | day | month | total)",
                        metric.as_str()
                    ))),
                    (_, Some(window)) => Ok(LimitCfg {
                        metric,
                        amount,
                        per: Some(window),
                    }),
                }
            }
        }

        deserializer.deserialize_map(LimitVisitor)
    }
}

/// Serialize mirrors the custom deserializer: a limit is a map with its ONE metric key + amount, plus
/// `per: <window>` for the windowed metrics (never for `concurrent`). This is what lets a group survive
/// in the config OVERLAY (the Admin-API-mutable persistence layer): the round-trip `{ budget: 1000,
/// per: month }` -> LimitCfg -> `{ budget: 1000, per: month }` is exact, so an API-applied group budget
/// re-parses identically at boot. Deliberately hand-written (not derived) so it can never drift from the
/// `{ <metric>: <amount>, per: <window> }` shape the deserializer enforces.
impl Serialize for LimitCfg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = if self.per.is_some() { 2 } else { 1 };
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry(self.metric.as_str(), &self.amount)?;
        if let Some(window) = self.per {
            map.serialize_entry("per", window.as_str())?;
        }
        map.end()
    }
}

/// Validate the whole `groups:` tree: parents exist, acyclic, depth <= 8. Returns paste-ready
/// errors in the config_validate style. Pure - shared verbatim by boot and `--validate` so the two
/// cannot drift.
pub(crate) fn validate_groups(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
    errors: &mut Vec<String>,
) {
    /// Chain-walk depth ceiling (root counts as 1).
    const MAX_GROUP_DEPTH: usize = 8;

    for (name, group) in groups {
        if let Some(parent) = &group.parent {
            if !groups.contains_key(parent) {
                errors.push(format!(
                    "groups.{name} names parent '{parent}', which does not exist.\n\
                     Paste this under groups and set its limits:\n\n    \
                     {parent}:\n      limits:\n        - {{ requests: 0, per: minute }}\n"
                ));
                continue;
            }
        }
        // Walk the parent chain from this node: a repeat visit is a cycle; a walk past the depth
        // ceiling is too deep. Bounded by MAX_GROUP_DEPTH+1 steps, so no visited-set allocation.
        let mut depth = 1usize;
        let mut cursor = group.parent.as_deref();
        let mut path = vec![name.as_str()];
        while let Some(cur) = cursor {
            if path.contains(&cur) {
                errors.push(format!(
                    "groups chain starting at '{name}' is CYCLIC ({} -> {cur}); break the cycle \
                     by removing one `parent:`",
                    path.join(" -> ")
                ));
                break;
            }
            path.push(cur);
            depth += 1;
            if depth > MAX_GROUP_DEPTH {
                errors.push(format!(
                    "groups chain starting at '{name}' exceeds the maximum depth of \
                     {MAX_GROUP_DEPTH} ({})",
                    path.join(" -> ")
                ));
                break;
            }
            cursor = groups.get(cur).and_then(|g| g.parent.as_deref());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A group round-trips through YAML (deserialize -> serialize -> deserialize) unchanged. This is
    /// the property the config OVERLAY relies on: an Admin-API-applied group budget must re-parse
    /// identically at boot. Exercises every limit shape: windowed metrics, the windowless `concurrent`,
    /// a per-pool budget (future `pool:` qualifier is additive; this covers today's shape), and the
    /// parent chain.
    #[test]
    fn group_yaml_round_trips_exactly() {
        let src = "\
parent: team-payments
enabled: true
limits:
  - { budget: 1000, per: month }
  - { requests: 500, per: minute }
  - { tokens: 20000000, per: day }
  - { concurrent: 5 }
";
        let g1: GroupCfg = serde_yaml::from_str(src).expect("parse group");
        // Serialize back out, then parse again — the two parsed values must be identical.
        let out = serde_yaml::to_string(&g1).expect("serialize group");
        let g2: GroupCfg = serde_yaml::from_str(&out).expect("re-parse serialized group");
        assert_eq!(g1, g2, "group must survive a serialize/deserialize round-trip");

        // Spot-check the serialized shape is the canonical `{ <metric>: <amount>, per: <window> }`,
        // not some derived tagged form — a drift here would silently corrupt the overlay format.
        assert!(out.contains("budget: 1000"), "budget metric key preserved: {out}");
        assert!(out.contains("per: month"), "window preserved: {out}");
        assert!(out.contains("concurrent: 5"), "windowless concurrent preserved: {out}");
        assert!(!out.contains("per: null"), "concurrent must not emit a null `per`: {out}");
    }

    /// The windowless `concurrent` limit serializes WITHOUT a `per` key (len 1 map), and windowed
    /// limits serialize WITH it (len 2) — the custom Serialize mirrors the custom Deserialize.
    #[test]
    fn limit_serialize_shape_matches_deserialize() {
        let concurrent: LimitCfg = serde_yaml::from_str("{ concurrent: 3 }").unwrap();
        assert_eq!(serde_yaml::to_string(&concurrent).unwrap().trim(), "concurrent: 3");

        let budget: LimitCfg = serde_yaml::from_str("{ budget: 5000, per: month }").unwrap();
        let out = serde_yaml::to_string(&budget).unwrap();
        let back: LimitCfg = serde_yaml::from_str(&out).unwrap();
        assert_eq!(budget, back);
    }
}
