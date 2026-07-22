// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LAZY request-body DOM (perf/throughput-1.5.0).
//!
//! The dominant same-protocol passthrough request never needs the full `serde_json::Value` tree it
//! used to pay for on every ingress: the pristine short-circuit re-emits the ORIGINAL bytes, and the
//! only body reads on that path are a handful of TOP-LEVEL point reads (`model`, `stream`, the
//! affinity `system` key, the router shim keys). Building — and recursively dropping — a full DOM
//! (one allocation per JSON node) purely to answer those reads was the single biggest remaining
//! per-request CPU cost.
//!
//! [`LazyBody`] replaces the eager parse with:
//!   1. ONE validating scan over the bytes ([`LazyBody::parse`]) that PRESERVES the malformed-body
//!      400 contract exactly (it goes through `crate::json::parse`, so the depth security floor and
//!      the accept/reject set are unchanged — every byte is still parsed; uncaptured values are
//!      scanned via `serde::de::IgnoredAny` instead of allocated into a tree), and
//!   2. a tiny HEAD projection of exactly the top-level fields the pristine path reads, captured
//!      during that same scan, plus
//!   3. on-demand materialization of the full `Value` ([`LazyBody::ensure_dom`] /
//!      [`LazyBody::into_value`]) for every path that genuinely needs the tree (cross-protocol
//!      translation, rewrite hooks, taps, gates/routing policies, failover hops 2+).
//!
//! SAFETY CONTRACT for [`LazyBody::probe`]: the head projection answers top-level reads ONLY for
//! the keys in [`captured_head_keys`] (`model`, `stream`, `system`, and every registered protocol's
//! array-stream shim key). Every consumer that point-reads the request body on the pre-materialized
//! path (`OperationHandler::wants_stream` / `body_affinity_key` — chat reads `stream`/`system`;
//! `ProtocolWriter::wants_array_stream` — gemini reads its shim key; the ingress `model` resolution)
//! reads ONLY those keys. If a future operation/writer override reads a NEW top-level key through
//! `probe()`, that key MUST be added to `captured_head_keys` (or the call site must materialize via
//! `ensure_dom`) — see `head_matches_dom_for_captured_keys` below, which pins the equivalence.

use super::*;

/// The top-level keys the head projection captures — the COMPLETE set of body point-reads on the
/// pre-materialized path. `model` (ingress model resolution + the pristine model-rewrite check),
/// `stream` (chat's `wants_stream` + shim-strip invalidator #2), `system` (chat's body affinity
/// key), plus every registered protocol's array-stream shim key (invalidator #1 + gemini's
/// `wants_array_stream`).
fn captured_head_keys() -> &'static [&'static str] {
    static CACHE: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            // `stream_options` is captured so the engine can read `stream_options.include_usage`
            // (the OpenAI streaming-usage opt-in, Findings 2+3) off the head projection WITHOUT forcing
            // a full DOM materialization on the common streaming path. It is a small top-level object;
            // capturing it keeps the point read O(1) and DOM-equivalent.
            let mut v: Vec<&'static str> = vec!["model", "stream", "stream_options", "system"];
            v.extend_from_slice(crate::proto::array_stream_shim_keys());
            v.sort_unstable();
            v.dedup();
            v
        })
        .as_slice()
}

/// A top-level map key classified against [`captured_head_keys`] WITHOUT allocating: the serde
/// visitor borrows the key transiently and resolves it to the interned `&'static str` (or `None`
/// for a key the head does not capture, whose value is then scanned via `IgnoredAny`).
struct HeadKey(Option<&'static str>);

impl<'de> serde::Deserialize<'de> for HeadKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl serde::de::Visitor<'_> for KeyVisitor {
            type Value = HeadKey;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object key")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<HeadKey, E> {
                Ok(HeadKey(
                    captured_head_keys().iter().copied().find(|k| *k == s),
                ))
            }
        }
        d.deserialize_str(KeyVisitor)
    }
}

/// The head projection: `Value::Object` holding ONLY the captured top-level keys when the body's
/// top level is a JSON object; `Value::Null` for every non-object body (whose top-level `.get()`
/// reads all resolve to `None` — exactly what they resolve to on the full DOM, since `Value::get`
/// on a non-object is `None` too). Duplicate captured keys keep the LAST occurrence, matching
/// `serde_json::Map` insert semantics on the full parse.
struct Head(Value);

impl<'de> serde::Deserialize<'de> for Head {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct HeadVisitor;
        impl<'de> serde::de::Visitor<'de> for HeadVisitor {
            type Value = Head;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            // Non-object top levels: the whole body is still parsed/validated by the driving
            // deserializer; the head is Null (all point reads -> None, same as the DOM's `.get`).
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Head, E> {
                Ok(Head(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Head, A::Error> {
                // Consume (and thereby VALIDATE) every element without building values.
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Head(Value::Null))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Head, A::Error> {
                let mut mini = serde_json::Map::new();
                while let Some(HeadKey(k)) = map.next_key::<HeadKey>()? {
                    match k {
                        // A captured key: keep its (small) value. `insert` overwrites on duplicate
                        // keys — last-wins, byte-for-byte the full-DOM behavior.
                        Some(name) => {
                            let v: Value = map.next_value()?;
                            mini.insert(name.to_string(), v);
                        }
                        // Any other key: scan/validate the value without allocating a tree.
                        None => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Head(Value::Object(mini)))
            }
        }
        d.deserialize_any(HeadVisitor)
    }
}

/// The request body as the forward engine carries it: validated pristine bytes + the head
/// projection, with the full DOM materialized ONLY on the paths that need it. See the module docs.
pub(crate) enum LazyBody {
    /// Validated JSON bytes + top-level head projection; no DOM built yet.
    Head { bytes: Bytes, head: Value },
    /// The full DOM — materialized on demand, or supplied eagerly by a caller that already parsed
    /// (path-model ingress routes, failover re-parse, tests).
    Dom(Value),
}

impl LazyBody {
    /// Validate `bytes` as JSON and capture the head projection — WITHOUT building a DOM. Goes
    /// through `crate::json::parse` so the depth security floor and the malformed-body reject set
    /// are IDENTICAL to the old eager `parse::<Value>` (same guard, same parser, full-body scan).
    /// `Err` ⇒ the caller takes its existing malformed-body 400 path, exactly as before.
    pub(crate) fn parse(bytes: &Bytes) -> Result<Self, sonic_rs::Error> {
        let head: Head = crate::json::parse(bytes)?;
        Ok(LazyBody::Head {
            bytes: bytes.clone(), // refcount bump — the engine retains the same pristine bytes
            head: head.0,
        })
    }

    /// Wrap an ALREADY-parsed body (path-model ingress routes that injected shim keys, tests). The
    /// DOM is present from the start; every read sees it directly.
    pub(crate) fn from_value(v: Value) -> Self {
        LazyBody::Dom(v)
    }

    /// Top-level POINT-READ view: the DOM when materialized (always authoritative — it may have
    /// been mutated by rewrite hooks), else the head projection. ONLY valid for reads of the
    /// [`captured_head_keys`] — any other key must go through [`Self::ensure_dom`].
    pub(crate) fn probe(&self) -> &Value {
        match self {
            LazyBody::Dom(v) => v,
            LazyBody::Head { head, .. } => head,
        }
    }

    /// Materialize (memoized) the full DOM and return it mutably. The parse is infallible in
    /// practice — `Self::parse` already validated these exact bytes — but the `Err` is surfaced so
    /// callers keep their existing unreachable-parse-failure guards instead of unwrapping on the
    /// request path.
    pub(crate) fn ensure_dom(&mut self) -> Result<&mut Value, ()> {
        if let LazyBody::Head { bytes, .. } = self {
            let v: Value = crate::json::parse(bytes).map_err(|_| ())?;
            *self = LazyBody::Dom(v);
        }
        match self {
            LazyBody::Dom(v) => Ok(v),
            // Unreachable: the Head arm above either converted to Dom or returned Err.
            LazyBody::Head { .. } => Err(()),
        }
    }

    /// Consume into the full DOM (memoized parse if not yet materialized). Same infallibility note
    /// as [`Self::ensure_dom`].
    pub(crate) fn into_value(self) -> Result<Value, ()> {
        match self {
            LazyBody::Dom(v) => Ok(v),
            LazyBody::Head { bytes, .. } => crate::json::parse(&bytes).map_err(|_| ()),
        }
    }
}

/// HEAD-LEVEL mirror of `translate_request_cross_protocol`'s SAME-PROTOCOL invalidator set (#1-#4
/// of the request short-circuit contract, plus the Vertex-Anthropic body transform), evaluated on
/// top-level point reads only — so hop 1 of a same-protocol dispatch can re-emit the retained bytes
/// WITHOUT ever materializing the DOM.
///
/// SOUNDNESS (one-sided by design): this returns `true` ONLY when the full translate path would
/// provably leave the body pristine (and therefore re-emit the retained bytes itself). Any doubt
/// returns `false`, which sends the request down the unchanged materialize-and-translate path —
/// a slower CORRECT answer, never a wrong relay. Concretely:
///   - #1: any registered array-stream shim key present at the top level → not pristine.
///   - #2: `stream` present and the egress (== ingress) is path-model → not pristine.
///   - #3: modeled on the DEFAULT `rewrite_model_if_needed` (no change iff the body's top-level
///     `model` is exactly the lane's wire model string). `BedrockWriter`'s no-op override can only
///     make FEWER changes than the default, so treating every writer as the default is sound — a
///     Bedrock body without `model` reads "would change" here and takes the full path, where the
///     real no-op override still yields the byte short-circuit inside translate.
///   - Vertex-Anthropic (`path_base` on an anthropic lane) always mutates an object body.
///   - #4: same-protocol path-model with a body `model` → stripped → not pristine.
///
/// A NON-OBJECT top level is pristine: every invalidator no-ops (`as_object_mut` fails), exactly
/// as the full path concludes.
///
/// The parity test `head_pristine_matches_translate_output` pins this mirror against the real
/// translate seam so the two cannot silently drift.
pub(crate) fn head_provably_pristine(app: &App, i: usize, probe: &Value) -> bool {
    let Some(obj) = probe.as_object() else {
        return true;
    };
    // #1: never-native router shim keys are stripped on every branch.
    if crate::proto::array_stream_shim_keys()
        .iter()
        .any(|k| obj.contains_key(*k))
    {
        return false;
    }
    let lane = &app.lanes[i];
    let model_in_url = lane.protocol.writer().has_model_in_url();
    // #2: `stream` is a path shim for a path-model egress (same-proto ⇒ egress == this lane).
    if model_in_url && obj.contains_key("stream") {
        return false;
    }
    // #3: the default model rewrite is a no-op only when the body already carries exactly the
    // lane's wire model as a string (missing / non-string / different ⇒ the rewrite would fire).
    if obj.get("model").and_then(|m| m.as_str()) != Some(lane.wire_model()) {
        return false;
    }
    // Claude-on-Vertex: always mutates an object body (drops `model`, injects `anthropic_version`).
    if lane.path_base.is_some() && lane.protocol.name() == crate::proto::PROTO_ANTHROPIC {
        return false;
    }
    // #4: a same-protocol path-model body `model` is stripped after the rewrite.
    if model_in_url && obj.contains_key("model") {
        return false;
    }
    true
}

#[cfg(test)]
mod lazy_body_tests {
    use super::*;
    use crate::test_support::{LaneSpec, TestApp};
    use serde_json::json;

    /// The head projection must answer every captured-key point read EXACTLY as the full DOM does —
    /// including missing fields, non-string models, non-bool streams, duplicate keys (last wins),
    /// and non-object top levels.
    #[test]
    fn head_matches_dom_for_captured_keys() {
        let bodies: &[&str] = &[
            r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#,
            r#"{"model":"gpt-4o","stream":false,"system":"you are helpful"}"#,
            r#"{"messages":[]}"#,
            r#"{"model":42,"stream":"yes"}"#,
            r#"{"model":null,"system":""}"#,
            r#"{"model":"a","model":"b"}"#, // duplicate: last wins on both paths
            r#"{"__busbar_gemini_json_array":true,"contents":[]}"#,
            r#"{"system":{"nested":true},"stream":{"deep":[1,2]}}"#,
            r#"{"model":" gpt-4o "}"#, // whitespace preserved, never trimmed
            r#"[1,2,3]"#,
            r#""just a string""#,
            r#"42"#,
            r#"null"#,
            r#"true"#,
            r#"{}"#,
        ];
        for raw in bodies {
            let bytes = Bytes::from(raw.as_bytes().to_vec());
            let lazy = LazyBody::parse(&bytes).expect("valid JSON must head-parse");
            let dom: Value = crate::json::parse(&bytes).unwrap();
            for key in captured_head_keys() {
                assert_eq!(
                    lazy.probe().get(key),
                    dom.get(key),
                    "head/DOM divergence for key {key:?} on body {raw}"
                );
            }
        }
    }

    /// The head parse must accept/reject EXACTLY the same inputs as the old eager DOM parse —
    /// the malformed-body 400 contract is byte-identical.
    #[test]
    fn head_parse_rejects_iff_dom_parse_rejects() {
        let inputs: &[&[u8]] = &[
            b"{\"model\":\"m\"}",
            b"not json",
            b"{\"model\":",
            b"{\"model\":\"m\"} trailing",
            b"",
            b"{\"a\":1,}",
            b"{\"a\":00}",
            b"{\"a\":\"\\x\"}",
            b"\xff\xfe",
            b"{\"a\":\"\xff\"}", // invalid UTF-8 inside a string
            b"[1,2",
            b"{\"deep\":\"[[[[[ not depth, in a string\"}",
        ];
        for raw in inputs {
            let bytes = Bytes::copy_from_slice(raw);
            let dom_ok = crate::json::parse::<Value>(&bytes).is_ok();
            let head_ok = LazyBody::parse(&bytes).is_ok();
            assert_eq!(
                head_ok,
                dom_ok,
                "accept/reject divergence on input {:?}",
                String::from_utf8_lossy(raw)
            );
        }
        // The depth security floor holds on the head path too (no IgnoredAny recursion blowup).
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(LazyBody::parse(&Bytes::from(deep.into_bytes())).is_err());
    }

    /// PARITY PIN: `head_provably_pristine == true` must imply the REAL translate seam re-emits the
    /// retained bytes verbatim; and for the cases it declines, translate's output is still whatever
    /// it always was (exercised here to show the decline is safe, not wrong).
    #[test]
    fn head_pristine_matches_translate_output() {
        use crate::proto::Protocol;
        let cases: &[(Protocol, &'static str, &'static str, Value)] = &[
            // (proto, name, lane_model, body) — pristine expected
            (
                Protocol::openai(),
                "openai",
                "gpt-4o",
                json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}),
            ),
            (
                Protocol::anthropic(),
                "anthropic",
                "claude-3",
                json!({"model":"claude-3","max_tokens":7,"messages":[]}),
            ),
            // model differs → not head-pristine (translate rewrites)
            (
                Protocol::openai(),
                "openai",
                "gpt-4o-real",
                json!({"model":"alias","messages":[]}),
            ),
            // shim key present → not head-pristine
            (
                Protocol::openai(),
                "openai",
                "gpt-4o",
                json!({"model":"gpt-4o","__busbar_gemini_json_array":true}),
            ),
            // gemini: no body model → not head-pristine (conservative), translate still byte-identical
            (
                Protocol::gemini(),
                "gemini",
                "url-model-x",
                json!({"contents":[{"role":"user","parts":[{"text":"hi"}]}]}),
            ),
        ];
        for (proto, name, lane_model, body) in cases {
            let app = TestApp::new()
                .lane(LaneSpec::new(
                    lane_model,
                    proto.clone(),
                    "http://unused.local",
                ))
                .build();
            let hop_bytes = Bytes::from(crate::json::to_vec(body).unwrap());
            let lazy = LazyBody::parse(&hop_bytes).unwrap();
            let head_says = head_provably_pristine(&app, 0, lazy.probe());
            let out = translate_request_cross_protocol(
                &app,
                0,
                name,
                crate::handlers::chat(name),
                Some(body.clone()),
                APPLICATION_JSON,
                true,
                &hop_bytes,
            )
            .expect("same-proto shaping is infallible for a valid body");
            if head_says {
                assert_eq!(
                    out.as_ref(),
                    hop_bytes.as_ref(),
                    "{name}: head said pristine but translate mutated the body — UNSOUND"
                );
            }
            // (When head declines, translate's own pristine tracking still decides — no assertion
            // needed beyond translate succeeding; the decline path is byte-identical to today.)
        }
    }

    /// Non-object same-protocol bodies are pristine on BOTH paths (every invalidator no-ops).
    #[test]
    fn non_object_body_is_head_pristine() {
        let app = TestApp::new()
            .lane(LaneSpec::new(
                "m",
                crate::proto::Protocol::openai(),
                "http://unused.local",
            ))
            .build();
        for raw in [r#"[1,2,3]"#, r#""s""#, r#"null"#] {
            let bytes = Bytes::from(raw.as_bytes().to_vec());
            let lazy = LazyBody::parse(&bytes).unwrap();
            assert!(
                head_provably_pristine(&app, 0, lazy.probe()),
                "non-object body {raw} must be head-pristine"
            );
        }
    }

    /// Materialization round-trip: ensure_dom parses the same tree the eager path built, and a
    /// mutation through ensure_dom is visible to subsequent probe() reads (DOM authoritative).
    #[test]
    fn ensure_dom_materializes_and_probe_tracks_mutation() {
        let bytes = Bytes::from(r#"{"model":"a","messages":[{"role":"user","content":"hi"}]}"#);
        let mut lazy = LazyBody::parse(&bytes).unwrap();
        assert_eq!(
            lazy.probe().get("model").and_then(|m| m.as_str()),
            Some("a")
        );
        let dom = lazy.ensure_dom().expect("validated bytes must re-parse");
        assert_eq!(*dom, crate::json::parse::<Value>(&bytes).unwrap());
        dom.as_object_mut()
            .unwrap()
            .insert("model".into(), json!("b"));
        assert_eq!(
            lazy.probe().get("model").and_then(|m| m.as_str()),
            Some("b"),
            "probe must read the materialized (mutated) DOM, not the stale head"
        );
        assert_eq!(
            lazy.into_value().unwrap().get("model").unwrap(),
            &json!("b")
        );
    }
}
