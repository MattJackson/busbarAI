// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Operator-supplied **Rhai** routing transport (`route: script`).
//!
//! An operator embeds a small Rhai script (inline `script:` or `script_file:`) that, given a cheap
//! projection of the request and the candidate array, returns an ARRAY of candidate `idx` values —
//! the ranked preference, most-preferred first. Empty / unit / non-array → `Abstain`. Any script
//! error, hit limit, or marshaling failure → `Err`, which the seam coerces to the pool's `on_error`
//! (never blocks or fails the request).
//!
//! ## Dependency discipline
//! The whole module is behind the `script-policy` cargo feature (`rhai` is `optional`). The DEFAULT
//! build pulls NO Rhai — Busbar's small static binary stays small. When an operator configures a
//! `route: script` pool WITHOUT the feature, [`build_policy`] returns a clear "feature not enabled"
//! error so it degrades loudly (the seam still falls back to the pool default, never a hang).
//!
//! ## Sandbox
//! The engine is locked down HARD: a max-operations cap (so a runaway/`while true {}` script
//! TERMINATES at the cap rather than hanging), a call-depth cap, string/array/map size caps, and NO
//! module resolver / imports / file or network host functions are ever registered. Rhai's standard
//! engine has no file/network access of its own; we additionally forbid `import` by leaving the
//! module resolver unset and never exposing any host fn that can do I/O.
//!
//! ## Compile once
//! The script is parsed into an `AST` ONCE in [`build_policy`] (at config load), not per request.
//! With Rhai's `sync` feature both `Engine` and `AST` are `Send + Sync`, so the compiled
//! [`ScriptPolicy`] drops straight into `Arc<dyn RoutingPolicy>`. `decide` runs the synchronous eval
//! on the blocking pool (so a hostile script can't pin an async worker) under a hard wall-clock budget
//! enforced via `on_progress`, against the shared, pre-compiled `Arc<AST>`.
#![cfg(feature = "script-policy")]

use super::{
    Candidate, PolicyError, PolicyResult, RoutingContext, RoutingDecision, RoutingPolicy,
    RoutingRequest,
};
use rhai::{Array, Dynamic, Engine, Map, Scope, AST};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Sandbox limits ───────────────────────────────────────────────────────────────────────────────
// A routing decision is a tiny ranking over a handful of candidates; these caps are generous for any
// legitimate script yet bound a hostile one to terminate fast. The op cap is the runaway guard: Rhai
// counts every operation and aborts with an error once the budget is spent, so `while true {}` ends.

/// Max Rhai operations per evaluation. A real ranking script does a few hundred ops; 250k leaves
/// enormous headroom while still terminating a runaway in well under the wall-clock timeout.
const MAX_OPERATIONS: u64 = 250_000;
/// Max nested function / expression call depth (both top-level and within functions).
const MAX_CALL_DEPTH: usize = 32;
/// Max string length in bytes — no need to build large strings for a ranking.
const MAX_STRING_SIZE: usize = 8 * 1024;
/// Max array length — far more than any plausible candidate count.
const MAX_ARRAY_SIZE: usize = 4 * 1024;
/// Max object-map entries.
const MAX_MAP_SIZE: usize = 1024;

/// Build a sandboxed Rhai engine. No module resolver (so `import` fails), no I/O host functions, and
/// all the size/op/depth caps applied. Cheap to build; we build it once and keep it on the policy.
fn sandboxed_engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_max_operations(MAX_OPERATIONS);
    engine.set_max_call_levels(MAX_CALL_DEPTH);
    engine.set_max_expr_depths(MAX_CALL_DEPTH, MAX_CALL_DEPTH);
    engine.set_max_string_size(MAX_STRING_SIZE);
    engine.set_max_array_size(MAX_ARRAY_SIZE);
    engine.set_max_map_size(MAX_MAP_SIZE);
    // No module resolver → `import` statements error. Rhai's base engine registers no file/network
    // host functions, so the script cannot reach the filesystem, network, or process.
    engine.set_module_resolver(rhai::module_resolvers::DummyModuleResolver::new());
    engine
}

/// A compiled, sandboxed Rhai routing policy. Holds the shared engine + the AST compiled once at
/// config load. With Rhai's `sync` feature both fields are `Send + Sync`, so this is safe behind the
/// `Arc<dyn RoutingPolicy>` shared across worker tasks.
pub(crate) struct ScriptPolicy {
    // The compiled program only. The engine is built per-`decide` on the blocking pool so each eval
    // gets its own wall-clock `on_progress` deadline; the AST is shared via `Arc` (Send + Sync under
    // Rhai's `sync` feature) so cloning it into the blocking task is a refcount bump, not a recompile.
    ast: Arc<AST>,
}

impl ScriptPolicy {
    /// Compile an operator script ONCE. Returns an `Err` (surfaced at config load) if the script does
    /// not parse, so a bad script is rejected loudly at startup rather than per request.
    pub(crate) fn compile(source: &str) -> Result<Self, PolicyError> {
        let engine = sandboxed_engine();
        let ast = engine
            .compile(source)
            .map_err(|e| -> PolicyError { format!("rhai script compile error: {e}").into() })?;
        Ok(Self { ast: Arc::new(ast) })
    }
}

/// Project the request scalars into a Rhai object-map the script reads as `req`.
fn request_map(req: &RoutingRequest<'_>) -> Map {
    let mut m = Map::new();
    m.insert("pool".into(), req.pool.into());
    m.insert("ingress_protocol".into(), req.ingress_protocol.into());
    m.insert(
        "requested_model".into(),
        req.requested_model.map_or(Dynamic::UNIT, |s| s.into()),
    );
    m.insert("message_count".into(), (req.message_count as i64).into());
    m.insert("tool_count".into(), (req.tool_count as i64).into());
    m.insert("has_tools".into(), req.has_tools.into());
    m.insert("total_chars".into(), (req.total_chars as i64).into());
    m.insert("system_chars".into(), (req.system_chars as i64).into());
    m.insert(
        "max_tokens".into(),
        req.max_tokens.map_or(Dynamic::UNIT, |t| (t as i64).into()),
    );
    m.insert("stream".into(), req.stream.into());
    m
}

/// Project one candidate into a Rhai object-map. `None` numeric signals become `()` (unit) so the
/// script can test them with `==()` or default them with `??`.
fn candidate_map(c: &Candidate<'_>) -> Map {
    let mut m = Map::new();
    m.insert("idx".into(), (c.idx as i64).into());
    m.insert("model".into(), c.model.into());
    m.insert("provider".into(), c.provider.into());
    m.insert("weight".into(), (c.weight as i64).into());
    m.insert(
        "context_max".into(),
        c.context_max.map_or(Dynamic::UNIT, |v| (v as i64).into()),
    );
    m.insert("tier".into(), c.tier.map_or(Dynamic::UNIT, |s| s.into()));
    m.insert(
        "cost_per_mtok".into(),
        c.cost_per_mtok.map_or(Dynamic::UNIT, |v| v.into()),
    );
    m.insert(
        "latency_ms".into(),
        c.latency_ms.map_or(Dynamic::UNIT, |v| v.into()),
    );
    m.insert(
        "available_concurrency".into(),
        (c.available_concurrency as i64).into(),
    );
    m.insert(
        "budget_remaining".into(),
        c.budget_remaining.map_or(Dynamic::UNIT, |v| v.into()),
    );
    m.insert(
        "rate_headroom".into(),
        c.rate_headroom.map_or(Dynamic::UNIT, |v| v.into()),
    );
    let tags: Array = c.tags.iter().map(|t| Dynamic::from(t.clone())).collect();
    m.insert("tags".into(), tags.into());
    m
}

/// Coerce the script's return value into a raw `Vec<usize>` of ranked idxs. A non-array (including
/// unit `()`) yields an empty vec → the caller normalizes to `Abstain`. Each element must be an
/// integer; a non-integer element is skipped (liberal-in-what-you-accept). Negative idxs are dropped.
fn ranked_from_dynamic(out: Dynamic) -> Vec<usize> {
    let Some(arr) = out.try_cast::<Array>() else {
        // Unit, bool, string, map, etc. → no ranking → Abstain.
        return Vec::new();
    };
    arr.into_iter()
        .filter_map(|d| d.as_int().ok())
        .filter(|i| *i >= 0)
        .map(|i| i as usize)
        .collect()
}

#[async_trait::async_trait]
impl RoutingPolicy for ScriptPolicy {
    async fn decide(
        &self,
        req: &RoutingRequest<'_>,
        candidates: &[Candidate<'_>],
        ctx: &RoutingContext<'_>,
        budget: Duration,
    ) -> PolicyResult {
        // Build the input scope as OWNED Rhai values up front so they can move into the blocking task.
        let req_map = request_map(req);
        let cand_arr: Array = candidates
            .iter()
            .map(|c| Dynamic::from(candidate_map(c)))
            .collect();
        let mut ctx_map = Map::new();
        ctx_map.insert("pool".into(), ctx.pool.into());
        ctx_map.insert(
            "budget_remaining".into(),
            ctx.budget_remaining.map_or(Dynamic::UNIT, |v| v.into()),
        );
        let valid: std::collections::HashSet<usize> = candidates.iter().map(|c| c.idx).collect();
        let ast = Arc::clone(&self.ast);

        // Rhai eval is SYNCHRONOUS CPU work. Run it on the blocking pool so a pathological script can
        // never pin an async runtime worker (a routing-path DoS), AND enforce a hard WALL-CLOCK budget
        // inside the eval via `on_progress`: the op cap bounds *logical* work but not real time, and
        // the seam's outer `tokio::timeout` cannot interrupt blocking CPU — so the deadline must live
        // HERE. Building the engine per call (cheap) lets each eval carry its own deadline closure.
        let eval = tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + budget;
            let mut engine = sandboxed_engine();
            engine.on_progress(move |ops| {
                // Check the clock every ~1024 ops so the per-op overhead stays negligible. Returning
                // `Some(..)` aborts the eval (`ErrorTerminated`) → surfaced as an Err below.
                if ops & 0x3FF == 0 && Instant::now() >= deadline {
                    Some(Dynamic::UNIT)
                } else {
                    None
                }
            });
            let mut scope = Scope::new();
            scope.push("req", req_map);
            scope.push("candidates", cand_arr);
            scope.push("ctx", ctx_map);
            engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast)
        })
        .await;

        // Any error (op cap, depth/size cap, runtime fault, budget abort) OR a panicked/cancelled
        // blocking task becomes a `PolicyError` → coerced to `on_error` by the seam. Never crashes.
        let out: Dynamic = match eval {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return Err(format!("rhai script eval error: {e}").into()),
            Err(e) => return Err(format!("rhai script task error: {e}").into()),
        };

        // Normalize: drop unknown/duplicate idxs, empty → Abstain. The set of valid idxs is exactly
        // the candidate idxs we projected.
        Ok(RoutingDecision::from_ranked(
            ranked_from_dynamic(out),
            &valid,
        ))
    }

    fn name(&self) -> &'static str {
        "script"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn cand(idx: usize, cost: Option<f64>, lat: Option<f64>) -> Candidate<'static> {
        Candidate {
            idx,
            model: "m",
            provider: "p",
            weight: 1,
            context_max: None,
            tier: None,
            cost_per_mtok: cost,
            tags: &[],
            latency_ms: lat,
            available_concurrency: 1,
            budget_remaining: None,
            rate_headroom: None,
        }
    }

    fn req() -> RoutingRequest<'static> {
        RoutingRequest {
            pool: "p",
            ingress_protocol: "anthropic",
            requested_model: None,
            message_count: 3,
            tool_count: 0,
            has_tools: false,
            total_chars: 100,
            system_chars: 0,
            max_tokens: Some(256),
            stream: false,
        }
    }

    fn ctx() -> RoutingContext<'static> {
        RoutingContext {
            pool: "p",
            budget_remaining: None,
        }
    }

    /// A script that returns an explicit order.
    #[tokio::test]
    async fn script_returns_order() {
        let p = ScriptPolicy::compile("[2, 0, 1]").unwrap();
        let cands = [
            cand(0, None, None),
            cand(1, None, None),
            cand(2, None, None),
        ];
        let d = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![2, 0, 1]));
    }

    /// A script that ranks by reading candidate fields (cheapest cost first).
    #[tokio::test]
    async fn script_ranks_by_cost() {
        // Sort candidate idxs by cost_per_mtok ascending; missing cost sorts last.
        let src = r#"
            let scored = [];
            for c in candidates {
                let cost = if c.cost_per_mtok == () { 1e30 } else { c.cost_per_mtok };
                scored.push([cost, c.idx]);
            }
            scored.sort(|a, b| if a[0] < b[0] { -1 } else if a[0] > b[0] { 1 } else { 0 });
            let order = [];
            for s in scored { order.push(s[1]); }
            order
        "#;
        let p = ScriptPolicy::compile(src).unwrap();
        let cands = [
            cand(0, Some(15.0), None),
            cand(1, Some(3.0), None),
            cand(2, Some(8.0), None),
        ];
        let d = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![1, 2, 0]));
    }

    /// A script that reads the request projection and branches on it.
    #[tokio::test]
    async fn script_reads_request_fields() {
        // If has_tools, prefer idx 1 then 0; else prefer 0 then 1.
        let src = "if req.has_tools { [1, 0] } else { [0, 1] }";
        let p = ScriptPolicy::compile(src).unwrap();
        let cands = [cand(0, None, None), cand(1, None, None)];
        let d = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Prefer(vec![0, 1]));
    }

    /// A runaway script (infinite loop) must hit the operation cap and ERROR — never hang. The seam
    /// coerces the error to fallback.
    #[tokio::test]
    async fn runaway_script_hits_op_cap() {
        let p = ScriptPolicy::compile("let x = 0; while true { x += 1; } [0]").unwrap();
        let cands = [cand(0, None, None)];
        let res = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await;
        assert!(
            res.is_err(),
            "runaway script must error (op cap), not hang or succeed"
        );
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("eval error"),
            "error should be an eval error, got: {msg}"
        );
    }

    /// A genuine Rhai RUNTIME error — a reference to an undefined variable (a `canddiates` typo for
    /// `candidates`) — compiles fine but faults at eval, surfacing as `Err` (→ `on_error` fallback).
    /// Distinct from the op-cap / wall-clock aborts: this is an ordinary script-logic fault, the most
    /// common operator mistake, and it must degrade safely rather than strand the request.
    #[tokio::test]
    async fn runtime_error_undefined_variable_is_error_fallback() {
        // `canddiates` is a typo; the variable does not exist in scope → eval-time runtime error.
        let p = ScriptPolicy::compile("canddiates").unwrap();
        let cands = [cand(0, None, None), cand(1, None, None)];
        let res = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await;
        let msg = res
            .expect_err(
                "a runtime error (undefined variable) must surface as Err → on_error fallback",
            )
            .to_string();
        assert!(
            msg.contains("eval error"),
            "undefined-variable fault must route through the eval-error arm; got: {msg}"
        );
    }

    /// A call to an undefined FUNCTION is likewise a runtime fault → `Err` fallback.
    #[tokio::test]
    async fn runtime_error_undefined_function_is_error_fallback() {
        let p = ScriptPolicy::compile("no_such_fn(candidates)").unwrap();
        let cands = [cand(0, None, None)];
        let res = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await;
        let msg = res
            .expect_err("a call to an undefined function must surface as Err → on_error fallback")
            .to_string();
        assert!(
            msg.contains("eval error"),
            "undefined-function fault must route through the eval-error arm; got: {msg}"
        );
    }

    /// A malformed return (not an array of idxs) → Abstain.
    #[tokio::test]
    async fn malformed_return_abstains() {
        // Returns a string, not an array.
        let p = ScriptPolicy::compile(r#""not an array""#).unwrap();
        let cands = [cand(0, None, None), cand(1, None, None)];
        let d = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// A return of all-unknown idxs collapses to Abstain (never strands lanes).
    #[tokio::test]
    async fn unknown_idxs_abstain() {
        let p = ScriptPolicy::compile("[7, 8, 9]").unwrap();
        let cands = [cand(0, None, None), cand(1, None, None)];
        let d = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// A script that returns unit `()` → Abstain.
    #[tokio::test]
    async fn unit_return_abstains() {
        let p = ScriptPolicy::compile("let _x = 1; ()").unwrap();
        let cands = [cand(0, None, None)];
        let d = p
            .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(d, RoutingDecision::Abstain);
    }

    /// `import` is forbidden (no module resolver) — compile or eval fails, never reaches a module.
    #[tokio::test]
    async fn import_is_blocked() {
        // `import` parses but resolves against the DummyModuleResolver, which always errors.
        let p = ScriptPolicy::compile(r#"import "std" as s; [0]"#);
        match p {
            Err(_) => {} // rejected at compile — fine.
            Ok(policy) => {
                let cands = [cand(0, None, None)];
                let res = policy
                    .decide(&req(), &cands, &ctx(), Duration::from_millis(50))
                    .await;
                assert!(res.is_err(), "import must fail to resolve");
            }
        }
    }

    /// A script that burns wall-clock time past the `budget` deadline must abort and return `Err`.
    ///
    /// This exercises the WALL-CLOCK path in `decide`: `on_progress` checks `Instant::now()` every
    /// ~1024 ops and fires `ErrorTerminated` once the deadline is past. This is DISTINCT from the
    /// op-cap path tested by `runaway_script_hits_op_cap`: the op cap fires unconditionally after
    /// MAX_OPERATIONS iterations; the wall-clock path fires whenever real time exceeds the budget,
    /// even for a script that hasn't yet exhausted the op budget.
    ///
    /// We use a 1 ms budget and a tight spin loop. The `on_progress` callback checks the clock every
    /// 1024 ops, so the script runs at most ~1024 ops before the first clock check. With a 1 ms budget
    /// and modern hardware executing millions of ops/sec, even 1024 ops takes well under the deadline
    /// most of the time — so we use `std::thread::sleep` INSIDE the script to ensure real wall-clock
    /// time elapses. Since Rhai scripts cannot call `std::thread::sleep` directly, we instead set a
    /// budget of 1 ns (essentially already-expired) so the very FIRST on_progress tick (at op 1024)
    /// is guaranteed to find `Instant::now() >= deadline` and abort.
    #[tokio::test]
    async fn wall_clock_budget_abort() {
        // An extremely tight budget — effectively zero. The script is a simple spin; the first
        // on_progress tick (fired at op count 1024) will find the deadline already elapsed and abort.
        let p = ScriptPolicy::compile("let x = 0; loop { x += 1; }").unwrap();
        let cands = [cand(0, None, None)];
        let res = p
            .decide(&req(), &cands, &ctx(), Duration::from_nanos(1))
            .await;
        assert!(
            res.is_err(),
            "a script that exceeds the wall-clock budget must error (→ on_error fallback), not hang or succeed"
        );
        // The error message routes through the eval-error arm.
        let msg = res.unwrap_err().to_string();
        assert!(
            msg.contains("eval error"),
            "wall-clock abort must surface as an eval error; got: {msg}"
        );
    }

    /// A bad script is rejected at compile time (config load), not at request time.
    #[test]
    fn compile_rejects_bad_syntax() {
        assert!(ScriptPolicy::compile("this is ((( not rhai").is_err());
    }

    /// The compiled policy is `Send + Sync` (required for `Arc<dyn RoutingPolicy>`).
    #[test]
    fn policy_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ScriptPolicy>();
        let _arc: Arc<dyn RoutingPolicy> = Arc::new(ScriptPolicy::compile("[0]").unwrap());
    }
}
