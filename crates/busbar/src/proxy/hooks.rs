use super::*;

/// The coerced result of running a routing policy at the seam — what the ordered walk should do.
pub(crate) enum PolicyOutcome {
    /// Use this ranked order (the policy returned `Prefer`, or `on_error == first` produced the
    /// config member order). `name` is the policy/transport name for the transparency header.
    Order {
        order: Vec<usize>,
        name: &'static str,
    },
    /// Fall through to today's SWRR (the policy Abstained, or an error coerced to `on_error: weighted`).
    Weighted,
    /// Fail closed with a 503 (`on_error: reject` and the policy errored / timed out).
    Reject,
    /// The policy DELIBERATELY rejected the request (the hook's `reject` verb — a guardrail said
    /// no). Distinct from `Reject` above: that is a degraded "policy unavailable" 503, this is a
    /// first-class 4xx decision. `status` is clamped and `message` sanitized AT THE SEAM that
    /// constructs this variant (`decide_policy_order`'s mapping arm), so the guarantee holds for
    /// every producer of a rejection — wire-backed or direct-constructed.
    RejectRequest {
        status: u16,
        message: String,
        name: &'static str,
    },
    /// The hook's RESTRICT verb: the failover candidate set must be intersected with members carrying
    /// one of `tags_any` BEFORE selection, and that restriction persists across hops. An EMPTY
    /// intersection is fail-closed (`on_empty` default reject) — never allow-all. `tags_any` may be
    /// empty (a fail-closed-normalized malformed restrict), which forces the empty intersection.
    Restrict {
        tags_any: Vec<String>,
        name: &'static str,
        /// Behavior when the intersection is empty: `Reject` (default, fail-closed 503) or `Weighted`
        /// (advisory escape — SWRR over the FULL pool). `First` is treated as `Reject` (a restrict
        /// with no eligible member has no "first" to fall to).
        on_empty: crate::config::PolicyOnError,
    },
}

/// Apply a hook's `rewrite` reply to the INGRESS body, rendered PER DIALECT (the reply carries
/// `{role, content}` messages in body form; each ingress protocol frames conversation content
/// differently). Fail-safe throughout: a body without the dialect's conversation container, or a
/// rewrite message whose content isn't plain text where the dialect needs re-framing, leaves the
/// body untouched and returns `false` — never a corrupted request.
///
/// Dialect rendering:
/// - openai / anthropic / cohere: `messages: [{role, content}]` — inserted verbatim (all three
///   accept string content). Abstract `tools` injection applies here only (their tool shapes are
///   compatible enough to append; the other dialects' tool framings differ — deferred, fail-safe).
/// - bedrock (Converse): `messages: [{role, content: [{text}]}]` — each rewrite message is
///   RE-FRAMED into a one-block text content list (a verbatim insert would corrupt the block
///   shape — bedrock also has a `messages` key, so this arm is load-bearing, not cosmetic).
/// - gemini: `contents: [{role, parts: [{text}]}]` — re-framed, with the role mapping gemini
///   requires (`assistant` → `model`; everything else → `user`).
/// - responses: `input: [{role, content}]` — re-framed into the EasyInputMessage list (string
///   content is accepted); a string `input` is replaced by the list.
pub(crate) fn apply_rewrite_to_body(
    v: &mut Value,
    rewrite: &crate::hooks::wire::RewriteReply,
    ingress_protocol: &str,
) -> bool {
    if rewrite.messages.is_empty() {
        return false;
    }
    let Some(obj) = v.as_object_mut() else {
        return false;
    };
    // Extract (role, text) pairs when a dialect needs re-framing. `None` = a message without
    // plain-string content — abort untouched (fail-safe).
    let as_text_pairs = || -> Option<Vec<(String, String)>> {
        rewrite
            .messages
            .iter()
            .map(|m| {
                let role = m.get("role").and_then(Value::as_str)?.to_string();
                let text = m.get("content").and_then(Value::as_str)?.to_string();
                Some((role, text))
            })
            .collect()
    };
    match ingress_protocol {
        PROTO_BEDROCK => {
            if !obj.get("messages").is_some_and(Value::is_array) {
                return false;
            }
            let Some(pairs) = as_text_pairs() else {
                return false;
            };
            let framed: Vec<Value> = pairs
                .into_iter()
                .map(|(role, text)| {
                    serde_json::json!({ "role": role, "content": [{ "text": text }] })
                })
                .collect();
            obj.insert("messages".to_string(), Value::Array(framed));
            true
        }
        PROTO_GEMINI => {
            if !obj.get("contents").is_some_and(Value::is_array) {
                return false;
            }
            let Some(pairs) = as_text_pairs() else {
                return false;
            };
            let framed: Vec<Value> = pairs
                .into_iter()
                .map(|(role, text)| {
                    // Accept BOTH the canonical `assistant` AND the gemini-native `model` on the
                    // hook's reply — a hook that echoes the role it was PROJECTED (see the
                    // gemini-role canonicalization in build_prompt_projection) or one written to the
                    // gemini vocabulary must both round-trip to `model`, not silently fall through to
                    // `user` and corrupt every assistant turn. (found: audit c1r14.)
                    let g_role = if role == "assistant" || role == "model" {
                        "model"
                    } else {
                        "user"
                    };
                    serde_json::json!({ "role": g_role, "parts": [{ "text": text }] })
                })
                .collect();
            obj.insert("contents".to_string(), Value::Array(framed));
            true
        }
        PROTO_RESPONSES => {
            if obj.get("input").is_none() {
                return false;
            }
            let Some(pairs) = as_text_pairs() else {
                return false;
            };
            let framed: Vec<Value> = pairs
                .into_iter()
                .map(|(role, text)| serde_json::json!({ "role": role, "content": text }))
                .collect();
            obj.insert("input".to_string(), Value::Array(framed));
            true
        }
        // openai / anthropic / cohere: the reply IS the dialect's message shape.
        _ => {
            if !obj.get("messages").is_some_and(Value::is_array) {
                return false;
            }
            obj.insert(
                "messages".to_string(),
                Value::Array(rewrite.messages.clone()),
            );
            if !rewrite.tools.is_empty() {
                match obj.get_mut("tools").and_then(Value::as_array_mut) {
                    Some(existing) => existing.extend(rewrite.tools.iter().cloned()),
                    None => {
                        obj.insert("tools".to_string(), Value::Array(rewrite.tools.clone()));
                    }
                }
            }
            true
        }
    }
}

/// Build the request projection a rewrite (`prompt: rw`) gate receives. The prompt is ALWAYS sent (a
/// rewrite hook is a content hook); identity is omitted (rewrite operates on content, not caller
/// identity — the `user` grant projection for rewrite hooks is a follow-up). Borrows from `v`.
pub(crate) fn build_rewrite_request<'a>(
    v: &'a Value,
    pool_name: &'a str,
    ingress_protocol: &'a str,
    wants_stream: bool,
    with_prompt: bool,
) -> crate::hooks::RoutingRequest<'a> {
    let system_chars = system_text_chars(v, ingress_protocol);
    crate::hooks::RoutingRequest {
        pool: pool_name,
        ingress_protocol,
        requested_model: v.get("model").and_then(|m| m.as_str()),
        message_count: turn_count(v, ingress_protocol),
        tool_count: v
            .get("tools")
            .and_then(|t| t.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        has_tools: v
            .get("tools")
            .and_then(|t| t.as_array())
            .is_some_and(|a| !a.is_empty()),
        total_chars: total_text_chars(v, ingress_protocol, system_chars),
        system_chars,
        max_tokens: max_tokens_for(v, ingress_protocol),
        stream: wants_stream,
        // A `prompt: rw` rewrite gate needs the prompt content (`with_prompt`). A TAP gets the
        // shape-only default bucket (`with_prompt == false`) — a per-grant prompt projection for
        // `prompt: ro` taps is a follow-up; shape-only never OVER-shares, so the grant holds.
        prompt: with_prompt.then(|| build_prompt_projection(v, ingress_protocol)),
        identity: None,
    }
}

/// The GLOBAL REWRITE (transform) pass: fire each `prompt: rw` gate in PRIORITY order, each seeing the
/// prior gate's output (the projection is rebuilt from the CURRENT body every iteration — a true
/// transform chain), and apply its rewrite to the body in place. FAIL-SAFE end to end: a hook that
/// errors/times out/abstains yields `None` (`transform`) and is skipped; `apply_rewrite_to_body` only
/// touches a chat-shaped body. Zero cost when no rewrite hook is configured (the caller guards on the
/// empty list before calling).
/// Returns `Ok(applied)` — whether ANY rewrite actually committed to the body (the caller must
/// then invalidate every retained copy of the ORIGINAL bytes: the same-protocol pristine
/// short-circuit and the failover re-parse both read them, or the rewrite silently vanishes on
/// those paths) — or `Err((status, message))` when a hook REJECTED the request (audit W-H1:
/// reject > rewrite > abstain on the transform path too; a rw gate that also screens must be able
/// to stop the request — dropping its reject was fail-OPEN from the author's view).
pub(crate) async fn apply_global_rewrites(
    rewrite_hooks: &[(
        std::time::Duration,
        std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
    )],
    v: &mut Value,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
) -> Result<bool, (u16, String)> {
    let mut applied = false;
    for (timeout, hook) in rewrite_hooks {
        // Rebuild the projection from the current body so a later hook sees the earlier rewrite.
        let req = build_rewrite_request(v, pool_name, ingress_protocol, wants_stream, true);
        let outcome = hook.transform(&req, *timeout).await;
        drop(req); // end the immutable borrow of `v` before mutating it
        match outcome {
            busbar_api::TransformOutcome::Rewrite(rw) => {
                applied |= apply_rewrite_to_body(v, &rw, ingress_protocol);
            }
            busbar_api::TransformOutcome::Reject { status, message } => {
                // Already status-clamped + message-sanitized at the wire seam.
                return Err((status, message));
            }
            busbar_api::TransformOutcome::Abstain => {}
        }
    }
    Ok(applied)
}

/// The ingress body's conversation-turn array, DIALECT-AWARE — the READ-side mirror of
/// `apply_rewrite_to_body`'s write dialects: gemini carries turns in `contents`
/// (`{role, parts: [{text}]}`), the Responses API in a list `input` (`{role, content}`), and
/// every other protocol in `messages`. Reading only `messages` here made every projection
/// (rewrite request, `send_prompt`, stage-tap shape) EMPTY on gemini/responses ingress — a
/// rewrite gate saw `message_count: 0` and no prompt, so it abstained and silently no-oped.
pub(crate) fn conversation_turns<'a>(
    v: &'a Value,
    ingress_protocol: &str,
) -> Option<&'a Vec<Value>> {
    let key = match ingress_protocol {
        PROTO_GEMINI => "contents",
        PROTO_RESPONSES => "input",
        _ => "messages",
    };
    v.get(key).and_then(|m| m.as_array())
}

/// Dialect-aware conversation-turn count. The Responses API also allows a bare-string `input`
/// (one implicit user turn) — counted as 1 so the SIZE signal matches what the hook projection
/// yields for the same body.
pub(crate) fn turn_count(v: &Value, ingress_protocol: &str) -> usize {
    match conversation_turns(v, ingress_protocol) {
        Some(turns) => turns.len(),
        None => usize::from(
            ingress_protocol == PROTO_RESPONSES && v.get("input").and_then(Value::as_str).is_some(),
        ),
    }
}

/// Dialect-aware max-output-tokens SIZE signal from the pristine ingress body. The OpenAI Responses
/// API names this field `max_output_tokens` (see `proto::openai_responses`), NOT `max_tokens`, and a
/// pure responses-ingress body never carries `max_tokens` — so reading `max_tokens` unconditionally
/// projected `None` for EVERY responses request, silently blinding any routing policy or tap hook
/// that keys on the size signal. Mirrors the other dialect-aware projections (`turn_count`,
/// `system_text_chars`). Saturating narrow: an absurd cap (> u32::MAX) still signals "huge ask"
/// rather than wrapping to a small number.
pub(crate) fn max_tokens_for(v: &Value, ingress_protocol: &str) -> Option<u32> {
    let key = if ingress_protocol == PROTO_RESPONSES {
        "max_output_tokens"
    } else {
        "max_tokens"
    };
    v.get(key)
        .and_then(|m| m.as_u64())
        .map(|n| u32::try_from(n).unwrap_or(u32::MAX))
}

/// Sum the chars of every `parts[].text` string in a gemini Content object (`systemInstruction`
/// or a `contents[]` turn). Non-text parts (inlineData, functionCall, …) contribute 0.
pub(crate) fn gemini_parts_chars(content: &Value) -> usize {
    content
        .get("parts")
        .and_then(|p| p.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                .map(|t| t.chars().count())
                .sum()
        })
        .unwrap_or(0)
}

/// Chars of the request's system prompt, DIALECT-AWARE: `system` as a bare string or a block
/// array (Anthropic allows both; blocks keyed on the `text` field's presence, not on `type`),
/// gemini's `systemInstruction` (`{parts: [{text}]}`), or the Responses API's bare-string
/// `instructions`. The SAME shapes `build_prompt_projection` flattens, so the SIZE signal and
/// the opt-in content projection never diverge. Cheap v1 SIZE signal (NOT a token count).
pub(crate) fn system_text_chars(v: &Value, ingress_protocol: &str) -> usize {
    match ingress_protocol {
        PROTO_GEMINI => v
            .get("systemInstruction")
            .map(gemini_parts_chars)
            .unwrap_or(0),
        PROTO_RESPONSES => v
            .get("instructions")
            .and_then(|i| i.as_str())
            .map(|s| s.chars().count())
            .unwrap_or(0),
        _ => match v.get("system") {
            Some(Value::String(s)) => s.chars().count(),
            Some(Value::Array(blocks)) => blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                .map(|t| t.chars().count())
                .sum(),
            _ => 0,
        },
    }
}

/// Total chars across the system prompt + every conversation turn's text content, DIALECT-AWARE.
/// `content` is a bare string or an array of blocks carrying `text` (Anthropic text blocks,
/// Bedrock `[{text}]`, or Responses `input_text` blocks NESTED inside a message's `content[]`);
/// gemini turns carry `parts[].text` instead. The Responses API ALSO allows a TOP-LEVEL typed item
/// directly in `input[]` (`{type: "input_text", text: "…"}`, no `content` key) — that text lives at
/// the item root, so a responses turn with no `content` falls back to its own `text` key (mirroring
/// the proto reader). A best-effort projection over the pristine ingress body — never fails.
pub(crate) fn total_text_chars(v: &Value, ingress_protocol: &str, system_chars: usize) -> usize {
    let mut total = system_chars;
    if let Some(turns) = conversation_turns(v, ingress_protocol) {
        for m in turns {
            if ingress_protocol == PROTO_GEMINI {
                total += gemini_parts_chars(m);
                continue;
            }
            match m.get("content") {
                Some(Value::String(s)) => total += s.chars().count(),
                Some(Value::Array(blocks)) => {
                    for b in blocks {
                        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                            total += t.chars().count();
                        }
                    }
                }
                // A top-level Responses `input_text`/`output_text` item carries its text at the
                // item root, not under `content` — count it so the SIZE signal is not blinded.
                _ if ingress_protocol == PROTO_RESPONSES => {
                    if let Some(t) = m.get("text").and_then(Value::as_str) {
                        total += t.chars().count();
                    }
                }
                _ => {}
            }
        }
    } else if ingress_protocol == PROTO_RESPONSES {
        // Bare-string `input` = one implicit user turn.
        if let Some(s) = v.get("input").and_then(Value::as_str) {
            total += s.chars().count();
        }
    }
    total
}

/// Map a hook-chosen reject status to the closest dialect error KIND, so an SDK caller catches the
/// right typed exception: a hook 429 must surface as a rate-limit error, not a permission error.
/// Statuses without a natural kind (400, 422, 451, ...) read as invalid-request; 403 (the reject
/// default) stays a permission error.
pub(crate) fn reject_kind_for_status(status: u16) -> &'static str {
    match status {
        401 => KIND_AUTHENTICATION,
        403 => KIND_PERMISSION,
        404 => KIND_NOT_FOUND,
        408 => KIND_TIMEOUT,
        429 => KIND_RATE_LIMIT,
        _ => KIND_INVALID_REQUEST,
    }
}

/// The request body's end-user identifier, dialect-aware: `user` (OpenAI) first, then
/// `metadata.user_id` (Anthropic). An empty string means "no user id" in EITHER position — an
/// empty `user: ""` falls through to a populated `metadata.user_id` rather than shadowing it,
/// and empty-everywhere coalesces to `None`. Part of the `policy.send_user` identity projection.
pub(crate) fn body_end_user(v: &Value) -> Option<String> {
    v.get("user")
        .and_then(|u| u.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            v.get("metadata")
                .and_then(|m| m.get("user_id"))
                .and_then(|u| u.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string)
}

/// Flatten the ingress body's prompt content into the opt-in hook projection
/// (`policy.send_prompt`). The same content shapes as the SIZE signals (`total_text_chars` /
/// `system_text_chars`) — bare-string content and blocks carrying a `text` string (keyed on the
/// `text` field's presence, not on `type`) — but collecting
/// the text instead of counting the chars. (The flattened text joins blocks with a newline, so
/// its length can exceed the `total_chars` SIZE signal by one char per block boundary — the
/// signal counts text, not separators.) Non-text blocks (images, documents, tool results)
/// contribute NO text, but the message ENTRY is kept (possibly with empty text and, for a
/// malformed body, an empty role): entries stay index-aligned with the body's `messages` and with
/// `message_count`, so a screening hook sees every turn — a media-only turn reads as
/// `{role, text: ""}`, never silently vanishes. Bare-string content BORROWS from the parsed body
/// (`Cow::Borrowed`, the common case); only block arrays allocate a joined string. Runs ONLY
/// behind the per-pool opt-in, so even that cost never touches a default pool.
pub(crate) fn build_prompt_projection<'a>(
    v: &'a Value,
    ingress_protocol: &str,
) -> crate::hooks::PromptProjection<'a> {
    use std::borrow::Cow;
    // A content value is a bare string (borrowed as-is) or an array of blocks (text blocks joined
    // by newline into an owned string).
    fn flatten_content(c: Option<&Value>) -> Cow<'_, str> {
        match c {
            Some(Value::String(s)) => Cow::Borrowed(s.as_str()),
            Some(Value::Array(blocks)) => {
                let mut out = String::new();
                for b in blocks {
                    if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                        if !out.is_empty() {
                            out.push('\n');
                        }
                        out.push_str(t);
                    }
                }
                Cow::Owned(out)
            }
            _ => Cow::Borrowed(""),
        }
    }
    // A gemini Content object: join `parts[].text` with newlines (mirrors `gemini_parts_chars`,
    // which counts what this flattens). Borrows a lone text part (the common case).
    fn flatten_gemini_parts(c: &Value) -> Cow<'_, str> {
        match c.get("parts").and_then(|p| p.as_array()) {
            Some(parts) => {
                let mut texts = parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
                    .peekable();
                match texts.next() {
                    Some(first) if texts.peek().is_none() => Cow::Borrowed(first),
                    Some(first) => {
                        let mut out = String::from(first);
                        for t in texts {
                            out.push('\n');
                            out.push_str(t);
                        }
                        Cow::Owned(out)
                    }
                    None => Cow::Borrowed(""),
                }
            }
            None => Cow::Borrowed(""),
        }
    }
    let system = match ingress_protocol {
        PROTO_GEMINI => v.get("systemInstruction").map(flatten_gemini_parts),
        PROTO_RESPONSES => v
            .get("instructions")
            .and_then(|i| i.as_str())
            .map(Cow::Borrowed),
        _ => v.get("system").map(|s| flatten_content(Some(s))),
    }
    .filter(|s| !s.is_empty());
    let messages = match conversation_turns(v, ingress_protocol) {
        Some(turns) => turns
            .iter()
            .map(|m| {
                let text = if ingress_protocol == PROTO_GEMINI {
                    flatten_gemini_parts(m)
                } else if ingress_protocol == PROTO_RESPONSES && m.get("content").is_none() {
                    // A top-level Responses typed item (`{type: "input_text"/"output_text", text}`)
                    // carries its text at the item root, not under `content`.
                    m.get("text")
                        .and_then(Value::as_str)
                        .map_or(Cow::Borrowed(""), Cow::Borrowed)
                } else {
                    flatten_content(m.get("content"))
                };
                let role: Cow<'_, str> = match m.get("role").and_then(|r| r.as_str()) {
                    // CANONICALIZE the gemini-native assistant role `model` → `assistant` so a
                    // `prompt: rw` hook sees the SAME canonical-IR vocabulary on every dialect (the
                    // hook contract promises normalized IR). Without this a hook that echoes the role
                    // it received emitted `model`, which the gemini write-back then mapped to `user`,
                    // silently corrupting assistant turns. Mirrors the responses arm below. (c1r14.)
                    Some("model") if ingress_protocol == PROTO_GEMINI => Cow::Borrowed("assistant"),
                    Some(r) => Cow::Borrowed(r),
                    // Top-level typed item without a `role`: infer from its `type` so a `prompt: rw`
                    // hook sees the correct speaker (`output_text` = assistant, else user).
                    None if ingress_protocol == PROTO_RESPONSES => {
                        match m.get("type").and_then(Value::as_str) {
                            Some("output_text") => Cow::Borrowed("assistant"),
                            _ => Cow::Borrowed("user"),
                        }
                    }
                    None => Cow::Borrowed(""),
                };
                (role, text)
            })
            .collect(),
        // The Responses API's bare-string `input` = one implicit user turn.
        None if ingress_protocol == PROTO_RESPONSES => v
            .get("input")
            .and_then(Value::as_str)
            .map(|s| vec![(Cow::Borrowed("user"), Cow::Borrowed(s))])
            .unwrap_or_default(),
        None => Vec::new(),
    };
    crate::hooks::PromptProjection { system, messages }
}

/// Build the routing projection (request + candidates + context) and run the resolved policy ONCE,
/// bounded by its configured timeout, coercing the result to a `PolicyOutcome` per `on_error`.
///
/// This runs ONLY for a pool with a non-default `route:` — the zero-cost default path never calls it
/// and never constructs any of these projection types. Every signal is REAL data: `cost_per_mtok`
/// from member config, `latency_ms` from the per-lane EWMA, `available_concurrency` from the lane
/// semaphore, `budget_remaining` from the lane budget, and `rate_headroom` from the caller key's
/// governance rate window. A policy error/timeout NEVER reaches the client: it degrades per `on_error`
/// (weighted / reject / first).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn decide_policy_order(
    app: &Arc<App>,
    resolved: &crate::hooks::ResolvedPolicy,
    cands: &[WeightedLane],
    request_ctx: &RequestCtx,
    v: &Value,
    pool_name: &str,
    ingress_protocol: &str,
    wants_stream: bool,
    caller_token: Option<&str>,
    resolved_gov_key: Option<&std::sync::Arc<crate::governance::VirtualKey>>,
) -> PolicyOutcome {
    use crate::hooks::{
        Candidate, ResolvedPolicy, RoutingContext, RoutingDecision, RoutingRequest,
    };

    // A weighted/default pool resolves to `None` at config load (no policy object is constructed), so
    // the only `ResolvedPolicy` that can reach this seam is a constructed `Policy`.
    let (policy, on_error, on_error_chain, timeout, send_prompt, send_user, on_empty) =
        match resolved {
            ResolvedPolicy::Policy {
                policy,
                on_error,
                on_error_chain,
                timeout,
                send_prompt,
                send_user,
                on_empty,
            } => (
                policy,
                on_error,
                on_error_chain,
                *timeout,
                *send_prompt,
                *send_user,
                on_empty,
            ),
        };

    // The candidate set the policy ranks over = this pool's members MINUS the already-excluded ones
    // (configured exclusions). `idx` is the stable lane handle the ordered walk speaks.
    let mut live_buf: Vec<&WeightedLane> = Vec::with_capacity(cands.len());
    request_ctx.fill_candidates(cands, &mut live_buf);
    let live = &live_buf;
    if live.is_empty() {
        // Nothing to rank — let the loop's exhaustion handling take over (SWRR will also find none).
        return PolicyOutcome::Weighted;
    }

    // ONE governance key serves both consumers: the per-key rate headroom (always, same value
    // across candidates today — rate limits are per-key; see `Candidate.rate_headroom`) and, behind
    // `policy.send_user`, the caller identity projection. A virtual-key caller resolves via
    // `lookup` (which CONSUMES the secret; only the returned key RECORD flows forward — nothing
    // downstream sees the token). A GROUP/SSO principal's token is NOT a virtual-key secret, so
    // `lookup` misses — fall back to the key the auth layer already SYNTHESIZED for it (carried in
    // `GovCtx.key`, threaded here as `resolved_gov_key`). Without this fallback `rate_headroom` and
    // `identity` were silently `None` for every group principal, blinding usage/identity policies.
    let gov = app.governance.as_ref();
    let gov_key = match (gov, caller_token) {
        (Some(g), Some(tok)) => g.lookup(tok),
        _ => None,
    }
    .or_else(|| resolved_gov_key.cloned());
    let rate_headroom: Option<f64> = match (gov, gov_key.as_ref()) {
        (Some(g), Some(key)) => g.rate_headroom(key, now()),
        _ => None,
    };

    // `policy.send_user` opt-in (default off): project the caller identity — the virtual key's
    // id/name (from the resolved record, NEVER the token) plus the body's end-user field (`user` in
    // the OpenAI dialect, `metadata.user_id` in the Anthropic dialect).
    let identity = if send_user {
        let body_user = body_end_user(v);
        Some(crate::hooks::CallerIdentity {
            key_id: gov_key.as_ref().map(|k| k.id.clone()),
            key_name: gov_key.as_ref().map(|k| k.name.clone()),
            user: body_user,
        })
    } else {
        None
    };

    // `policy.send_prompt` opt-in (default off): flatten the prompt content for the hook. The
    // allocation cost lives entirely behind the flag — a shape-only pool never runs this.
    let prompt = if send_prompt {
        Some(build_prompt_projection(v, ingress_protocol))
    } else {
        None
    };

    let member_meta = app.pool_runtime.get(pool_name).map(|r| &r.members);

    // Count the system prompt's chars ONCE: it feeds both `total_chars` (via `total_text_chars`) and
    // `system_chars`, so computing it inline twice would run the O(n) UTF-8 scan over the system block
    // twice. Off the zero-cost default path (only non-default route policies reach here).
    let system_chars = system_text_chars(v, ingress_protocol);

    let req = RoutingRequest {
        pool: pool_name,
        ingress_protocol,
        requested_model: v.get("model").and_then(|m| m.as_str()),
        message_count: turn_count(v, ingress_protocol),
        tool_count: v
            .get("tools")
            .and_then(|t| t.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        has_tools: v
            .get("tools")
            .and_then(|t| t.as_array())
            .is_some_and(|a| !a.is_empty()),
        total_chars: total_text_chars(v, ingress_protocol, system_chars),
        system_chars,
        // Saturating narrow (in `max_tokens_for`): an absurd caller cap (> u32::MAX) still signals
        // "huge ask" to the policy instead of wrapping to a small number. A SIZE signal, not a limit.
        max_tokens: max_tokens_for(v, ingress_protocol),
        stream: wants_stream,
        prompt,
        identity,
    };

    let candidates: Vec<Candidate> = live
        .iter()
        .map(|wl| {
            let lane = &app.lanes[wl.idx];
            let meta = member_meta.and_then(|m| m.get(&wl.idx));
            Candidate {
                idx: wl.idx,
                model: &lane.model,
                provider: &lane.provider,
                weight: wl.weight,
                context_max: lane.context_max,
                tier: meta.and_then(|m| m.tier.as_deref()),
                cost_per_mtok: meta.and_then(|m| m.cost_per_mtok),
                tags: meta.map(|m| m.tags.as_slice()).unwrap_or(&[]),
                latency_ms: app.store.lane_latency_ms(wl.idx),
                available_concurrency: app.store.available_permits(wl.idx),
                budget_remaining: app.store.lane_budget_remaining(wl.idx),
                rate_headroom,
            }
        })
        .collect();

    // The HOOK SEAM's budget projection (cost-model spec §9): for the caller key and each ancestor
    // budget group, {bucket_id, spend_micros_at_current_rate, remaining_micros, window} - derived
    // fresh from the token ledger x the CURRENT rate card at this moment. Built ONLY here (a
    // routing-policy pool; the zero-cost default path never runs this fn), so its allocation stays
    // off the default hot path. Busbar exposes the READ surface only; downshifting to a cheaper
    // model on it is the hook's policy, never core's.
    let budget_chain: Vec<busbar_api::BudgetBucketState> = match (gov, gov_key.as_ref()) {
        (Some(g), Some(key)) => g.budget_state(&app.cost, key, now()),
        _ => Vec::new(),
    };
    let ctx = RoutingContext {
        pool: pool_name,
        // Lane-health-shaped budget signal (legacy v1 field): still not fed - the per-request
        // budget signal now rides the structured `budget` chain below.
        budget_remaining: None,
        budget: &budget_chain,
    };

    // Run the decision under a HARD wall-clock timeout (the policy is also asked to respect `budget`).
    // A timeout or an `Err` is coerced to `on_error`; an impl that simply has no opinion returns
    // `Ok(Abstain)`. The decision NEVER blocks past `timeout` and NEVER propagates an error to the
    // client.
    let decision: RoutingDecision = match tokio::time::timeout(
        timeout,
        policy.decide(&req, &candidates, &ctx, timeout),
    )
    .await
    {
        Ok(Ok(d)) => d,
        // Policy errored: apply on_error — but LOG the error first. A hook binary that is down,
        // deadline-exceeded, or replying garbage would otherwise fail silently on every request
        // (the pool degrades to on_error with no operator-visible signal that the hook is broken).
        Ok(Err(e)) => {
            tracing::warn!(
                policy = policy.name(),
                pool = pool_name,
                error = %e,
                "routing policy failed; applying on_error fallback"
            );
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
        // Timed out at the seam's own hard deadline: same fallback, same visibility. The policy/
        // transport stays cancel-safe — a dropped future on timeout is fine.
        Err(_) => {
            tracing::warn!(
                policy = policy.name(),
                pool = pool_name,
                timeout_ms = timeout.as_millis() as u64,
                "routing policy deadline exceeded; applying on_error fallback"
            );
            return run_on_error_chain(
                on_error_chain,
                on_error,
                &req,
                &candidates,
                &ctx,
                policy.name(),
                pool_name,
            )
            .await;
        }
    };

    map_decision(decision, policy.name(), &candidates, on_empty)
}

/// Walk a failed gate's resolved `on_error` fallback CHAIN: fire each fallback in order (bounded by
/// ITS deadline, projected per ITS grants — a fallback never sees prompt/identity its own grants
/// don't allow), and let the FIRST one that answers decide, exactly as a primary decision would.
/// Every link failing lands on the chain's reserved TERMINAL (weighted/reject/first). The common
/// case — `on_error: weighted` etc. — has an EMPTY chain and goes straight to the terminal.
pub(crate) async fn run_on_error_chain(
    chain: &[crate::hooks::FallbackHook],
    terminal: &crate::config::PolicyOnError,
    req: &crate::hooks::RoutingRequest<'_>,
    candidates: &[crate::hooks::Candidate<'_>],
    ctx: &crate::hooks::RoutingContext<'_>,
    failed_policy_name: &'static str,
    pool_name: &str,
) -> PolicyOutcome {
    for fb in chain {
        // Re-project per the FALLBACK's grants: it may see at most what the primary projection
        // built AND its own grants allow (never over-shares; a fallback with a grant the primary
        // lacked gets shape-only — the projection was never built).
        let fb_req = crate::hooks::RoutingRequest {
            prompt: if fb.send_prompt {
                req.prompt.clone()
            } else {
                None
            },
            identity: if fb.send_user {
                req.identity.clone()
            } else {
                None
            },
            ..req.clone()
        };
        match tokio::time::timeout(
            fb.timeout,
            fb.policy.decide(&fb_req, candidates, ctx, fb.timeout),
        )
        .await
        {
            Ok(Ok(decision)) => {
                tracing::info!(
                    policy = failed_policy_name,
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    "on_error fallback hook answered for the failed gate"
                );
                return map_decision(decision, fb.policy.name(), candidates, &fb.on_empty);
            }
            // This link failed too — follow the chain to the next (its own on_error was flattened
            // into this chain at resolution).
            Ok(Err(e)) => {
                tracing::warn!(
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    error = %e,
                    "on_error fallback hook failed; continuing down the chain"
                );
            }
            Err(_) => {
                tracing::warn!(
                    fallback = fb.policy.name(),
                    pool = pool_name,
                    timeout_ms = fb.timeout.as_millis() as u64,
                    "on_error fallback hook deadline exceeded; continuing down the chain"
                );
            }
        }
    }
    coerce_on_error(terminal, candidates, failed_policy_name)
}

/// Map a policy's `RoutingDecision` to the seam's `PolicyOutcome` — shared by the primary decision
/// and every on_error fallback, so a fallback's reject/restrict/order carries the same clamping,
/// sanitizing, and normalization guarantees as a primary's.
pub(crate) fn map_decision(
    decision: crate::hooks::RoutingDecision,
    policy_name: &'static str,
    candidates: &[crate::hooks::Candidate<'_>],
    on_empty: &crate::config::PolicyOnError,
) -> PolicyOutcome {
    use crate::hooks::RoutingDecision;

    match decision {
        RoutingDecision::Prefer(order) => {
            // Normalize against the valid candidate idxs (drop unknown, dedup). An empty result is
            // Abstain — fall through to SWRR.
            let valid: std::collections::HashSet<usize> =
                candidates.iter().map(|c| c.idx).collect();
            match RoutingDecision::from_ranked(order, &valid) {
                RoutingDecision::Prefer(o) => PolicyOutcome::Order {
                    order: o,
                    name: policy_name,
                },
                RoutingDecision::Abstain => PolicyOutcome::Weighted,
                // `from_ranked` only ever produces Prefer/Abstain — it normalizes an order, it
                // cannot invent a rejection or a restriction.
                RoutingDecision::Reject { .. } => unreachable!("from_ranked never rejects"),
                RoutingDecision::Restrict { .. } => {
                    unreachable!("from_ranked never restricts")
                }
            }
        }
        // Abstain is the clean "no opinion" — today's exact SWRR (NOT coerced via on_error).
        RoutingDecision::Abstain => PolicyOutcome::Weighted,
        // The hook's reject verb: a deliberate first-class decision (a guardrail said no), NOT an
        // error — `on_error` does not apply. The shipped transports produce Reject only through
        // `wire::normalize` (clamped + sanitized), but the trait lets ANY policy impl construct
        // the variant directly — so the seam re-clamps the status to 400..=499 (else 403) AND
        // re-sanitizes the message (same shared sanitizer, idempotent on already-clean input) as
        // defense in depth: no policy, present or future, can mint a success/redirect/5xx or a
        // log/client-injecting message through this path.
        RoutingDecision::Reject { status, message } => PolicyOutcome::RejectRequest {
            status: crate::hooks::wire::clamp_reject_status(status),
            message: crate::hooks::wire::sanitize_reject_message(&message),
            name: policy_name,
        },
        // The hook's RESTRICT verb: keep only candidates carrying one of `tags_any` (a compliance
        // gate). The intersection + on_empty are applied at the failover-set seam in `forward_with_
        // pool`; here we just carry the tag set through. An empty `tags_any` (malformed restrict,
        // normalized fail-closed) forces the empty intersection → on_empty, never allow-all.
        RoutingDecision::Restrict { tags_any } => PolicyOutcome::Restrict {
            tags_any,
            name: policy_name,
            on_empty: on_empty.clone(),
        },
    }
}

/// Coerce an `on_error` fallback into a `PolicyOutcome` when the policy errored / timed out:
/// `weighted` ⇒ SWRR, `first` ⇒ the config member order (a deterministic degraded pick), `reject`
/// ⇒ a 503. `first` advertises the policy name so the degraded pick is still observable.
pub(crate) fn coerce_on_error(
    on_error: &crate::config::PolicyOnError,
    candidates: &[crate::hooks::Candidate<'_>],
    policy_name: &'static str,
) -> PolicyOutcome {
    use crate::config::PolicyOnError;
    match on_error {
        PolicyOnError::Weighted => PolicyOutcome::Weighted,
        PolicyOnError::Reject => PolicyOutcome::Reject,
        PolicyOnError::First => PolicyOutcome::Order {
            order: candidates.iter().map(|c| c.idx).collect(),
            name: policy_name,
        },
    }
}

/// Shape scalars captured ONCE per request for the STAGE tap payloads (route/attempt/completion).
/// All owned/`'static`-free scalars except the pool/protocol names (which outlive the request), so
/// the capture survives `v` being consumed by the first dispatch hop. Stage taps are SHAPE-ONLY in
/// this increment: the default signal bucket plus the stage object — never prompt content or caller
/// identity, regardless of grant (never over-shares; a granted tap still gets content at the
/// `request` stage).
pub(crate) struct StageShape<'a> {
    pool: &'a str,
    ingress_protocol: &'a str,
    message_count: usize,
    has_tools: bool,
    total_chars: usize,
    max_tokens: Option<u32>,
    stream: bool,
}

/// Capture the stage-tap shape from the parsed body (`None` = an opaque/binary body: zeroed shape).
pub(crate) fn capture_stage_shape<'a>(
    v: Option<&Value>,
    pool: &'a str,
    ingress_protocol: &'a str,
    stream: bool,
) -> StageShape<'a> {
    let (message_count, has_tools, total_chars, max_tokens) = match v {
        Some(v) => {
            let system_chars = system_text_chars(v, ingress_protocol);
            (
                turn_count(v, ingress_protocol),
                v.get("tools")
                    .and_then(|t| t.as_array())
                    .is_some_and(|a| !a.is_empty()),
                total_text_chars(v, ingress_protocol, system_chars),
                max_tokens_for(v, ingress_protocol),
            )
        }
        None => (0, false, 0, None),
    };
    StageShape {
        pool,
        ingress_protocol,
        message_count,
        has_tools,
        total_chars,
        max_tokens,
        stream,
    }
}

/// Fire one STAGE's taps (route/attempt/completion) fire-and-forget: serialize the shape-only
/// projection + stage object ONCE, then spawn one detached task per tap. A tap can never delay,
/// reorder, or fail the request; a serialization failure silently skips the fire (observation is
/// best-effort). ZERO COST when the stage has no taps (first-line empty check).
pub(crate) fn fire_stage_taps(
    taps: &[(
        std::time::Duration,
        bool,
        Arc<dyn crate::hooks::RoutingPolicy>,
    )],
    shape: &StageShape<'_>,
    stage: crate::hooks::wire::HookStageProjection<'_>,
) {
    if taps.is_empty() {
        return;
    }
    let hook_req = crate::hooks::wire::HookRequest {
        op: crate::hooks::wire::OP_NOTIFY,
        request: crate::hooks::wire::HookReqProjection {
            pool: shape.pool,
            ingress_protocol: shape.ingress_protocol,
            message_count: shape.message_count,
            has_tools: shape.has_tools,
            total_chars: shape.total_chars,
            max_tokens: shape.max_tokens,
            stream: shape.stream,
            system: None,
            messages: None,
            user: None,
        },
        candidates: Vec::new(),
        context: crate::hooks::wire::HookContext {
            budget: &[],
            budget_remaining: None,
        },
        stage: Some(stage),
    };
    let Ok(bytes) = crate::json::to_vec(&hook_req) else {
        return;
    };
    let bytes = std::sync::Arc::new(bytes);
    for (timeout, _send_prompt, hook) in taps {
        let policy = hook.clone();
        let budget = *timeout;
        let proj = bytes.clone();
        spawn_bounded_tap(async move { policy.notify(&proj, budget).await });
    }
}

/// Hard cap on concurrently in-flight fire-and-forget tap notifications. Taps fan out per stage x per
/// tap hook x per request, so a slow/unreachable tap endpoint could otherwise accumulate unbounded
/// Tokio tasks under load (OOM/DoS). Mirrors the bounded webhook-delivery guard in `observability`.
const MAX_INFLIGHT_TAP_NOTIFICATIONS: usize = 1024;
static TAP_INFLIGHT: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
fn tap_inflight() -> &'static tokio::sync::Semaphore {
    TAP_INFLIGHT.get_or_init(|| tokio::sync::Semaphore::new(MAX_INFLIGHT_TAP_NOTIFICATIONS))
}
struct TapInflightGuard;
impl Drop for TapInflightGuard {
    fn drop(&mut self) {
        tap_inflight().add_permits(1);
    }
}

/// Spawn a bounded fire-and-forget tap notification: at most MAX_INFLIGHT_TAP_NOTIFICATIONS run
/// concurrently; when saturated the notification is dropped (metric) instead of accumulating tasks.
/// The permit rides an RAII guard into the task so the slot is returned even on a task panic.
pub(crate) fn spawn_bounded_tap<F>(fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let Ok(permit) = tap_inflight().try_acquire() else {
        metrics::counter!(crate::metrics::TAP_NOTIFICATIONS_DROPPED_TOTAL).increment(1);
        return;
    };
    permit.forget();
    let guard = TapInflightGuard;
    tokio::spawn(async move {
        let _guard = guard;
        fut.await;
    });
}

/// Response-extension marker set by every GATE-produced rejection return, so the completion-stage
/// taps can report the SYNTHETIC `rejected_by_gate` outcome (audit taps see denials) instead of a
/// generic `failed`.
#[derive(Clone)]
pub(crate) struct GateRejected;

/// Tag a gate-produced rejection response with the [`GateRejected`] marker.
pub(crate) fn gate_rejected(mut resp: Response) -> Response {
    resp.extensions_mut().insert(GateRejected);
    resp
}
