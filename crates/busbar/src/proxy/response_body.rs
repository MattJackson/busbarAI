use super::*;

/// Where to charge a request's token usage when its response stream completes (the resolved virtual
/// key + its budget period + the governance store). `None` when governance is off or no key resolved.
#[derive(Clone)]
pub(crate) struct UsageSink {
    pub(crate) gov: Arc<crate::governance::GovState>,
    pub(crate) key_id: String,
    pub(crate) period: String,
    /// Wall-clock epoch (seconds) captured ONCE at header-arrival time for this request. Both the
    /// flat per-request fee (`ingress::budget_check` → `try_charge_request_within_budget`) and the token fee (`record_tokens`,
    /// fired at stream end / on the buffered path) are attributed to the window this epoch implies,
    /// so a single streaming request whose stream completes in a later rate-limit/budget window than
    /// its headers arrived cannot split its two charges across two windows (#29). Without it, the two
    /// calls read the clock independently and could land in different 60s rate windows / budget
    /// periods, mis-attributing spend and TPM.
    pub(crate) charged_at: u64,
}

/// Body wrapper that drives IR-based usage extraction, billing, and mid-stream error handling for
/// streaming responses.
pub(crate) struct FirstByteBody<S, P> {
    inner: S,
    first_byte_sent: Arc<AtomicBool>,
    /// True when the upstream body is an incremental stream (SSE or AWS event-stream). Drives the
    /// after-first-byte error-emission behavior (vs. propagating the error for pre-first-byte
    /// failover). Derived from the UPSTREAM Content-Type.
    is_sse: bool,
    /// The INGRESS protocol the CLIENT speaks (NOT the upstream/egress protocol). A mid-stream error
    /// is emitted in THIS protocol's framing so a native client SDK can decode it — keying the
    /// framing decision off the upstream CT (which on a cross-protocol reframe describes the egress,
    /// not the client) was the bug.
    ingress_protocol: Box<str>,
    /// The operation this response belongs to. Drives whether the non-stream body is buffered for
    /// usage extraction (`taps_nonstream_usage`) and how usage is read from it (`extract_usage`).
    /// Chat reads the egress reader's IR usage; a flat-fee op taps nothing.
    op: crate::handlers::Op,
    /// True when the INGRESS client decodes a binary `application/vnd.amazon.eventstream` body (a
    /// native AWS SDK Bedrock client). A mid-stream error must then be a BINARY exception frame, not
    /// an SSE `event: error` text frame — writing SSE text into a binary eventstream body yields an
    /// undecodable prelude/CRC for the SDK's decoder. Independent of `is_sse` (which reflects the
    /// upstream CT) so a bedrock-ingress → SSE-egress reframe is handled correctly.
    ingress_eventstream: bool,
    permit: Option<P>,
    app: Option<Arc<App>>,
    lane_idx: usize,
    /// Resolved breaker config for the routing pool, so a mid-stream failure trips this lane using
    /// the same thresholds the synchronous path used (defaults on the degraded path).
    breaker_cfg: Arc<crate::store::BreakerCfg>,
    /// Routing pool name, so a mid-stream failure trips this lane's per-pool breaker cell (empty on
    /// the degraded path → the lane-default cell).
    pool: Box<str>,
    /// when Some, translate each egress SSE chunk to the caller's ingress protocol.
    /// None = native passthrough (same-protocol or non-SSE).
    translate: Option<crate::proto::StreamTranslate>,
    /// When set (gemini ingress streaming WITHOUT `?alt=sse`), the SSE bytes — whether from a
    /// same-protocol passthrough or the cross-protocol `translate` stage above, both of which are
    /// gemini SSE here — are reframed into the JSON-array streaming format the native non-`alt=sse`
    /// `:streamGenerateContent` request expects (`[{...},{...}]`). Runs AFTER `translate`.
    json_array: Option<Box<dyn crate::proto::JsonArrayFramer>>,
    /// When set, the token usage tapped from this response is charged to a virtual key's budget at
    /// stream end (token-accurate accounting). Taken (fired) exactly once when the stream completes.
    usage_sink: Option<UsageSink>,
    /// True when the 2xx-headers `spend_budget(lane_idx)` on this request actually decremented the
    /// lane's `max_requests` budget. A pre-first-byte upstream transport failure on the streaming
    /// path delivers NO usable body, so it must refund that unit — symmetric with the buffered
    /// `ReadEnd::TransportError` path (#21). Guarding the refund on this flag keeps `refund_budget`
    /// (an unconditional `fetch_add`) from raising the budget above its cap when the spend was a
    /// no-op (unlimited lane, or budget already 0). Cleared once a refund fires so it happens once.
    budget_spent: bool,
    /// Set once the stream has fully ended (after any translation terminator), so a later poll
    /// returns None instead of re-polling a finished inner stream.
    ended: bool,
    /// Bounded reassembly buffer for a SAME-PROTOCOL NON-STREAM (`!is_sse`, `translate == None`)
    /// `application/json` body that reqwest delivers across multiple transport frames. This is the
    /// non-stream analog of Change B's read-for-IR-emit-verbatim: the body is relayed to the client
    /// byte-for-byte (each chunk passes through unchanged), but a bounded copy is retained here so the
    /// stream-end arm can run the EGRESS READER over the reassembled body and source `IrUsage` for
    /// billing (Change A path #4). Same-proto means egress == ingress, so the body is in the ingress
    /// protocol's native shape and `ingress_protocol`'s reader decodes it. Capped at
    /// `MAX_TRANSLATED_BODY_BYTES` (dropping past the cap with a warn like the buffered guards). The
    /// SSE / translation paths never touch this (they bill via `translate.usage()`).
    nonstream_buf: Vec<u8>,
}

impl<S, P> FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        inner: S,
        is_sse: bool,
        ingress_protocol: &str,
        op: crate::handlers::Op,
        permit: P,
        app: Arc<App>,
        lane_idx: usize,
        breaker_cfg: Arc<crate::store::BreakerCfg>,
        pool: &str,
        translate: Option<crate::proto::StreamTranslate>,
        json_array: Option<Box<dyn crate::proto::JsonArrayFramer>>,
        usage_sink: Option<UsageSink>,
        budget_spent: bool,
    ) -> Self {
        Self {
            inner,
            first_byte_sent: Arc::new(AtomicBool::new(false)),
            is_sse,
            // Resolve the ingress protocol's writer ONCE to determine whether the client expects a
            // binary event-stream body (Bedrock) rather than SSE text. Dispatches through the
            // `ingress_is_eventstream` vtable method so this constructor carries no `== "bedrock"`
            // branch — a future protocol with a binary framing just overrides the method.
            ingress_eventstream: crate::proto::protocol_for(ingress_protocol)
                .map(|p| p.writer().ingress_is_eventstream())
                .unwrap_or(false),
            ingress_protocol: Box::from(ingress_protocol),
            op,
            permit: Some(permit),
            app: Some(app),
            lane_idx,
            breaker_cfg,
            pool: Box::from(pool),
            translate,
            json_array,
            usage_sink,
            budget_spent,
            ended: false,
            nonstream_buf: Vec::new(),
        }
    }
}

impl<S, P> Stream for FirstByteBody<S, P>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
    P: Send + Unpin + 'static,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(None);
        }
        // Loop so a translated chunk that yields no complete frame yet (partial) re-polls the
        // inner stream instead of emitting an empty chunk to the client.
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if !this.first_byte_sent.load(Ordering::Relaxed) {
                        this.first_byte_sent.store(true, Ordering::Relaxed);
                    }
                    // cross-protocol → translate egress SSE bytes to the ingress format. SAME-protocol
                    // (Change B) → `t.feed` returns the VERBATIM original frame bytes. Billing now reads
                    // the IR-derived `t.usage()` at stream end (Change A) — there is no longer a byte-
                    // scanner tap on this path, so `feed` is the single usage source for both modes.
                    if let Some(t) = this.translate.as_mut() {
                        let out = t.feed(&chunk);
                        let out_bytes = Bytes::from(out);
                        // Gemini non-`alt=sse` ingress: reframe the (now gemini-SSE) bytes into the
                        // JSON-array streaming shape. Run AFTER translate so accounting is unaffected.
                        if let Some(framer) = this.json_array.as_mut() {
                            let framed = framer.feed(&out_bytes);
                            if framed.is_empty() {
                                continue; // no complete object yet; poll inner again
                            }
                            return Poll::Ready(Some(Ok(Bytes::from(framed))));
                        }
                        if out_bytes.is_empty() {
                            continue; // only a partial frame buffered; poll inner again
                        }
                        return Poll::Ready(Some(Ok(out_bytes)));
                    }
                    // Passthrough: the raw chunk is already in the client's shape. This branch is reached
                    // only for (a) a SAME-PROTOCOL NON-STREAM (`!is_sse`) `application/json` body — the
                    // streaming SSE/eventstream same-proto path always builds a `Some(translate)` now —
                    // and (b) the unknown-protocol fallback (`new_same_proto` returned `None`), which has
                    // no reader to drive the IR and therefore no usage source. The bytes always stream to
                    // the client unchanged; for (a) we retain a bounded copy for IR-based billing below.
                    // Only buffer when the operation actually taps usage from the body. Chat and the
                    // token-billed ops do; a flat-fee op (or a large-binary response) skips the copy
                    // entirely — the bytes still relay verbatim below, unbuffered.
                    if !this.is_sse && this.op.taps_nonstream_usage() {
                        // SAME-PROTOCOL NON-STREAM `application/json` passthrough (Change A path #4): the
                        // non-stream analog of B's read-for-IR-emit-verbatim. The body relays verbatim,
                        // but a bounded copy is retained so the stream-end arm can run the egress reader
                        // (`ingress_protocol`'s reader — same-proto, so egress == ingress) over the
                        // reassembled body and source `IrUsage` for billing. Cap at
                        // `MAX_TRANSLATED_BODY_BYTES`; past the cap, drop the overflow with a warn
                        // (matching the buffered `read_capped` guards) — the tail `usage` may then be
                        // missed, but the gap is observable, not a memory leak.
                        if this.nonstream_buf.len() < max_translated_body_bytes() {
                            let remaining = max_translated_body_bytes() - this.nonstream_buf.len();
                            if chunk.len() <= remaining {
                                this.nonstream_buf.extend_from_slice(&chunk);
                            } else {
                                this.nonstream_buf.extend_from_slice(&chunk[..remaining]);
                                // Fires once per response (the next chunk sees buf == cap and skips
                                // this arm). Count it so the undercount is alertable on a dashboard,
                                // not just visible in a log line an operator has to be watching for.
                                metrics::counter!(crate::metrics::BILLING_TRUNCATED_TOTAL)
                                    .increment(1);
                                tracing::warn!(
                                    buffered = this.nonstream_buf.len(),
                                    cap = max_translated_body_bytes(),
                                    "same-protocol non-stream body exceeded the usage-tap reassembly \
                                     cap; if the tail usage frame fell past the cap, this request's \
                                     tokens are undercounted (TPM/spend may be undercharged)"
                                );
                            }
                        }
                    }
                    // Gemini same-protocol passthrough WITHOUT `?alt=sse` on the unknown-protocol
                    // fallback: the upstream chunk is gemini SSE (busbar always requests `?alt=sse`
                    // upstream); reframe it into the JSON-array streaming shape the native client
                    // expects. (The known-protocol gemini same-proto path runs through `translate`.)
                    if let Some(framer) = this.json_array.as_mut() {
                        let framed = framer.feed(&chunk);
                        if framed.is_empty() {
                            continue; // no complete object yet; poll inner again
                        }
                        return Poll::Ready(Some(Ok(Bytes::from(framed))));
                    }
                    return Poll::Ready(Some(Ok(chunk)));
                }
                Poll::Ready(Some(Err(e))) => {
                    let had_first = this.first_byte_sent.load(Ordering::Relaxed);
                    if had_first && this.is_sse {
                        // Mid-stream failure after first byte in SSE mode: record breaker failure then emit SSE error event
                        if let Some(ref app) = this.app {
                            let tripped = app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                "mid-stream",
                                &this.breaker_cfg,
                                None,
                            );
                            // A mid-stream failure that drives a Closed→Open trip is a breaker trip
                            // for this (pool, lane) — emit BREAKER_TRIPS_TOTAL once (#29).
                            if tripped {
                                emit_breaker_trip(app, &this.pool, this.lane_idx);
                            }
                        }
                        // Mark the stream ended so the subsequent `Poll::Ready(None)` arm returns
                        // early instead of re-recording this same failure (the inner stream closes
                        // with `None` right after the error). Without this, one mid-stream transport
                        // failure double-counted against the breaker.
                        drop(this.permit.take());
                        this.ended = true;
                        // The raw reqwest/transport error (`e`) must NEVER reach the client body: its
                        // Display embeds hyper/reqwest/tokio internals and the egress backend URL
                        // (hostname, region, port) — a protocol-indistinguishability tell (no native
                        // AI vendor emits hyper/reqwest strings) AND an infrastructure-disclosure leak.
                        // Log the real cause server-side for operator observability, then put only a
                        // static, vendor-neutral detail into the client-facing frame. A native vendor
                        // mid-stream interruption carries a generic message, never a backend URL.
                        tracing::warn!(
                            ingress = %this.ingress_protocol,
                            error = %e,
                            "mid-stream upstream transport error; returning generic interruption to client"
                        );
                        // Gemini JSON-array ingress (non-`alt=sse`): the client has been receiving a
                        // streaming JSON ARRAY (`[obj,obj`), so the in-band error MUST be a valid
                        // trailing array element followed by the closing `]` — NOT the SSE text frame
                        // `mid_stream_error_bytes` produces. Emitting `event: error\ndata:{...}` into a
                        // JSON-array body splices non-JSON into the array (unparseable) and is a
                        // protocol tell (a native Gemini JSON-array stream never contains SSE framing).
                        // Route the error through the framer instead: a Gemini `google.rpc.Status`
                        // element + `]`.
                        if let Some(framer) = this.json_array.as_mut() {
                            // The framer owns the wire status/code shape (Gemini → 500/`INTERNAL`); the
                            // agnostic core supplies only the generic message.
                            let err_bytes =
                                framer.finish_with_server_error(MID_STREAM_GENERIC_DETAIL);
                            return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                        }
                        // Emit the error in the INGRESS protocol's framing, NOT a hard-coded SSE
                        // text frame. For a bedrock-ingress client (binary eventstream) this is a
                        // valid AWS exception frame; for SSE clients it is shaped to the ingress
                        // protocol's native error envelope. Keying off `is_sse` (the upstream CT)
                        // alone would inject SSE text into a binary eventstream body on a
                        // bedrock-ingress → SSE-egress reframe — an undecodable frame for the SDK.
                        let err_bytes = mid_stream_error_bytes(
                            &this.ingress_protocol,
                            this.ingress_eventstream,
                            MID_STREAM_GENERIC_DETAIL,
                        );
                        return Poll::Ready(Some(Ok(Bytes::from(err_bytes))));
                    } else {
                        // Before first byte or non-SSE: terminate the body stream with an error. The
                        // raw reqwest error (with its embedded backend URL / hyper internals) must not
                        // ride out on the io::Error either — log the real cause server-side and surface
                        // only a generic, vendor-neutral message on the stream item.
                        tracing::warn!(
                            ingress = %this.ingress_protocol,
                            error = %e,
                            "pre-first-byte upstream transport error; terminating body stream generically"
                        );
                        // Mid-BODY transport failure AFTER the first byte on a NON-SSE same-protocol
                        // passthrough (e.g. OpenAI→OpenAI /chat/completions, content-type
                        // application/json): the 2xx headers already recorded an optimistic breaker
                        // SUCCESS (via `record_success_in`), but the body never arrived intact, so that
                        // success is wrong — exactly the case the SSE if-branch above and BOTH buffered
                        // `ReadEnd::TransportError` paths compensate. The SSE
                        // branch couldn't fire here (this path is reached only when `!this.is_sse`), and
                        // without this the optimistic success is NEVER reversed → repeated mid-body
                        // failures accumulate as successes and the lane never trips. Record a compensating
                        // transient. Gate on `had_first`: a PRE-first-byte failure (had_first == false) is
                        // the original symmetric-with-#21 refund-only case (no streamed body content was
                        // ever emitted to the client) and must NOT additionally record a transient — that
                        // would be a sibling over-broad fix. Only a post-first-byte mid-body failure both
                        // refunds budget AND records the failed transfer.
                        if had_first {
                            if let Some(ref app) = this.app {
                                let tripped = app.store.record_transient_in(
                                    &this.pool,
                                    this.lane_idx,
                                    "mid-body-transport",
                                    &this.breaker_cfg,
                                    None,
                                );
                                // A threshold-based Closed→Open trip here is a breaker trip (#29).
                                if tripped {
                                    emit_breaker_trip(app, &this.pool, this.lane_idx);
                                }
                            }
                        }
                        // Symmetric with the buffered `ReadEnd::TransportError` path (#21): the 2xx
                        // headers already spent one `max_requests` budget unit on this lane, but a
                        // pre-first-byte body transport failure delivers NO usable response — so refund
                        // that unit, or sustained streaming transport failures would permanently drain
                        // the lane's serving-capacity budget one unit at a time (MED #3). The streaming
                        // path previously refunded nothing here while the buffered paths did. Refund
                        // ONLY when the headers-spend actually decremented (`budget_spent`): a no-op
                        // spend (unlimited lane, or budget already 0) must not be refunded, since
                        // `refund_budget` is an unconditional `fetch_add` that would otherwise push the
                        // budget above its cap. Mark the stream ended and clear the flag so the inner
                        // stream's trailing `Poll::Ready(None)` neither double-refunds nor token-bills.
                        if this.budget_spent {
                            if let Some(ref app) = this.app {
                                app.store.refund_budget(this.lane_idx);
                            }
                            this.budget_spent = false;
                        }
                        drop(this.permit.take());
                        this.ended = true;
                        return Poll::Ready(Some(Err(std::io::Error::other(
                            MID_STREAM_GENERIC_DETAIL,
                        ))));
                    }
                }
                Poll::Ready(None) => {
                    // Stream ended. A clean `Poll::Ready(None)` is the NORMAL termination for both
                    // clean and truncated streams and is NOT a failure — success was already
                    // recorded synchronously (record_success_in) before streaming began. Only record
                    // a breaker failure here if the tap actually saw a terminal ERROR frame
                    // (`{"type":"error", ...}`) mid-stream. Previously this arm recorded a failure on
                    // EVERY completed SSE stream, so healthy streaming lanes tripped after a handful
                    // of successful requests.
                    //
                    // Hoist the TRANSLATE-side abort flag ONCE, at the top of this arm, BEFORE
                    // `finish()` consumes the translate below. A cross-protocol `StreamTranslate`
                    // that overflowed `MAX_BUF` (>16MiB without a frame terminator) or hit a
                    // malformed egress prelude calls `abort()` and stops feeding the body — but it
                    // leaves `tap.terminal_error` clear (no in-band `{"type":"error"}` frame was ever
                    // scanned). That is the SIBLING condition to the R25 mid-body terminal-error fix:
                    // both deliver a partial/aborted response the caller cannot use, so BOTH must be
                    // treated as a failed stream by ALL THREE downstream gates (breaker, token
                    // billing, json-array byte-shaping). The json-array close path below previously
                    // read `aborted()` locally for its own byte-shaping; that single read is hoisted
                    // here and reused so the three gates can never diverge.
                    let translate_aborted = this
                        .translate
                        .as_ref()
                        .map(|t| t.aborted())
                        .unwrap_or(false);
                    // A stream is FAILED for breaker purposes when EITHER a reader-emitted terminal ERROR
                    // event was seen (the IR-sourced `translate.terminal_error()`, Change A — replacing
                    // the deleted `UsageTap::terminal_error` byte-scan) OR the cross-protocol translate
                    // aborted mid-flight. Every same-proto/cross-proto SSE+eventstream stream now flows
                    // through `translate`, so the terminal error is observable at this point in the arm
                    // for all of them; the billing gate re-evaluates the same predicate AFTER the bedrock
                    // deferred `finish()` below (whose `metadata` frame can surface usage/error at end).
                    let stream_terminal_error = this
                        .translate
                        .as_ref()
                        .and_then(|t| t.terminal_error())
                        .is_some();
                    let breaker_failed = stream_terminal_error || translate_aborted;
                    if this.is_sse && this.first_byte_sent.load(Ordering::Relaxed) && breaker_failed
                    {
                        if let Some(app) = this.app.as_ref() {
                            // Distinguish the two failure lineages in the recorded reason so the
                            // R25 terminal-error path and this R26 translate-abort sibling remain
                            // separable in breaker telemetry.
                            let reason = if stream_terminal_error {
                                "stream-terminal-error"
                            } else {
                                // translate_aborted must hold here (breaker_failed && no
                                // terminal_error) — name the sibling lineage explicitly.
                                "stream-translate-abort"
                            };
                            let tripped = app.store.record_transient_in(
                                &this.pool,
                                this.lane_idx,
                                reason,
                                &this.breaker_cfg,
                                None,
                            );
                            // A terminal-error frame OR translate abort that drives a Closed→Open
                            // trip is a breaker trip for this (pool, lane) — emit BREAKER_TRIPS_TOTAL
                            // once (#29). This is the arm the `response.failed` recognition (#H2) now
                            // reaches for a streaming Responses FAILURE that previously recorded as
                            // success.
                            if tripped {
                                emit_breaker_trip(app, &this.pool, this.lane_idx);
                            }
                        }
                    }
                    // emit the ingress terminator before close. For a gemini JSON-array stream the
                    // terminator is the closing `]` from the framer; the SSE `translate.finish()`
                    // terminator (e.g. OpenAI `data: [DONE]`) must NOT be emitted into a JSON-array
                    // body — drain the translate buffer (so its decode side-effects run) but discard
                    // its SSE terminator bytes, then append the framer close.
                    let done = if let Some(framer) = this.json_array.as_mut() {
                        // The TRANSLATE-side abort flag was hoisted at the top of this arm (BEFORE any
                        // `finish()` drains the translate): a cross-protocol StreamTranslate that
                        // overflowed `MAX_BUF` (or hit a malformed egress prelude) stopped feeding this
                        // framer, and its SSE terminal-error frame cannot ride inside a JSON-array body,
                        // so the framer's own `aborted` flag stays clear. Route the close through
                        // `finish_for_translate(translate_aborted)` so an aborted gemini-json-array
                        // stream surfaces a NATIVE error element + `]` instead of a bare `]` (a silent
                        // truncation indistinguishable from a short success). Drain the translate's SSE
                        // terminator for its decode side-effects but discard those bytes — the
                        // JSON-array terminator is the framer close. Reuse the single hoisted read so
                        // the breaker, billing, and byte-shaping gates can never diverge.
                        let _ = this.translate.as_mut().map(|t| t.finish());
                        framer.finish_for_translate(translate_aborted)
                    } else {
                        this.translate
                            .as_mut()
                            .map(|t| t.finish())
                            .unwrap_or_default()
                    };
                    // Bedrock ingress: `finish()` may emit a deferred terminal `metadata` frame (the
                    // default-OpenAI-streaming case carries usage there). Its usage is folded into the
                    // translator's `last_usage` A-tap by `finish()` itself, so `translate.usage()` below
                    // already reflects it — no separate tap-feed of the binary `done` bytes is needed.
                    drop(this.permit.take());
                    this.ended = true;
                    // Token usage for billing, sourced from the IR (Change A):
                    //   - STREAMING (SSE / eventstream, same- or cross-proto): `translate.usage()` — the
                    //     terminal `IrUsage` the readers accumulated, post Anthropic start-usage backfill.
                    //   - SAME-PROTOCOL NON-STREAM (`!is_sse`, `translate == None`): run the EGRESS reader
                    //     (`ingress_protocol`'s reader — same-proto, egress == ingress) over the
                    //     reassembled `nonstream_buf` body and read `ir.usage` (Change A path #4). The body
                    //     was relayed verbatim; this is the read-for-IR side-channel for billing.
                    // The unknown-protocol fallback passthrough has no reader and yields `None` (no usage
                    // source — same as before; an unknown protocol cannot be metered).
                    let ir_usage: Option<crate::ir::IrUsage> =
                        if let Some(t) = this.translate.as_ref() {
                            t.usage().cloned()
                        } else if !this.is_sse && !this.nonstream_buf.is_empty() {
                            // Same-protocol non-stream body relayed verbatim; the operation reads
                            // usage from the reassembled bytes. Chat runs the egress reader and
                            // reports IR usage (byte-identical to the previous inline read); a
                            // flat-fee op returns None and bills nothing.
                            let buf = std::mem::take(&mut this.nonstream_buf);
                            this.op.extract_usage(&this.ingress_protocol, &buf)
                        } else {
                            None
                        };
                    // Charge this request's token usage to the virtual key's budget (once) — but ONLY
                    // for a cleanly-terminated stream. A stream that saw a reader-emitted terminal ERROR
                    // event (`translate.terminal_error()`) OR whose cross-protocol translate aborted
                    // mid-flight (`translate_aborted`) delivered a partial/aborted response the caller
                    // cannot use, and billing it contradicts the flat-fee-only-on-success policy (the
                    // per-request fee is charged at admission by
                    // `ingress::budget_check`→`try_charge_request_within_budget`, and `ingress::finish`
                    // REFUNDS it on a non-2xx, so the net flat fee lands only on a 2xx). Mirror that
                    // here with the SAME `failed` predicate the breaker gate above uses: a failed
                    // stream is not token-billed, covering BOTH the SSE-ingress and json-array close
                    // paths (the json-array path previously fell through and billed an aborted
                    // stream's partial tokens). A same-proto non-stream body has no terminal-error/abort
                    // path here (it is `!is_sse`), so `billing_failed` is false there.
                    if let Some(sink) = this.usage_sink.take() {
                        // Re-read the terminal error AFTER the deferred bedrock `finish()` above (whose
                        // `metadata`/exception frame can surface an error only at stream end), OR'd with
                        // the hoisted translate-abort flag — keeping the SAME failed semantics the breaker
                        // gate used. An aborted translate's `feed` is a no-op, so the `translate_aborted`
                        // snapshot taken at the top of the arm is still authoritative.
                        let billing_failed = this
                            .translate
                            .as_ref()
                            .and_then(|t| t.terminal_error())
                            .is_some()
                            || translate_aborted;
                        if !billing_failed {
                            // billed tokens = the normalized billable total (A2): uncached input +
                            // cache_read + cache_creation + output. Readers normalize `input_tokens`
                            // to UNCACHED and keep the cache fields ADDITIVE, so this single sum is
                            // correct provider-agnostically — OpenAI-family stay at prompt_total+output
                            // (no double-count), Anthropic/Bedrock now correctly include their
                            // additive cache reads/writes. `billable_tokens` saturates internally
                            // (counts are UPSTREAM-CONTROLLED) rather than risking a request-path panic.
                            let tokens =
                                ir_usage.as_ref().map(|u| u.billable_tokens()).unwrap_or(0);
                            // Attribute the token fee to the SAME window the flat per-request fee was
                            // charged in (`sink.charged_at`, the header-arrival epoch), not the
                            // stream-end clock — otherwise a stream that completes in a later window
                            // than its headers arrived would split its two charges across two windows
                            // (#29).
                            sink.gov.record_tokens(
                                &sink.key_id,
                                &sink.period,
                                sink.charged_at,
                                tokens,
                            );
                            // Metering (raw per-model consumption series, token SPLIT preserved):
                            // attribute to the SERVING lane — `lane_idx` is the lane that actually
                            // answered, post-failover. Same pinned epoch as the budget charges (#29).
                            if let Some(lane) =
                                this.app.as_ref().and_then(|a| a.lanes.get(this.lane_idx))
                            {
                                sink.gov.record_metering(
                                    &sink.key_id,
                                    &lane.model,
                                    &lane.provider,
                                    ir_usage.as_ref(),
                                    sink.charged_at,
                                );
                            }
                        }
                    }
                    if !done.is_empty() {
                        return Poll::Ready(Some(Ok(Bytes::from(done))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S, P> Drop for FirstByteBody<S, P> {
    fn drop(&mut self) {
        // Token-fee billing normally fires in `Poll::Ready(None)` (natural stream end), which TAKES
        // `usage_sink`. So a `None` here means "already billed" and this Drop is a no-op — no
        // double-charge. A `Some` means the body was DROPPED MID-STREAM (client disconnect /
        // cancellation) before the natural end, so the token-fee site never ran and the tokens already
        // generated + delivered would go unbilled (the under-billing the audit flagged). Bill the
        // tokens the readers accumulated up to the drop point instead.
        //
        // Best-effort: the provider's terminal usage frame may not have arrived before the cancel, so
        // `translate.usage()` may be partial or absent — partial/zero usage bills partial/zero
        // (`record_tokens` no-ops on 0 tokens). Only the streaming `translate.usage()` source is
        // consulted; a partially-buffered same-proto non-stream body cannot be reliably parsed for
        // usage, so it is not billed on a mid-buffer drop.
        let Some(sink) = self.usage_sink.take() else {
            return;
        };
        // Mirror the `Poll::Ready(None)` failed-gate EXACTLY: do not bill a stream that surfaced a
        // terminal reader error OR whose cross-protocol translate aborted mid-flight (buffer overflow
        // etc.) — both delivered a partial/aborted response the caller cannot use, and billing either
        // contradicts the no-bill-on-failure policy (asserted by
        // `test_streaming_translate_abort_trips_breaker_and_skips_billing`).
        let translate = self.translate.as_ref();
        if translate.and_then(|t| t.terminal_error()).is_some()
            || translate.map(|t| t.aborted()).unwrap_or(false)
        {
            return;
        }
        let usage = self.translate.as_ref().and_then(|t| t.usage()).cloned();
        let tokens = usage.as_ref().map(|u| u.billable_tokens()).unwrap_or(0);
        if tokens > 0 {
            sink.gov
                .record_tokens(&sink.key_id, &sink.period, sink.charged_at, tokens);
            // Meter the delivered-then-dropped partial too (same serving-lane attribution as the
            // natural-end site) — the tokens were really consumed against this model.
            if let Some(lane) = self.app.as_ref().and_then(|a| a.lanes.get(self.lane_idx)) {
                sink.gov.record_metering(
                    &sink.key_id,
                    &lane.model,
                    &lane.provider,
                    usage.as_ref(),
                    sink.charged_at,
                );
            }
        }
    }
}

impl<S, P> FirstByteBody<S, P> {
    pub(crate) fn into_body(self) -> Body
    where
        S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin + Send + 'static,
        P: Send + Unpin + 'static,
    {
        Body::from_stream(self)
    }
}
