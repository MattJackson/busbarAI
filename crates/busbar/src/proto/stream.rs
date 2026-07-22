// Cross-protocol response-stream translation, split out of proto/mod.rs.
use super::*;

/// pure cross-protocol response-stream translator. Feed EGRESS-protocol SSE bytes,
/// get the equivalent INGRESS-protocol SSE bytes — composing `egress.reader().read_response_events`
/// (wire → IR, stateful fan-out) with `ingress.writer().write_response_event` (IR → wire). Holds
/// a reassembly buffer for frames split across chunks and the IR decode state across the stream.
/// It is driven from the live streaming response path (see `FirstByteBody` in `forward`).
pub(crate) struct StreamTranslate {
    ingress: Protocol,
    egress: Protocol,
    pub(super) decode: crate::ir::StreamDecodeState,
    pub(super) buf: Vec<u8>,
    /// How far into `buf` we have already scanned for an SSE frame terminator. Searching only the
    /// unscanned tail keeps `feed()` linear even when a single large frame arrives as many small
    /// chunks (otherwise the whole accumulated prefix is re-scanned on every call → O(n^2)).
    pub(super) scanned: usize,
    /// Set once the reassembly buffer exceeds `MAX_BUF` with no complete frame: the stream is
    /// abandoned (an untrusted upstream that never emits a terminator must not grow `buf`
    /// without bound — that is a memory-exhaustion DoS).
    pub(super) aborted: bool,
    /// ingress == "openai" → the stream must terminate with `data: [DONE]\n\n`.
    emit_done: bool,
    /// egress == "bedrock" → frames are binary `application/vnd.amazon.eventstream`, not SSE.
    pub(super) egress_eventstream: bool,
    /// ingress == "bedrock" → the CLIENT is a native AWS SDK, so each translated event must be
    /// packed into a binary `application/vnd.amazon.eventstream` frame (with valid CRC32) instead of
    /// reframed as SSE. The stream's terminator is the `messageStop`/`metadata` frames themselves
    /// (Bedrock has no `[DONE]`), so `finish()` stays empty. See `docs/architecture.md`.
    pub(super) ingress_eventstream: bool,
    /// Wall-clock instant the first byte was fed, used to report a real `metrics.latencyMs` on a
    /// Bedrock-INGRESS `metadata` frame (finding: a native ConverseStream reports actual latency; a
    /// hard-coded `0` was a detectable tell). Set lazily on the first `feed`. `None` until then (and
    /// for non-Bedrock ingress, where it is never read).
    started_at: Option<std::time::Instant>,
    /// Per-stream, INGRESS-keyed protocol framing state. All protocol-specific stream-shape
    /// decisions the translator used to make inline — the OpenAI per-chunk identity replay +
    /// include_usage trailing-usage un-fold, and the Bedrock messageStop/metadata two-frame deferral
    /// with its finish-time flush — live BEHIND this vtable, implemented in the owning protocol's
    /// module (see [`StreamFraming`]). Built once from `ingress.writer().new_stream_framing()`; the
    /// translator consults it and never names a protocol's wire quirk. A protocol with no per-stream
    /// quirk gets the inert [`PassthroughFraming`] default.
    framing: Box<dyn StreamFraming>,
    /// CROSS-PROTOCOL tool-id native remap (the streaming half of the §Finding-2 class fix). Reshapes
    /// each egress `tool_use` id (e.g. OpenAI `call_…`) to the INGRESS client's native shape (Anthropic
    /// `toolu_…`) before the ingress writer serializes it, so a foreign id never reaches the client. The
    /// map is stream-scoped: a tool id seen on `BlockStart` maps stably for the life of this stream (and
    /// the transform is deterministic, so the matching `tool_result` the client sends back next round
    /// decodes to the original egress id). The same-protocol path re-emits frames verbatim and bypasses
    /// `translate_event` entirely, so this remap only ever runs on a cross-protocol hop.
    tool_id_remap: ToolIdRemap,
    /// Input-token usage captured at stream start (`MessageStart.usage`), carried forward so the
    /// terminal `MessageDelta` reports the prompt-token count.
    ///
    /// Anthropic's SSE puts `usage.input_tokens` (and the cache-token splits) ONLY on `message_start`;
    /// its `message_delta` carries `output_tokens` alone. Every other protocol bundles input+output
    /// into the terminal usage event. So on a cross-protocol hop OUT of an Anthropic backend the IR's
    /// terminal `MessageDelta.usage.input_tokens` is 0 and the prompt-token count is lost — the ingress
    /// writer under-reports usage (and the IR-derived `last_usage` that billing reads inherits the gap). Latch the
    /// start-usage input/cache fields here and backfill them onto the terminal delta when the delta
    /// itself carries none, so input tokens survive the seam regardless of how the egress protocol
    /// split start-vs-terminal usage. `None` until the first `MessageStart` carrying usage is seen.
    start_usage: Option<crate::ir::IrUsage>,
    /// Set once a terminal `MessageStop` has been emitted for this stream. Guards against an
    /// out-of-order trailing `MessageDelta` of ANY flavour being written AFTER the terminal frame on
    /// a NON-eventstream ingress — e.g. an Anthropic `message_delta` after `message_stop`, which is
    /// invalid stream framing and a proxy tell. The common case is a usage-only
    /// `MessageDelta{stop_reason: None}` (the OpenAI `include_usage` convention puts token totals in a
    /// chunk that arrives AFTER the finish chunk); a re-emitting backend can also repeat a terminal
    /// `MessageDelta{stop_reason: Some(_)}` after the stop. The bedrock (`ingress_eventstream`) path
    /// folds late usage into its single `metadata` frame and so is handled separately above; for
    /// every other ingress ANY post-stop `MessageDelta` is dropped once the message has stopped
    /// (matching v1.0.0-rc.2, which did not read trailing usage at all).
    message_stopped: bool,
    /// SAME-PROTOCOL universal-translate mode (Change B step 2): `true` when ingress == egress and
    /// the translator was built via [`StreamTranslate::new_same_proto`]. In this mode `feed` re-emits
    /// the ORIGINAL frame bytes verbatim (byte-exact passthrough) INSTEAD of re-serializing the IR —
    /// every frame is structurally pristine (no cross-protocol mutation can fire), so the short-
    /// circuit is unconditional. The IR pipeline still runs per frame, but purely as a side-channel:
    /// it drives `last_usage` (the A-tap billing value). The
    /// serialized IR output it produces is DISCARDED — only the retained original bytes reach `out`.
    same_proto: bool,
    /// The terminal IR-derived usage for this stream (Change A "A-tap" value), accumulated from the
    /// `MessageStart`/`MessageDelta`/`MessageStop` events `translate_event` processes — AFTER the
    /// Anthropic start-usage backfill, so it reports the real prompt+completion token counts for every
    /// protocol. PRODUCTION billing source (Change A step 3, now permanent): `FirstByteBody`'s
    /// stream-end arm reads this via `usage()` for the per-request token fee (the old `UsageTap`
    /// byte-scanner and the shadow-check that proved this value matched it have both been retired).
    /// `None` until the first usage-bearing terminal event is seen.
    last_usage: Option<crate::ir::IrUsage>,
    /// A genuine terminal ERROR seen mid-stream — the IR-sourced replacement for the byte-scanner's
    /// `UsageTap::terminal_error` (Change A). Set when a reader emits an [`crate::ir::IrStreamEvent::Error`]
    /// (an Anthropic `error` event, an OpenAI in-band `{"error":...}` frame, a Responses
    /// `response.failed` frame, or a Bedrock in-band `*Exception` frame). This is the breaker-failure
    /// signal the stream-end arm reads to distinguish a clean close from an aborted one. Holds the
    /// human message (`provider_signal`) for observability; `None` on a clean stream.
    terminal_error: Option<String>,
    /// TERMINAL-USAGE FOLD (SSE ingress: anthropic/gemini/cohere/responses — see
    /// `StreamFraming::folds_terminal_usage`). Holds the deferred terminal `MessageDelta`
    /// `(stop_reason, stop_sequence, usage)` so a trailing usage-only chunk (OpenAI `include_usage`)
    /// can be merged into it before it is flushed at `finish()`. `None` until the finish delta arrives
    /// (and for the OpenAI/Bedrock ingresses, which opt out). `pending_stop` records that the paired
    /// `MessageStop` was also deferred, so `finish()` re-emits it after the flushed delta. The response
    /// body feeds `finish()`'s output through the json-array framer too, so this flush reaches the
    /// client uniformly on both the SSE and gemini-json-array paths.
    pending_terminal: Option<(crate::ir::IrStopReason, Option<String>, crate::ir::IrUsage)>,
    pending_stop: bool,
}

impl StreamTranslate {
    /// Build a translator for an ingress→egress pair. `None` if either protocol is unknown OR
    /// ingress == egress (no translation needed — the caller does native passthrough).
    ///
    /// This is the CROSS-protocol constructor and its same-proto guard is UNCHANGED: same-protocol
    /// callers that want the universal-translate verbatim path use [`new_same_proto`] explicitly, so
    /// the legacy `ingress == egress → None` contract (and every caller relying on it) is preserved.
    pub(crate) fn new(ingress: &str, egress: &str) -> Option<Self> {
        if ingress == egress {
            return None;
        }
        Self::build(ingress, egress, false)
    }

    /// Build a SAME-PROTOCOL universal translator (Change B step 2). Unlike [`new`], this returns
    /// `Some` when `ingress == egress` (the protocol must be known). The resulting translator runs the
    /// full reader→IR pipeline per frame for usage extraction but re-emits the ORIGINAL frame bytes
    /// verbatim (see the `same_proto` field) — a byte-exact passthrough with an IR side-channel. The
    /// caller gates this behind the reversible universal-same-proto flag
    /// (`proxy::ENABLE_UNIVERSAL_SAME_PROTO_TRANSLATE`); when the flag is off the caller passes
    /// `None` and falls back to the legacy raw-chunk passthrough.
    pub(crate) fn new_same_proto(proto: &str) -> Option<Self> {
        Self::build(proto, proto, true)
    }

    /// Shared constructor body for [`new`] and [`new_same_proto`]. `same_proto` selects the verbatim
    /// re-emit path in `feed`.
    fn build(ingress: &str, egress: &str, same_proto: bool) -> Option<Self> {
        let ingress_proto = protocol_for(ingress)?;
        let egress_proto = protocol_for(egress)?;
        // Derive the framing flags from the protocol vtable rather than re-comparing the name
        // strings: `ingress_eventstream`/`egress_eventstream` reuse the SAME `ingress_is_eventstream()`
        // method `FirstByteBody` already dispatches through (so the two can never drift from it), and
        // `emit_done` reads `emits_sse_done_terminator()`. This constructor carries no provider-name
        // branch; a 7th protocol gets the safe `false` defaults.
        let emit_done = ingress_proto.writer().emits_sse_done_terminator();
        let ingress_eventstream = ingress_proto.writer().ingress_is_eventstream();
        let egress_eventstream = egress_proto.writer().ingress_is_eventstream();
        // The per-stream framing is keyed to the INGRESS writer — it produces the client-facing wire.
        // A protocol with no per-stream framing quirk yields the inert PassthroughFraming.
        let framing = ingress_proto.writer().new_stream_framing();
        Some(Self {
            ingress: ingress_proto,
            egress: egress_proto,
            decode: crate::ir::StreamDecodeState::default(),
            buf: Vec::new(),
            scanned: 0,
            aborted: false,
            emit_done,
            egress_eventstream,
            ingress_eventstream,
            started_at: None,
            framing,
            tool_id_remap: ToolIdRemap::default(),
            start_usage: None,
            message_stopped: false,
            same_proto,
            last_usage: None,
            terminal_error: None,
            pending_terminal: None,
            pending_stop: false,
        })
    }

    /// Record whether the ORIGINAL client request opted into streaming usage
    /// (`stream_options.include_usage == true`), forwarding it to the ingress framing (Findings 2+3).
    /// Only the OpenAI-ingress framing acts on it (its `include_usage` un-fold/strip); every other
    /// ingress framing ignores it. Called by the engine after it captures the client's intent from the
    /// request body and before the first frame is fed.
    pub(crate) fn set_client_include_usage(&mut self, include: bool) {
        self.framing.set_client_include_usage(include);
    }

    /// Translate one egress event `(event_type, payload)` into ingress wire bytes, advancing the
    /// decode state. Shared by the SSE and event-stream feed paths.
    fn translate_event(&mut self, event_type: &str, data: &serde_json::Value, out: &mut Vec<u8>) {
        // Ingress protocol name for the tool-id remap below. Captured up front (owned) because
        // `Protocol::name(&self) -> &str` returns a reference with `self`'s lifetime (elided), not
        // `&'static`, so holding it would conflict with the mutable `self.tool_id_remap` borrow in
        // `remap_event` below. The copy of a short static name is cheap and breaks the borrow.
        let ingress_name = self.ingress.name().to_string();
        for mut ev in self
            .egress
            .reader()
            .read_response_events(event_type, data, &mut self.decode)
        {
            // CROSS-PROTOCOL tool-id native remap: reshape the egress `tool_use` id on a `BlockStart`
            // to the ingress client's native shape (see `StreamTranslate::tool_id_remap`). Done before
            // identity-strip/usage-backfill so the rest of the pipeline sees the client-facing id.
            self.tool_id_remap.remap_event(&ingress_name, &mut ev);
            // Cross-protocol stream identity strip: a `StreamTranslate` only exists when
            // ingress != egress (`new` returns None otherwise), so every event here crosses a
            // protocol boundary. Clear the foreign-format `MessageStart` `id`/`created` so the INGRESS
            // writer synthesizes NATIVE-format stream identity rather than leaking the backend's
            // `chatcmpl-…`/`msg_…` id to a different-protocol client — mirrors the non-stream strip in
            // proxy engine (`ir.id = None`). `model` is DELIBERATELY LEFT INTACT: it is the lane's model
            // name (format-neutral, like `created`), and ingress writers use a populated `model` as
            // the anchor for synthesizing the full native stream-start skeleton — clearing it
            // suppressed that synthesis (the Anthropic writer emitted a degenerate `message_start`
            // missing `id`/`type`/`content`/`stop_reason`/`stop_sequence`; the Gemini writer omitted
            // `modelVersion`). The non-stream path in proxy engine also does NOT clear `model`. Same-
            // protocol byte-exact round-trips never reach here, so they are untouched.
            if let crate::ir::IrStreamEvent::MessageStart {
                id, created, usage, ..
            } = &mut ev
            {
                // Latch the start-usage input/cache token counts (before stripping identity). Anthropic
                // carries input tokens ONLY here, never on `message_delta`; backfilling the terminal
                // delta below keeps the prompt-token count from vanishing across the cross-protocol seam.
                if let Some(u) = usage {
                    self.start_usage = Some(u.clone());
                }
                *id = None;
                *created = None;
            }
            // Backfill the terminal usage: if the egress protocol reported input/cache tokens only at
            // stream start (Anthropic), the `MessageDelta` arrives with `input_tokens == 0` and no cache
            // splits. Restore them from the latched start-usage so the ingress writer emits — and the
            // billing-source `last_usage` reflects — the real prompt-token count. Only fills fields the delta
            // itself left empty, so a protocol that DOES carry input on its terminal delta (OpenAI
            // include_usage, Gemini, Bedrock, Cohere) is never overwritten.
            if let crate::ir::IrStreamEvent::MessageDelta { usage, .. } = &mut ev {
                if let Some(start) = &self.start_usage {
                    if usage.input_tokens == 0 {
                        usage.input_tokens = start.input_tokens;
                    }
                    if usage.cache_creation_input_tokens.is_none() {
                        usage.cache_creation_input_tokens = start.cache_creation_input_tokens;
                    }
                    if usage.cache_read_input_tokens.is_none() {
                        usage.cache_read_input_tokens = start.cache_read_input_tokens;
                    }
                }
                // A-tap capture (Change A): accumulate the terminal IR usage AFTER the start-usage
                // backfill, so `last_usage` reports the real prompt+completion counts for every
                // protocol regardless of how it split start-vs-terminal usage. Merge per field (keep
                // any non-zero / Some already seen) rather than blind-overwrite, so a backend that
                // splits usage across two deltas (e.g. OpenAI `include_usage`: a finish delta with
                // zero usage, then a usage-only delta) does not let the first zero clobber the second's
                // real counts. `last_usage` is the production billing source the stream-end arm reads
                // for the per-request token fee (Change A step 3, now permanent).
                let acc = self.last_usage.get_or_insert(crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                });
                if usage.input_tokens != 0 {
                    acc.input_tokens = usage.input_tokens;
                }
                if usage.output_tokens != 0 {
                    acc.output_tokens = usage.output_tokens;
                }
                if usage.cache_creation_input_tokens.is_some() {
                    acc.cache_creation_input_tokens = usage.cache_creation_input_tokens;
                }
                if usage.cache_read_input_tokens.is_some() {
                    acc.cache_read_input_tokens = usage.cache_read_input_tokens;
                }
            }
            // A-tap terminal-error capture (Change A): a reader-emitted `Error` event is the IR-sourced
            // breaker-failure signal that replaces the byte-scanner's `UsageTap::terminal_error`. Record
            // its message so the stream-end breaker/billing arms treat the stream as failed (no token
            // billing, record a breaker transient). Mirrors the byte-scanner's per-shape detection, but
            // sourced from the reader's structured decode rather than a brace-scan of the output bytes.
            if let crate::ir::IrStreamEvent::Error(err) = &ev {
                self.terminal_error = Some(
                    err.provider_signal
                        .clone()
                        .unwrap_or_else(|| "upstream stream error".to_string()),
                );
            }
            // Bedrock-INGRESS error path: a native AWS SDK dispatches mid-stream errors off the
            // `:message-type: exception` / `:exception-type` headers, which ONLY
            // `encode_exception_frame` produces. A normal `write_response_event` pair would be framed
            // `:message-type: event` and silently dropped by a strict decoder. So when the ingress is
            // an event-stream client and the IR event is an Error, emit a real modeled-exception frame
            // via the writer's `write_response_exception` mapping instead of the event encoder.
            if self.ingress_eventstream {
                if let crate::ir::IrStreamEvent::Error(err) = &ev {
                    if let Some((exc_name, message)) =
                        self.ingress.writer().write_response_exception(err)
                    {
                        out.extend_from_slice(&crate::eventstream::encode_exception_frame(
                            &exc_name, &message,
                        ));
                        continue;
                    }
                }
            }

            // Bedrock-INGRESS combined-delta fan-out: the IR carries ONE combined
            // `MessageDelta{stop_reason: Some, usage}` (the egress reader collapses Bedrock's native
            // two-frame stop/usage split — or any other protocol's single message_delta — into one).
            // A native AWS SDK Bedrock client, however, expects the real TWO-frame sequence: a
            // `messageStop` frame carrying the stop reason FOLLOWED by a `metadata` frame carrying the
            // token usage (and a `metrics` object). The single-`(String,Value)`-return writer trait
            // cannot emit two frames, so we fan the combined delta into two synthetic single-purpose
            // deltas here — a stop-only delta → `messageStop`, then a usage-only delta → `metadata` —
            // and inject the real `metrics.latencyMs` onto the metadata frame (see below). This
            // reproduces exactly what `BedrockReader::read_response_events` consumed, so a
            // bedrock->bedrock stream still round-trips frame-for-frame.
            // Bedrock-INGRESS messageStop/metadata two-frame deferral — entirely behind the
            // framing vtable. The framing decides WHAT to emit and tracks the
            // exactly-one-metadata invariant; the translator stays the emission primitive and names no
            // Bedrock wire shape. PassthroughFraming returns `None` for both seams, so non-Bedrock
            // ingress falls through unchanged.
            if let crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some(reason),
                usage,
                stop_sequence,
            } = &ev
            {
                if let Some(events) =
                    self.framing
                        .on_combined_stop_delta(*reason, stop_sequence.clone(), usage)
                {
                    for emit in &events {
                        self.emit_ir_event(emit, out);
                    }
                    continue;
                }
            }
            // TERMINAL-USAGE FOLD (SSE ingress: anthropic/gemini/cohere/responses). These ingresses
            // carry usage in their single terminal `message_delta`, but an egress like OpenAI under
            // include_usage reports it in a SEPARATE trailing usage-only chunk that arrives AFTER the
            // finish chunk — so the terminal frame would ship with zeros and the real usage would be
            // dropped by the post-stop guard below. Defer the terminal delta + its MessageStop, merge
            // any trailing usage, and flush at `finish()` (which the response body now feeds through the
            // json-array framer too, so it reaches the client on every ingress). OpenAI/Bedrock opt out
            // (folds_terminal_usage == false) — they re-emit/fold usage via their own framing seams
            // above. Mutually exclusive with the Bedrock combined-stop path (which `continue`d). (H3.)
            if self.framing.folds_terminal_usage() {
                match &ev {
                    crate::ir::IrStreamEvent::MessageDelta {
                        stop_reason: Some(reason),
                        usage,
                        stop_sequence,
                    } => {
                        match self.pending_terminal.as_mut() {
                            // A DUPLICATE stop-bearing delta (some providers repeat the terminal
                            // message_delta): keep the FIRST terminal's captured usage and merge any this
                            // one carries (non-zero fields only), instead of overwriting the whole tuple —
                            // a duplicate with empty usage would otherwise drop the real, client-visible
                            // terminal usage. (found: 1.4.0 audit, streaming-billing.)
                            Some((_, _, acc)) => merge_trailing_usage(acc, usage),
                            None => {
                                self.pending_terminal =
                                    Some((*reason, stop_sequence.clone(), usage.clone()))
                            }
                        }
                        continue;
                    }
                    crate::ir::IrStreamEvent::MessageStop if self.pending_terminal.is_some() => {
                        self.pending_stop = true;
                        continue;
                    }
                    crate::ir::IrStreamEvent::MessageDelta {
                        stop_reason: None,
                        usage,
                        ..
                    } if self.pending_terminal.is_some() => {
                        if let Some((_, _, acc)) = self.pending_terminal.as_mut() {
                            merge_trailing_usage(acc, usage);
                        }
                        continue;
                    }
                    _ => {}
                }
            }
            if let crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: None, ..
            } = &ev
            {
                if let Some(should_emit) = self.framing.on_usage_only_delta() {
                    if should_emit {
                        self.emit_ir_event(&ev, out);
                    }
                    continue;
                }
            }

            // Non-eventstream ingress ordering guard: once the terminal `MessageStop` has been
            // emitted, drop ANY trailing `MessageDelta` (regardless of `stop_reason`). The common
            // case is a usage-only `MessageDelta{stop_reason: None}` (OpenAI `include_usage`
            // delivers token totals in a chunk that arrives AFTER the finish chunk), but a backend
            // can also re-emit a DUPLICATE terminal `MessageDelta{stop_reason: Some(_)}` after the
            // stop. Either one, written now, would put a `message_delta` AFTER `message_stop` on the
            // wire — invalid stream framing and a proxy tell for SSE ingress
            // (Anthropic/Gemini/Cohere/OpenAI). The bedrock (`ingress_eventstream`) path already
            // folded such usage into its single `metadata` frame above and returned via `continue`,
            // so it never reaches here.
            if self.message_stopped && matches!(ev, crate::ir::IrStreamEvent::MessageDelta { .. }) {
                continue;
            }
            if matches!(ev, crate::ir::IrStreamEvent::MessageStop) {
                self.message_stopped = true;
            }

            // Multi-citation fan-out (wire-correctness, HIGH-1): a single
            // `BlockDelta{CitationsDelta(vec of N)}` (e.g. ONE Gemini chunk batches 3–10
            // `citationSources[]` → ONE delta carrying N citations) MUST NOT serialize to a single
            // wire event whose body is a JSON ARRAY of N citation frames when the ingress protocol
            // frames exactly one citation per event — a native Anthropic SDK `JSON.parse`s ONE object
            // per `data:` line and crashes on an array. The single-`(String,Value)`-return writer trait
            // cannot emit N frames from one event, so — mirroring the Bedrock combined-delta fan-out
            // above — split the multi-citation delta into N single-citation `BlockDelta`s here at the
            // framing seam. The per-event citation limit is a per-protocol WIRE constraint, read via the
            // `max_citations_per_delta()` vtable (Anthropic → Some(1)) rather than an `ingress ==
            // "anthropic"` name-branch: Gemini legitimately coalesces N sources into one candidate-level
            // `citationMetadata` chunk (None → no fan-out). A single-citation delta (the common case)
            // is within any limit and takes the untouched fall-through below.
            if let Some(max_per_event) = self.ingress.writer().max_citations_per_delta() {
                if let crate::ir::IrStreamEvent::BlockDelta {
                    index,
                    delta: crate::ir::IrDelta::CitationsDelta(citations),
                } = &ev
                {
                    if citations.len() > max_per_event {
                        for chunk in citations.chunks(max_per_event) {
                            let single = crate::ir::IrStreamEvent::BlockDelta {
                                index: *index,
                                delta: crate::ir::IrDelta::CitationsDelta(chunk.to_vec()),
                            };
                            self.emit_ir_event(&single, out);
                        }
                        continue;
                    }
                }
            }

            self.emit_ir_event(&ev, out);
        }
    }

    /// SAME-PROTOCOL usage side-channel (Change B step 2). Runs ONLY the egress reader + the
    /// start-usage/backfill/`last_usage` accumulation that `translate_event` does — and NOTHING ELSE
    /// (no tool-id remap, no identity strip, no writer/fan-out/reframe). The same-proto path re-emits
    /// the ORIGINAL frame bytes verbatim, so the writer half is pure waste; skipping it keeps the
    /// short-circuit at-or-below the cost of NOT translating at all (the benchmark gate). The decode
    /// state still advances (the reader owns it) so multi-frame streams parse correctly, and the A-tap
    /// `last_usage` is populated by the SAME A-tap accumulation as the cross-protocol `translate_event`.
    fn extract_usage_only(&mut self, event_type: &str, data: &serde_json::Value) {
        for ev in self
            .egress
            .reader()
            .read_response_events(event_type, data, &mut self.decode)
        {
            if let crate::ir::IrStreamEvent::MessageStart { usage: Some(u), .. } = &ev {
                self.start_usage = Some(u.clone());
            }
            // A-tap terminal-error capture (Change A) on the SAME-PROTOCOL path: a reader-emitted
            // `Error` event is the IR-sourced breaker-failure signal replacing the byte-scanner's
            // `UsageTap::terminal_error`. Same-proto streams re-emit the original error frame verbatim,
            // but the breaker/billing arms still need to KNOW the stream ended abnormally, so record it.
            if let crate::ir::IrStreamEvent::Error(err) = &ev {
                self.terminal_error = Some(
                    err.provider_signal
                        .clone()
                        .unwrap_or_else(|| "upstream stream error".to_string()),
                );
            }
            if let crate::ir::IrStreamEvent::MessageDelta { usage, .. } = &ev {
                // Mirror translate_event's terminal-usage accumulation (post start-usage backfill).
                let (mut input, output) = (usage.input_tokens, usage.output_tokens);
                let (mut cache_creation, mut cache_read) = (
                    usage.cache_creation_input_tokens,
                    usage.cache_read_input_tokens,
                );
                if let Some(start) = &self.start_usage {
                    if input == 0 {
                        input = start.input_tokens;
                    }
                    if cache_creation.is_none() {
                        cache_creation = start.cache_creation_input_tokens;
                    }
                    if cache_read.is_none() {
                        cache_read = start.cache_read_input_tokens;
                    }
                }
                let acc = self.last_usage.get_or_insert(crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                });
                if input != 0 {
                    acc.input_tokens = input;
                }
                if output != 0 {
                    acc.output_tokens = output;
                }
                if cache_creation.is_some() {
                    acc.cache_creation_input_tokens = cache_creation;
                }
                if cache_read.is_some() {
                    acc.cache_read_input_tokens = cache_read;
                }
            }
        }
    }

    /// Write a single IR event through the ingress writer and append its framed bytes to `out`.
    /// Handles the eventstream-vs-SSE framing split and routes every protocol-specific per-frame
    /// decision through the [`StreamFraming`] vtable — the ingress writer's framing injects any
    /// per-frame metrics (a native eventstream usage frame's real latency) and replays per-chunk SSE
    /// identity — so this emitter branches only on transport (binary frame vs SSE), never on a wire
    /// event-type or protocol name.
    fn emit_ir_event(&mut self, ev: &crate::ir::IrStreamEvent, out: &mut Vec<u8>) {
        let Some((out_et, mut out_data)) = self.ingress.writer().write_response_event(ev) else {
            return;
        };
        if self.ingress_eventstream {
            // ingress is a native AWS SDK Bedrock client: pack the logical event into a binary
            // `application/vnd.amazon.eventstream` frame with valid CRC32. Per-frame protocol metrics
            // (a native usage frame's real latency) are injected through the framing vtable, so this
            // agnostic emitter names no wire event-type of its own.
            self.framing
                .inject_streaming_metrics(&out_et, &mut out_data, self.started_at);
            let payload = crate::json::to_vec(&out_data).unwrap_or_default();
            // Bedrock-INGRESS usage (Change A): the usage carried by this frame was already accumulated
            // into `last_usage` by `translate_event`/`extract_usage_only` from the structured IR event,
            // BEFORE this writer ran — so billing reads `usage()` and no longer needs the pre-encode
            // JSON side-channel the deleted byte-scanner consumed. Just encode the binary frame.
            out.extend_from_slice(&crate::eventstream::encode_frame(&out_et, &payload));
        } else {
            // EGRESS-CHUNK framing seam: the OpenAI per-chunk identity replay AND the
            // include_usage trailing-usage un-fold now live behind the framing vtable. The framing
            // mutates the chunk in place (latch/replay id/created/model) and, when it is a usage-bearing
            // finish chunk, returns a separate trailing usage-only chunk to frame after it — preserving
            // the exact two-frame order. PassthroughFraming is inert (no mutation, returns `None`), so
            // every non-OpenAI ingress is untouched. The `[DONE]` terminator stays a separate `finish()`
            // literal — only the chunk-identity + trailing-usage logic moved here.
            if let Some(trailing) = self.framing.on_egress_chunk(&mut out_data) {
                out.extend_from_slice(reframe_sse(&out_et, &out_data).as_bytes());
                out.extend_from_slice(reframe_sse(&out_et, &trailing).as_bytes());
                return;
            }
            out.extend_from_slice(reframe_sse(&out_et, &out_data).as_bytes());
        }
    }

    /// Hard cap on the reassembly buffer. An upstream that streams bytes without ever emitting a
    /// frame terminator must not grow `buf` indefinitely (memory-exhaustion DoS). DEFINED as
    /// `eventstream::MAX_FRAME_BYTES` (a single source of truth) so any single frame the binary
    /// decoder is willing to assemble can be buffered to completion here — a smaller cap would
    /// silently abort an oversized-but-decoder-legal frame before `drain_frames` ever saw it, and a
    /// divergence between the two literals (the previous hand-copied `16 * 1024 * 1024`) would
    /// reintroduce that bug with no compile-time signal. Far larger than any legitimate single SSE /
    /// event-stream frame from a chat completion.
    pub(super) const MAX_BUF: usize = crate::eventstream::MAX_FRAME_BYTES;

    /// Feed a chunk of EGRESS SSE bytes; return translated INGRESS SSE bytes for whatever
    /// COMPLETE frames are now available (empty if only a partial frame is buffered). Once the
    /// reassembly buffer exceeds [`Self::MAX_BUF`] with no complete frame the stream is abandoned
    /// and all further input is ignored.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.aborted {
            return Vec::new();
        }
        // Stamp the stream's wall-clock start on the first byte fed, so a Bedrock-INGRESS `metadata`
        // frame can report a real `metrics.latencyMs` (elapsed since the stream began) instead of a
        // tell-tale hard-coded 0. Cheap monotonic clock read; only read on the bedrock-ingress path.
        if self.started_at.is_none() {
            self.started_at = Some(std::time::Instant::now());
        }
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();

        if self.egress_eventstream {
            // egress is binary AWS event-stream framing (Bedrock ConverseStream). The event
            // name lives in the frame's `:event-type` header, not the JSON payload; the Bedrock
            // reader keys off a `type` field, so fold the header into the payload.
            //
            // Use `drain_frames_checked` (not the discarding `drain_frames` wrapper) so a MALFORMED
            // EGRESS PRELUDE — an out-of-range `total_len` / oversized `headers_len` from a corrupt or
            // adversarial Bedrock stream — surfaces as the EXPLICIT `DrainStatus::MalformedPrelude`
            // abort signal rather than being silently swallowed (the decoder clears the buffer and
            // stops, which a length-only check could not tell apart from a clean full drain, so the
            // stream would otherwise continue as if healthy and close with NO terminal exception).
            // SAME-PROTOCOL bedrock→bedrock: re-emit the ORIGINAL binary
            // frame bytes verbatim — NEVER re-encode. `encode_frame` would recompute the
            // length-prefix and CRC32, and any divergence (key ordering, float formatting,
            // whitespace) from the upstream's exact bytes is an undecodable frame for a native AWS
            // SDK. `drain_frames_checked` collects the verbatim bytes of each COMPLETE valid frame
            // DIRECTLY into `out` via the `consumed_sink` (in frame order) as it drains them — so the
            // re-emit costs only the consumed bytes, NOT a per-chunk clone of the whole reassembly
            // buffer (which was O(buf) every feed → a memory-pressure DoS for a large frame split into
            // many small chunks). The sink never receives a cleared malformed-prelude remainder (the
            // malformed branch breaks before the push), so the client never gets undecodable garbage
            // ahead of the synthesized exception frame. On the cross-proto path the sink is `None`
            // (the bytes are re-encoded by `translate_event`).
            let (frames, status, _valid_consumed) = crate::eventstream::drain_frames_checked(
                &mut self.buf,
                if self.same_proto {
                    Some(&mut out)
                } else {
                    None
                },
            );
            for (event_type, payload) in frames {
                let Ok(mut data) = serde_json::from_slice::<serde_json::Value>(&payload) else {
                    continue; // non-JSON payload — skip the frame
                };
                if let Some(obj) = data.as_object_mut() {
                    obj.insert(
                        "type".to_string(),
                        serde_json::Value::String(event_type.clone()),
                    );
                }
                if self.same_proto {
                    // Same-proto: run ONLY the reader + usage accumulation (`extract_usage_only`) —
                    // the writer/reframe half would be discarded, so skip it. The verbatim original
                    // bytes were already written to `out` by the drain's `consumed_sink` above.
                    self.extract_usage_only(&event_type, &data);
                } else {
                    self.translate_event(&event_type, &data, &mut out);
                }
            }
            // A malformed prelude is unrecoverable: abandon the stream exactly like the MAX_BUF
            // overflow path so the terminal exception frame is emitted by `finish()` (the `aborted`
            // flag drives that branch). Without this the stream would silently truncate.
            if status == crate::eventstream::DrainStatus::MalformedPrelude
                || self.buf.len() > Self::MAX_BUF
            {
                self.abort();
            }
            return out;
        }

        // Drain every complete blank-line-delimited SSE frame currently buffered. Both the LF-LF
        // (`\n\n`) and the spec-legal CRLF (`\r\n\r\n`) terminators are recognized — some gateways /
        // CDNs in front of model APIs emit CRLF SSE, which contains no `\n\n` adjacency, so an
        // LF-only scanner would buffer the whole stream until MAX_BUF and silently abort it.
        //
        // `consumed` is a FRONT cursor: each complete frame advances it instead of physically
        // `drain(..end)`-ing the front, which shifted the entire remaining tail down once PER frame
        // (O(n^2) when one buffer holds many small frames). We parse each frame as a slice and only
        // reclaim the consumed prefix ONCE, after the loop.
        //
        // `scanned`/`consumed` are absolute offsets into `buf`. The next frame begins exactly at
        // `consumed`, so the search floor is `consumed` — NEVER below it (a sub-`consumed` start would
        // re-find the terminator we just consumed → an empty frame and an infinite loop). The 3-byte
        // backup (to catch a CRLF terminator straddling the previous chunk boundary) and the `scanned`
        // skip (avoid rescanning the already-searched prefix of a frame split across many feeds) apply
        // only ABOVE that floor, so `feed()` stays linear without looping.
        let mut consumed = 0usize;
        // SAME-PROTOCOL verbatim re-emit cursor (R3-A-b): the start of the not-yet-flushed verbatim
        // region. The common case flushes `[0..consumed]` in one shot at the end (a single bulk copy);
        // it only splits when a frame must be SUPPRESSED (the OpenAI opted-out trailing usage chunk),
        // in which case the run BEFORE the suppressed frame is flushed and the frame's bytes skipped.
        let mut emit_from = 0usize;
        loop {
            let search_from = self
                .scanned
                .saturating_sub(3)
                .max(consumed)
                .min(self.buf.len());
            match find_frame_terminator(&self.buf[search_from..]) {
                Some((rel, term_len)) => {
                    let end = search_from + rel + term_len;
                    let frame_start = consumed;
                    let frame = &self.buf[frame_start..end];
                    consumed = end;
                    self.scanned = end;

                    let parsed = parse_sse_frame(frame);
                    let Some((event_type, data_str)) = parsed else {
                        continue; // no data: line, or non-utf8 — skip
                    };
                    if data_str.is_empty() || data_str == SSE_DONE_SENTINEL {
                        // egress terminator/keepalive — ingress terminator is finish()'s. Carries no
                        // usage on any current protocol; a future protocol that embeds usage in a
                        // terminator/keepalive frame MUST extract it here (the A-tap is skipped for
                        // this frame, but its bytes are still re-emitted verbatim in same_proto mode).
                        continue;
                    }
                    let Ok(data) = crate::json::parse_str::<serde_json::Value>(&data_str) else {
                        continue; // malformed data JSON — skip the frame rather than abort
                    };
                    if self.same_proto {
                        // Same-proto (gemini json-array & openai bare
                        // `data:`): run ONLY the reader + `last_usage` accumulation
                        // (`extract_usage_only`) — the verbatim original frame bytes are emitted from
                        // the consumed prefix below, so every frame (incl. comments, keepalives,
                        // `[DONE]`, and the exact `event:`/`data:` line shape and terminator) reaches
                        // the client byte-for-byte unchanged, and the writer/reframe work is skipped.
                        self.extract_usage_only(&event_type, &data);
                        // R3-A-b: on the verbatim path `on_egress_chunk` never runs, so an opted-out
                        // OpenAI client would still receive the unsolicited trailing usage chunk busbar
                        // forced upstream. The framing decides per-frame whether to DROP it - flush the
                        // verbatim run up to this frame's start, then skip the frame (its usage was
                        // already A-tapped above for billing). Inert for every non-suppressing frame.
                        if self.framing.suppress_same_proto_frame(&data) {
                            if frame_start > emit_from {
                                out.extend_from_slice(&self.buf[emit_from..frame_start]);
                            }
                            emit_from = end;
                        }
                    } else {
                        self.translate_event(&event_type, &data, &mut out);
                    }
                }
                None => {
                    // No complete frame: everything currently buffered has been scanned.
                    self.scanned = self.buf.len();
                    break;
                }
            }
        }
        // SAME-PROTOCOL verbatim re-emit: append the remaining un-flushed verbatim region (every
        // complete frame the loop consumed and did NOT suppress, including the keepalive/`[DONE]`/
        // non-`data:` frames the cross-proto path drops), BEFORE the consumed prefix is reclaimed below
        // - so the client sees the upstream SSE stream byte-for-byte, with the IR pipeline acting purely
        // as the usage side-channel above. In the common (no-suppression) case `emit_from == 0`, so this
        // is the single bulk copy of `[0..consumed]` the prior code did.
        if self.same_proto && consumed > emit_from {
            out.extend_from_slice(&self.buf[emit_from..consumed]);
        }
        // Reclaim the consumed prefix in a single shift (linear), then rebase the cursors.
        if consumed > 0 {
            self.buf.drain(..consumed);
            self.scanned = self.buf.len();
        }
        if self.buf.len() > Self::MAX_BUF {
            self.abort();
        }
        out
    }

    /// True once this translator abandoned its stream — the reassembly buffer grew past
    /// [`Self::MAX_BUF`] without a frame terminator, or a malformed egress event-stream prelude was
    /// hit (`abort`), so the happy-path terminal events were never produced and every subsequent
    /// `feed` is a no-op.
    ///
    /// On the SSE-ingress path `finish()` already surfaces this abort as the ingress protocol's
    /// native in-band error frame. On the GEMINI JSON-ARRAY ingress path the close arm normally FEEDS
    /// `finish()`'s tail THROUGH [`GeminiJsonArrayFramer::feed`] (so the terminal usage frame is
    /// delivered as a trailing array element) and then closes with
    /// [`GeminiJsonArrayFramer::finish_for_translate`]. But on an ABORT the SSE `finish()` bytes are an
    /// error frame that cannot ride inside a JSON-array body, so the tail is NOT fed through; the
    /// framer's OWN `aborted` flag is also unset (the translate simply stopped feeding it bytes), so a
    /// bare `]` would silently swallow the truncation. This accessor lets that close path observe the
    /// translate-side abort and emit the framer error-close instead, mirroring the SSE-ingress
    /// terminal-error behavior in `finish()`.
    ///
    /// Production wiring lives in `proxy engine`: the `FirstByteBody` `Poll::Ready(None)` JSON-array
    /// close arm reads `translate.aborted()` and passes it to
    /// `framer.finish_for_translate(translate_aborted)` so an aborted gemini-json-array stream
    /// surfaces a native error element instead of a bare close.
    pub(crate) fn aborted(&self) -> bool {
        self.aborted
    }

    /// The terminal IR-derived usage accumulated for this stream (the Change A "A-tap" value), or
    /// `None` if no usage-bearing terminal event was seen. PRODUCTION billing source (Change A step 3):
    /// the `FirstByteBody` stream-end arm reads this for the per-request token fee instead of the
    /// deleted `UsageTap` byte-scanner. Populated by `translate_event` / `extract_usage_only` AFTER the
    /// Anthropic start-usage backfill, so it carries the TERMINAL prompt+completion counts. See the
    /// `last_usage` field.
    pub(crate) fn usage(&self) -> Option<&crate::ir::IrUsage> {
        self.last_usage.as_ref()
    }

    /// The terminal stream ERROR message, or `None` for a clean stream (Change A). The IR-sourced
    /// replacement for `UsageTap::terminal_error`: the `FirstByteBody` stream-end arm reads this to
    /// decide breaker disposition (a non-`None` value records a breaker transient and suppresses token
    /// billing). Set when a reader emits an [`crate::ir::IrStreamEvent::Error`]. See `terminal_error`.
    pub(crate) fn terminal_error(&self) -> Option<&str> {
        self.terminal_error.as_deref()
    }

    /// Abandon the stream as unrecoverable: release the reassembly buffer, set `aborted` so every
    /// subsequent `feed()` is a no-op, and let `finish()` emit the ingress-native terminal error
    /// frame. The two abandonment triggers are a reassembly buffer that grew past [`Self::MAX_BUF`]
    /// without a frame terminator, and a malformed egress event-stream prelude
    /// ([`crate::eventstream::DrainStatus::MalformedPrelude`]); both must surface an error, never a
    /// silent truncation.
    fn abort(&mut self) {
        self.aborted = true;
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.scanned = 0;
    }

    /// Call once at end-of-stream. Returns the INGRESS terminator (OpenAI → `data: [DONE]\n\n`,
    /// Anthropic → empty: its `message_stop` event already carries termination).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        // Bedrock-INGRESS abort path: the SSE reassembly buffer overflowed `MAX_BUF` without a frame
        // terminator (a malformed/adversarial upstream that never emits `\n\n`), so the translator was
        // abandoned and no `messageStop`/`metadata` was ever translated. A bare TCP close with neither
        // a terminal `:message-type: exception` frame nor `metadata` is structurally impossible from a
        // real ConverseStream endpoint (it ALWAYS ends with messageStop+metadata or an exception
        // frame) — a protocol-indistinguishability tell, and it leaves an AWS SDK keying on the final
        // exception/metadata event in an ambiguous state. Emit a modeled `InternalServerException`
        // frame so the close is well-formed for the native decoder, mirroring the inner-stream
        // transport-error path in proxy engine (`mid_stream_error_bytes`, also keyed off
        // `ingress_eventstream`). This is the only terminator on an aborted stream, so return early.
        if self.aborted {
            // The shared abort detail (see `STREAM_ABORT_DETAIL`) so the text a client sees is
            // identical across this Bedrock-eventstream path and proxy engine's SSE/forward abort path.
            const ABORT_DETAIL: &str = STREAM_ABORT_DETAIL;
            if let Some(exc_type) = self.framing.abort_exception_type() {
                // The ingress framing owns the wire exception TYPE name (Bedrock →
                // `InternalServerException`); this agnostic translator names none. `Some` here is the
                // eventstream-ingress abort signal (equivalent to the prior `ingress_eventstream` gate,
                // which only Bedrock sets).
                out.extend_from_slice(&crate::eventstream::encode_exception_frame(
                    exc_type,
                    ABORT_DETAIL,
                ));
                return out;
            }
            // SSE-INGRESS abort path (openai/anthropic/gemini/cohere/responses): the reassembly buffer
            // overflowed `MAX_BUF` without a frame terminator, so the translator was abandoned and the
            // happy-path terminal events (`message_stop`/finish chunk/…) were never produced. Returning
            // a bare close here leaves the SSE client with a SILENTLY-TRUNCATED stream and NO terminal /
            // error frame — indistinguishable from a successful short completion, so a native SDK
            // believes it received the whole answer. Emit the ingress protocol's NATIVE streaming error
            // frame so the truncation is signaled in-band, mirroring `proxy::mid_stream_error_bytes`'s
            // SSE branch (the same `write_response_event(&IrStreamEvent::Error(..))` path, framed by
            // `emit_ir_event` exactly as every other event on this stream). `emit_ir_event` takes the
            // non-eventstream branch here (`ingress_eventstream` is false), so this stays SSE text.
            let err = IrError {
                class: crate::breaker::StatusClass::ServerError,
                provider_signal: Some(ABORT_DETAIL.to_string()),
                retry_after: None,
            };
            let ev = crate::ir::IrStreamEvent::Error(err);
            self.emit_ir_event(&ev, &mut out);
            // OpenAI ingress still terminates with `data: [DONE]\n\n` after the error frame, matching a
            // genuine OpenAI stream (the error event is an in-band `data:` chunk, not the terminator).
            if self.emit_done {
                out.extend_from_slice(SSE_DONE_FRAME);
            }
            return out;
        }
        // SAME-PROTOCOL verbatim mode: the upstream's OWN native terminator (`[DONE]`, the final
        // bedrock `metadata`/`messageStop` frame, etc.) already rode through `feed` byte-for-byte, so
        // `finish` must add NOTHING on the happy path — appending a synthetic `[DONE]` or a deferred
        // `metadata` frame here would duplicate the terminator and corrupt the verbatim stream. The
        // abort branch above still fires (a truncated same-proto stream must surface an in-band error),
        // and the IR pipeline never ran its terminator-emitting fan-out into `out` for same-proto.
        if self.same_proto {
            return out;
        }
        // FINISH framing seam: if the ingress framing deferred a `metadata` frame that was
        // never resolved (the Bedrock-ingress zero-usage stop with no trailing usage delta — the
        // default OpenAI streaming case), it returns the single best-effort zero-usage event to flush
        // here. A genuine Bedrock ConverseStream ALWAYS ends with a `metadata` frame; emitting a
        // zero-usage one is far closer to native than omitting it (which loses the AWS SDK's
        // `ConverseStreamMetadataEvent` callback and is a deterministic proxy tell). PassthroughFraming
        // returns `None`, so non-Bedrock ingress flushes nothing.
        if let Some(trailing) = self.framing.on_finish() {
            self.emit_ir_event(&trailing, &mut out);
        }
        // TERMINAL-USAGE FOLD flush (SSE ingress): the terminal `message_delta` was deferred during
        // `feed` so a trailing usage-only chunk could be merged into it (see `folds_terminal_usage`).
        // Emit it now — with the merged usage — followed by its `MessageStop`. On a stream that never
        // sent a trailing usage chunk this simply emits the terminal frame with the usage it already
        // had, just deferred to end-of-stream (nothing follows a stop, so ordering is unchanged). The
        // response body feeds this `finish()` output through the json-array framer too, so the terminal
        // frame reaches the client on the gemini-json-array path as well as plain SSE.
        if let Some((reason, stop_sequence, usage)) = self.pending_terminal.take() {
            self.emit_ir_event(
                &crate::ir::IrStreamEvent::MessageDelta {
                    stop_reason: Some(reason),
                    stop_sequence,
                    usage,
                },
                &mut out,
            );
            if self.pending_stop {
                self.emit_ir_event(&crate::ir::IrStreamEvent::MessageStop, &mut out);
            }
        }
        if self.emit_done {
            out.extend_from_slice(SSE_DONE_FRAME);
        }
        out
    }
}

/// Merge a trailing usage-only chunk's token counts into the deferred terminal usage (SSE
/// terminal-usage fold). Mirrors the `last_usage` accumulation rule: a non-zero/`Some` field in the
/// trailing chunk overrides the (typically zero) terminal value; a zero/`None` trailing field leaves
/// the terminal value intact, so a protocol that already carried usage on its terminal delta is never
/// clobbered by an absent trailing chunk.
fn merge_trailing_usage(acc: &mut crate::ir::IrUsage, trailing: &crate::ir::IrUsage) {
    if trailing.input_tokens > 0 {
        acc.input_tokens = trailing.input_tokens;
    }
    if trailing.output_tokens > 0 {
        acc.output_tokens = trailing.output_tokens;
    }
    if trailing.cache_creation_input_tokens.is_some() {
        acc.cache_creation_input_tokens = trailing.cache_creation_input_tokens;
    }
    if trailing.cache_read_input_tokens.is_some() {
        acc.cache_read_input_tokens = trailing.cache_read_input_tokens;
    }
}

#[cfg(test)]
mod merge_trailing_usage_tests {
    use super::merge_trailing_usage;
    use crate::ir::IrUsage;

    fn usage(i: u64, o: u64, cc: Option<u64>, cr: Option<u64>) -> IrUsage {
        IrUsage {
            input_tokens: i,
            output_tokens: o,
            cache_creation_input_tokens: cc,
            cache_read_input_tokens: cr,
        }
    }

    // 1.4.0 audit (streaming-billing): the terminal-usage fold merges a trailing usage-only chunk into
    // the deferred terminal delta. A non-zero/Some trailing field OVERRIDES; a zero/None trailing field
    // LEAVES the accumulator intact so a protocol that already carried usage on its terminal delta is
    // never clobbered by an absent trailing chunk. (Billing reads the merged accumulator.)
    #[test]
    fn trailing_nonzero_overrides_zero_leaves_intact() {
        // A terminal delta that carried zeros gets the real counts from the trailing usage chunk.
        let mut acc = usage(0, 0, None, None);
        merge_trailing_usage(&mut acc, &usage(120, 45, Some(7), Some(9)));
        assert_eq!((acc.input_tokens, acc.output_tokens), (120, 45));
        assert_eq!(acc.cache_creation_input_tokens, Some(7));
        assert_eq!(acc.cache_read_input_tokens, Some(9));

        // A terminal delta that ALREADY carried usage is NOT clobbered by an absent/zero trailing chunk.
        let mut acc = usage(200, 80, Some(3), Some(5));
        merge_trailing_usage(&mut acc, &usage(0, 0, None, None));
        assert_eq!((acc.input_tokens, acc.output_tokens), (200, 80));
        assert_eq!(acc.cache_creation_input_tokens, Some(3));
        assert_eq!(acc.cache_read_input_tokens, Some(5));

        // Field-by-field: only the non-zero/Some trailing fields win; the rest are preserved.
        let mut acc = usage(200, 0, Some(3), None);
        merge_trailing_usage(&mut acc, &usage(0, 90, None, Some(11)));
        assert_eq!(
            acc.input_tokens, 200,
            "zero trailing input preserves the accumulator"
        );
        assert_eq!(acc.output_tokens, 90, "non-zero trailing output overrides");
        assert_eq!(
            acc.cache_creation_input_tokens,
            Some(3),
            "None trailing preserves Some"
        );
        assert_eq!(
            acc.cache_read_input_tokens,
            Some(11),
            "Some trailing overrides None"
        );
    }
}
