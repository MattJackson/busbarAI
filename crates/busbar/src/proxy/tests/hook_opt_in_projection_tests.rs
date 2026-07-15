use super::*;

/// `build_prompt_projection` flattens both Anthropic content shapes: bare-string content and
/// `{type:"text"}` block arrays (text blocks joined by newline, non-text blocks skipped).
#[test]
fn prompt_projection_flattens_string_and_block_content() {
    let v: Value = serde_json::json!({
        "system": "be brief",
        "messages": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "part one"},
                {"type": "image", "source": {"data": "AAAA"}},
                {"type": "text", "text": "part two"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "part one\npart two".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // The bare-string message BORROWS from the body (the zero-copy path); the block-array
    // message is owned (flattening had to join).
    assert!(matches!(p.messages[0].1, std::borrow::Cow::Borrowed(_)));
    assert!(matches!(p.messages[1].1, std::borrow::Cow::Owned(_)));
}

/// A system prompt given as a BLOCK ARRAY (Anthropic allows both) flattens too; an absent /
/// empty system stays `None` so the wire omits the key.
#[test]
fn prompt_projection_system_blocks_and_absent() {
    let v: Value = serde_json::json!({
        "system": [{"type": "text", "text": "sys a"}, {"type": "text", "text": "sys b"}],
        "messages": []
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.system.as_deref(), Some("sys a\nsys b"));

    let v: Value = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.system, None);

    // A non-JSON / bodyless request (v == Null) projects empty, never panics.
    let p = build_prompt_projection(&Value::Null, "anthropic");
    assert_eq!(p.system, None);
    assert!(p.messages.is_empty());
}

/// PINS the message-entry contract: a media-only message (no text blocks) keeps its ENTRY with
/// empty text (index-aligned with the body and `message_count`, never silently dropped), and a
/// malformed message with no `role` key projects an empty role. The system field, by contrast,
/// coalesces empty to absent (there is no index to keep).
#[test]
fn prompt_projection_keeps_empty_entries_aligned() {
    let v: Value = serde_json::json!({
        "messages": [
            {"role": "user", "content": [{"type": "image", "source": {"data": "AAAA"}}]},
            {"content": "no role on this one"}
        ]
    });
    let p = build_prompt_projection(&v, "anthropic");
    assert_eq!(p.messages.len(), 2, "media-only entries must not vanish");
    assert_eq!(p.messages[0].0, "user");
    assert_eq!(p.messages[0].1, "", "media-only turn reads as empty text");
    assert_eq!(p.messages[1].0, "", "missing role projects as empty role");
    assert_eq!(p.messages[1].1, "no role on this one");
}

/// The SIZE signal and the content projection agree on a BLOCK-ARRAY system prompt: Anthropic
/// allows `system` as text blocks, and `system_text_chars` must count what
/// `build_prompt_projection` flattens (they diverged once — this is the tripwire).
#[test]
fn system_text_chars_counts_block_arrays() {
    let v: Value = serde_json::json!({
        "system": [{"type": "text", "text": "abcde"}, {"type": "text", "text": "fgh"}],
        "messages": []
    });
    assert_eq!(system_text_chars(&v, "anthropic"), 8);
    let p = build_prompt_projection(&v, "anthropic");
    // The flattened projection joins with a newline; the SIZE signal counts text only.
    assert_eq!(p.system.as_deref(), Some("abcde\nfgh"));

    let v: Value = serde_json::json!({"system": "plain", "messages": []});
    assert_eq!(system_text_chars(&v, "anthropic"), 5);
    assert_eq!(system_text_chars(&Value::Null, "anthropic"), 0);
}

/// REGRESSION (audit c1r4): the projection read-path was blind to GEMINI ingress — it read
/// only `messages`/`system`, so a gemini body (`contents`/`systemInstruction`/`parts`)
/// projected EMPTY: a rewrite gate saw `message_count: 0` with no prompt and silently
/// no-oped. The read side must mirror the dialects `apply_rewrite_to_body` writes.
#[test]
fn prompt_projection_reads_gemini_contents() {
    let v: Value = serde_json::json!({
        "systemInstruction": {"parts": [{"text": "be brief"}]},
        "contents": [
            {"role": "user", "parts": [{"text": "hello"}]},
            {"role": "model", "parts": [
                {"text": "part one"},
                {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
                {"text": "part two"}
            ]}
        ]
    });
    let p = build_prompt_projection(&v, "gemini");
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            // Gemini-native `model` is CANONICALIZED to `assistant` for the hook's IR view
            // (audit c1r14) — the hook sees the same vocabulary on every dialect.
            ("assistant".into(), "part one\npart two".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    // SIZE signals agree with the projection (minus join separators).
    assert_eq!(system_text_chars(&v, "gemini"), 8);
    assert_eq!(turn_count(&v, "gemini"), 2);
    assert_eq!(total_text_chars(&v, "gemini", 8), 8 + 5 + 16);
    // And the rewrite-request projection (the gate's view) is POPULATED, not blind.
    let req = build_rewrite_request(&v, "p", "gemini", false, true);
    assert_eq!(req.message_count, 2);
    assert!(req.total_chars > 0);
    assert_eq!(req.prompt.as_ref().unwrap().messages.len(), 2);
}

/// REGRESSION (audit c1r4), Responses-API half: `input` (list OR bare string) and
/// `instructions` must project — the old read-path saw neither.
#[test]
fn prompt_projection_reads_responses_input() {
    let v: Value = serde_json::json!({
        "instructions": "be brief",
        "input": [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": [{"type": "output_text", "text": "hi there"}]}
        ]
    });
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(p.system.as_deref(), Some("be brief"));
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "hi there".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert_eq!(system_text_chars(&v, "responses"), 8);
    assert_eq!(turn_count(&v, "responses"), 2);

    // A bare-string `input` is ONE implicit user turn — in the projection AND the count.
    let v: Value = serde_json::json!({"input": "just a question"});
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(
        p.messages,
        vec![("user".into(), "just a question".into())]
            as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>
    );
    assert_eq!(turn_count(&v, "responses"), 1);
    assert_eq!(total_text_chars(&v, "responses", 0), 15);

    let req = build_rewrite_request(&v, "p", "responses", false, true);
    assert_eq!(req.message_count, 1);
    assert_eq!(req.total_chars, 15);

    // REGRESSION (audit c1r9): TOP-LEVEL typed items in `input[]` carry text at the item ROOT
    // (`{type:"input_text", text}`), not under `content`. They must project (not blank) and
    // count toward the SIZE signal, with role inferred from `type`.
    let v: Value = serde_json::json!({
        "input": [
            {"type": "input_text", "text": "hello"},
            {"type": "output_text", "text": "hi back"}
        ]
    });
    let p = build_prompt_projection(&v, "responses");
    assert_eq!(
        p.messages,
        vec![
            ("user".into(), "hello".into()),
            ("assistant".into(), "hi back".into()),
        ] as Vec<(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)>,
        "top-level input_text/output_text items must project with inferred roles, not blank"
    );
    assert_eq!(
        total_text_chars(&v, "responses", 0),
        5 + 7,
        "top-level item text must count toward the size signal, not read as 0"
    );
    let req = build_rewrite_request(&v, "p", "responses", false, true);
    assert_eq!(req.message_count, 2);
    assert_eq!(req.total_chars, 12);
}

/// REGRESSION (audit c1r7): the `max_tokens` routing SIZE signal must be dialect-aware. The
/// Responses API names it `max_output_tokens`, so reading `max_tokens` unconditionally projected
/// `None` for every responses-ingress request — silently blinding any routing policy/tap that
/// keys on the size signal. Non-responses dialects still read `max_tokens`.
#[test]
fn max_tokens_signal_is_dialect_aware_for_responses() {
    // Responses ingress: only `max_output_tokens` is present.
    let resp: Value = serde_json::json!({"input": "hi", "max_output_tokens": 4096});
    assert_eq!(max_tokens_for(&resp, "responses"), Some(4096));
    // A stray `max_tokens` on a responses body is NOT the signal — the dialect ignores it.
    let resp_stray: Value =
        serde_json::json!({"input": "hi", "max_tokens": 999, "max_output_tokens": 4096});
    assert_eq!(max_tokens_for(&resp_stray, "responses"), Some(4096));
    // The routing projection is now populated for a responses request.
    let req = build_rewrite_request(&resp, "p", "responses", false, true);
    assert_eq!(req.max_tokens, Some(4096));

    // Every other dialect keeps reading `max_tokens`.
    let anth: Value = serde_json::json!({"messages": [], "max_tokens": 512});
    assert_eq!(max_tokens_for(&anth, "anthropic"), Some(512));
    assert_eq!(max_tokens_for(&anth, "gemini"), Some(512));
    // Absurd cap saturates rather than wrapping.
    let huge: Value = serde_json::json!({"max_tokens": u64::MAX});
    assert_eq!(max_tokens_for(&huge, "anthropic"), Some(u32::MAX));
}

/// Bedrock ingress rides the `messages` default: its `content: [{text}]` blocks (no `type`
/// key) flatten via the same text-keyed match as Anthropic blocks.
#[test]
fn prompt_projection_reads_bedrock_messages() {
    let v: Value = serde_json::json!({
        "system": [{"text": "sys"}],
        "messages": [
            {"role": "user", "content": [{"text": "hello"}, {"text": "again"}]}
        ]
    });
    let p = build_prompt_projection(&v, "bedrock");
    assert_eq!(p.system.as_deref(), Some("sys"));
    assert_eq!(p.messages[0].1, "hello\nagain");
    assert_eq!(turn_count(&v, "bedrock"), 1);
    assert_eq!(total_text_chars(&v, "bedrock", 3), 3 + 10);
}

/// `body_end_user` is dialect-aware: OpenAI `user` first, Anthropic `metadata.user_id` second,
/// `None` when neither (or the field is not a string).
#[test]
fn body_end_user_reads_both_dialects() {
    let v: Value = serde_json::json!({"user": "alice"});
    assert_eq!(body_end_user(&v).as_deref(), Some("alice"));
    let v: Value = serde_json::json!({"metadata": {"user_id": "bob"}});
    assert_eq!(body_end_user(&v).as_deref(), Some("bob"));
    let v: Value = serde_json::json!({"user": "alice", "metadata": {"user_id": "bob"}});
    assert_eq!(body_end_user(&v).as_deref(), Some("alice"));
    let v: Value = serde_json::json!({"user": 42});
    assert_eq!(body_end_user(&v), None);
    assert_eq!(body_end_user(&Value::Null), None);
    // Empty means "not supplied" in EITHER position: an empty OpenAI `user` falls THROUGH to
    // a populated Anthropic `metadata.user_id` (never shadows it), and empty-everywhere is
    // `None` — so an empty string can never ride the wire as `"user": ""`.
    let v: Value = serde_json::json!({"user": "", "metadata": {"user_id": "bob"}});
    assert_eq!(body_end_user(&v).as_deref(), Some("bob"));
    let v: Value = serde_json::json!({"user": ""});
    assert_eq!(body_end_user(&v), None);
    let v: Value = serde_json::json!({"metadata": {"user_id": ""}});
    assert_eq!(body_end_user(&v), None);
}
