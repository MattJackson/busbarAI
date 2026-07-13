
//! The two OpenAI<->Anthropic analog carries: `user` <-> `metadata.user_id` and
//! `parallel_tool_calls` <-> `!tool_choice.disable_parallel_tool_use`. Same switch, different
//! spelling/location — these must CROSS the seam instead of dying in `extra`.
use super::{AnthropicReader, AnthropicWriter};
use crate::proto::openai_chat::{OpenAiReader, OpenAiWriter};
use crate::proto::{ProtocolReader, ProtocolWriter};

fn tools_json() -> serde_json::Value {
    serde_json::json!([{
        "type": "function",
        "function": {"name": "f", "description": "d", "parameters": {"type": "object"}}
    }])
}

/// OpenAI -> Anthropic: `user` lands as `metadata.user_id`; `parallel_tool_calls: false`
/// lands inverted inside the caller's tool_choice object.
#[test]
fn openai_user_and_parallel_carry_to_anthropic() {
    let body = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": tools_json(),
        "tool_choice": "auto",
        "user": "end-user-7",
        "parallel_tool_calls": false
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.user.as_deref(), Some("end-user-7"));
    assert_eq!(ir.parallel_tool_calls, Some(false));
    // Promoted fields must NOT also ride extra (double-emit guard).
    assert!(!ir.extra.contains_key("user"));
    assert!(!ir.extra.contains_key("parallel_tool_calls"));

    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["metadata"]["user_id"], "end-user-7");
    assert_eq!(out["tool_choice"]["type"], "auto");
    assert_eq!(out["tool_choice"]["disable_parallel_tool_use"], true);
}

/// Anthropic -> OpenAI: `metadata.user_id` lands as `user`; `disable_parallel_tool_use: true`
/// lands inverted as `parallel_tool_calls: false`.
#[test]
fn anthropic_user_and_parallel_carry_to_openai() {
    // Tools present: `parallel_tool_calls` is only valid on OpenAI egress WITH tools (the writer
    // gates the emission on tools, matching OpenAI's own 400 on a tool-less request), and the
    // flag is meaningless without them anyway.
    let body = serde_json::json!({
        "model": "m",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {"user_id": "end-user-7"},
        "tools": tools_json(),
        "tool_choice": {"type": "auto", "disable_parallel_tool_use": true}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    assert_eq!(ir.user.as_deref(), Some("end-user-7"));
    assert_eq!(ir.parallel_tool_calls, Some(false));

    let out = OpenAiWriter.write_request(&ir);
    assert_eq!(out["user"], "end-user-7");
    assert_eq!(out["parallel_tool_calls"], false);
}

/// A tool-less request carrying `parallel_tool_calls` must NOT emit the flag on OpenAI egress —
/// OpenAI 400s on `parallel_tool_calls` without `tools`.
#[test]
fn parallel_tool_calls_omitted_on_openai_egress_without_tools() {
    let body = serde_json::json!({
        "model": "m",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
        "tool_choice": {"type": "auto", "disable_parallel_tool_use": true}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    assert_eq!(ir.parallel_tool_calls, Some(false));
    let out = OpenAiWriter.write_request(&ir);
    assert!(
        out.get("parallel_tool_calls").is_none(),
        "must not emit parallel_tool_calls without tools: {out}"
    );
}

/// Absence round-trips as absence: a request that never carried either field must not GAIN
/// `metadata`, `user`, `parallel_tool_calls`, or a synthesized `tool_choice` on translation.
#[test]
fn absence_gains_nothing() {
    let body = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.user, None);
    assert_eq!(ir.parallel_tool_calls, None);
    let out = AnthropicWriter.write_request(&ir);
    assert!(out.get("metadata").is_none());
    assert!(out.get("tool_choice").is_none());

    let ir2 = AnthropicReader
        .read_request(&serde_json::json!({
            "model": "m", "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .expect("parses");
    let out2 = OpenAiWriter.write_request(&ir2);
    assert!(out2.get("user").is_none());
    assert!(out2.get("parallel_tool_calls").is_none());
}

/// `parallel_tool_calls` with NO tool_choice synthesizes the neutral `auto` carrier — but only
/// when tools exist; a tool-less request must not gain a tool_choice Anthropic would reject.
#[test]
fn parallel_flag_with_tool_choice_none_stays_none() {
    // parallel_tool_calls:false with tool_choice:"none" must NOT flip the directive to auto —
    // Anthropic rejects disable_parallel_tool_use on a `none` choice, so the writer leaves it
    // as {type:none} without the flag.
    let body = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": tools_json(),
        "tool_choice": "none",
        "parallel_tool_calls": false
    });
    let ir = OpenAiReader.read_request(&body).expect("parses");
    assert_eq!(ir.parallel_tool_calls, Some(false));
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["tool_choice"]["type"], "none");
    assert!(
        out["tool_choice"]
            .get("disable_parallel_tool_use")
            .is_none(),
        "disable_parallel_tool_use must not ride a type:none choice: {out}"
    );
}

#[test]
fn parallel_without_directive_synthesizes_auto_only_with_tools() {
    let with_tools = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "tools": tools_json(),
        "parallel_tool_calls": false
    });
    let ir = OpenAiReader.read_request(&with_tools).expect("parses");
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["tool_choice"]["type"], "auto");
    assert_eq!(out["tool_choice"]["disable_parallel_tool_use"], true);

    let toolless = serde_json::json!({
        "model": "m",
        "messages": [{"role": "user", "content": "hi"}],
        "parallel_tool_calls": false
    });
    let ir2 = OpenAiReader.read_request(&toolless).expect("parses");
    let out2 = AnthropicWriter.write_request(&ir2);
    assert!(
        out2.get("tool_choice").is_none(),
        "no tools -> no synthesized tool_choice: {out2}"
    );
}

/// A NATIVE Anthropic `metadata` object (riding `extra`) beats the promoted carry on the
/// writer's overlay — the verbatim original always wins.
#[test]
fn native_metadata_wins_over_promoted_user() {
    let body = serde_json::json!({
        "model": "m",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
        "metadata": {"user_id": "original"}
    });
    let ir = AnthropicReader.read_request(&body).expect("parses");
    // Same-protocol translated path: extra still carries metadata verbatim.
    let out = AnthropicWriter.write_request(&ir);
    assert_eq!(out["metadata"]["user_id"], "original");
    assert_eq!(
        out["metadata"].as_object().unwrap().len(),
        1,
        "metadata must be the verbatim original, not a merged object"
    );
}
