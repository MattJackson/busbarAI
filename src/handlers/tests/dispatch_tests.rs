use super::*;

#[test]
fn chat_declares_its_capabilities() {
    let chat = CHAT;
    assert_eq!(chat.name(), "chat");
    assert!(chat.streaming(), "chat streams");
    assert!(
        chat.taps_nonstream_usage(),
        "chat bills tokens from the body"
    );
    assert!(
        chat.wants_stream(&serde_json::json!({"stream": true})),
        "chat reads the stream boolean"
    );
    assert!(!chat.wants_stream(&serde_json::json!({})));
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": "you are helpful"})),
        Some("you are helpful")
    );
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": ""})),
        None
    );
}

/// The load-bearing invariant of the operations axis: the forward engine branches on the
/// *capabilities* an OperationHandler declares, never on an operation's *identity*. If someone adds
/// `if op.name() == "embeddings"` or `match op.name() { ... }` to the engine, chat stops being
/// just operation #1 and the "add an operation without touching the engine" property is lost.
/// (`op.name()` used as a value — a tracing span field — is fine; only comparisons/matches are
/// forbidden.)
#[test]
fn engine_never_branches_on_operation_identity() {
    // Scan EVERY file of the forward engine (the module split must not open a blind spot).
    let engine_files = [("src/proxy/mod.rs", include_str!("../../proxy/mod.rs"))];
    let forbidden = [
        "op.name() ==",
        "op.name()==",
        "== op.name()",
        "==op.name()",
        "match op.name()",
    ];
    for (file, engine) in engine_files {
        for pat in forbidden {
            assert!(
                    !engine.contains(pat),
                    "{file} contains a forbidden operation-identity branch (`{pat}`). The \
                     engine must read capabilities off the OperationHandler, never branch on op.name()."
                );
        }
    }
}
