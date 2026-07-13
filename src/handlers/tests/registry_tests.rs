
use super::*;
use crate::operation::Operation;

#[test]
fn registry_resolves_openai_and_its_moderation_handler() {
    let h = request_handler("openai").expect("openai handler registered");
    assert_eq!(h.protocol_name(), "openai");
    assert!(h.operation_handler(Operation::Moderation).is_some());
    assert!(
        request_handler("zzz-unknown").is_none(),
        "unknown protocol → None"
    );
}

#[test]
fn every_protocol_serves_chat_via_its_request_handler() {
    // Chat is operation #1, reached through the SAME registry as every other op. All six
    // protocols resolve a handler and a chat OperationHandler — the unified dispatch, no special path.
    for proto in [
        "openai",
        "anthropic",
        "gemini",
        "bedrock",
        "cohere",
        "responses",
    ] {
        let h = request_handler(proto).expect("protocol registered");
        assert!(
            h.operation_handler(Operation::Chat).is_some(),
            "{proto} must serve chat via operation_handler(Chat)"
        );
    }
}
