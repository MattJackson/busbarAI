use super::*;

// A trivial OperationHandler + RequestHandler prove the trait objects are object-safe and the no-OperationHandler lookup works.
struct NoopModeration;
impl OperationHandler for NoopModeration {
    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("noop".into()))
    }
    fn write_request(&self, _ir: &IrReq) -> Bytes {
        Bytes::new()
    }
    fn read_response(&self, _w: &[u8]) -> Result<IrResp, CodecError> {
        Err(CodecError::Malformed("noop".into()))
    }
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}

struct OpenAiLike;
impl RequestHandler for OpenAiLike {
    fn protocol_name(&self) -> &'static str {
        "openai"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        // openai serves moderation; not, say, chat-on-a-moderation-only stub → None = no-handler 404.
        match op {
            Operation::Moderation => Some(&NoopModeration),
            _ => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.operation {
            Operation::Moderation => "/v1/moderations".into(),
            _ => String::new(),
        }
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        path.ends_with("/v1/moderations")
            .then_some(Operation::Moderation)
    }
}

#[test]
fn no_handler_lookup_returns_none_for_unsupported_op() {
    let h = OpenAiLike;
    assert!(h.operation_handler(Operation::Moderation).is_some());
    assert!(
        h.operation_handler(Operation::Chat).is_none(),
        "an absent OperationHandler IS the no-handler 404"
    );
    assert_eq!(h.protocol_name(), "openai");
}

#[test]
fn sub_op_reject_carries_op_and_model() {
    let r = IngressReject::UnsupportedSubOp {
        op: Operation::Image,
        model: "gpt-image-1".into(),
    };
    assert!(matches!(
        r,
        IngressReject::UnsupportedSubOp {
            op: Operation::Image,
            ..
        }
    ));
}
