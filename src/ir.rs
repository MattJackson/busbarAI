// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! ADR-0005 superset IR — request + response/stream sides (B-502a/B-502b).

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Used by tests only (B-502a)
pub(crate) struct IrRequest {
    pub system: Vec<IrBlock>,
    pub messages: Vec<IrMessage>,
    pub tools: Vec<IrTool>,
    pub max_tokens: Option<u32>,
    // f64 (not ADR-0005's f32): JSON numbers are f64; an f32 round-trip silently mutates a
    // caller's temperature (0.7 → 0.699999988) — the exact lossiness busbar exists to avoid.
    pub temperature: Option<f64>,
    pub stream: bool,
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Used by tests only (B-502a)
pub(crate) struct IrMessage {
    pub role: IrRole,
    pub content: Vec<IrBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Used by tests only (B-502a)
pub(crate) enum IrRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Used by tests only (B-502a)
pub(crate) enum IrBlock {
    Text {
        text: String,
        cache_control: Option<CacheControl>,
        citations: Vec<Value>,
    },
    Thinking {
        text: String,
        signature: Option<String>,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        tool_use_id: String,
        content: Vec<IrBlock>,
        is_error: bool,
    },
    Image {
        media_type: String,
        data: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Used by tests only (B-502a)
pub(crate) struct CacheControl {
    pub kind: CacheKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Used by tests only (B-502a)
pub(crate) enum CacheKind {
    Ephemeral,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Used by tests only (B-502a)
pub(crate) struct IrTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // B-502b: response/stream IR types (used by tests in proto.rs)
pub(crate) enum IrStreamEvent {
    MessageStart {
        role: IrRole,
        usage: Option<IrUsage>,
    },
    BlockStart {
        index: usize,
        block: IrBlockMeta,
    },
    BlockDelta {
        index: usize,
        delta: IrDelta,
    },
    BlockStop {
        index: usize,
    },
    MessageDelta {
        stop_reason: Option<String>,
        usage: IrUsage,
    },
    MessageStop,
    Error(crate::proto::IrError),
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // B-502b: response/stream IR types (used by tests in proto.rs)
pub(crate) struct IrUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // B-502b: response/stream IR types (used by tests in proto.rs)
pub(crate) enum IrBlockMeta {
    Text,
    Thinking,
    ToolUse { id: String, name: String },
    Image,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code, clippy::enum_variant_names)] // B-502b: response/stream IR types (used by tests in proto.rs)
pub(crate) enum IrDelta {
    TextDelta(String),
    ThinkingDelta(String),
    InputJsonDelta(String),
    SignatureDelta(String),
}
