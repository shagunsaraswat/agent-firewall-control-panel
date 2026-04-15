//! Span construction, classification, and redaction before emission.

use std::collections::HashMap;
use std::fmt;

use agentfirewall_core::types::SpanEvent;
use chrono::Utc;
use uuid::Uuid;

/// High-level span classification (maps to `SpanEvent.kind` wire strings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanKind {
    RunStart,
    RunEnd,
    ToolCall,
    ModelCall,
    Write,
    Delegation,
    SentinelSample,
    PolicyDecision,
    Custom(String),
}

impl SpanKind {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            SpanKind::RunStart => "run_start",
            SpanKind::RunEnd => "run_end",
            SpanKind::ToolCall => "tool_call",
            SpanKind::ModelCall => "model_call",
            SpanKind::Write => "write",
            SpanKind::Delegation => "delegation",
            SpanKind::SentinelSample => "sentinel_sample",
            SpanKind::PolicyDecision => "policy_decision",
            SpanKind::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for SpanKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fluent builder for [`SpanEvent`].
#[derive(Debug, Clone)]
pub struct SpanBuilder {
    event_id: Option<Uuid>,
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
    kind: SpanKind,
    tenant_id: Uuid,
    run_id: Uuid,
    agent_type: String,
    agent_id: Uuid,
    task_category: String,
    tool_name: String,
    tool_args_fingerprint: String,
    model_id: String,
    cost_usd: f64,
    input_tokens: u64,
    output_tokens: u64,
    step_index: u32,
    progress_score: f32,
    progress_delta: f32,
    write_target_uri: String,
    write_operation: String,
    net_host: String,
    net_method: String,
    attributes: HashMap<String, String>,
    sdk_version: String,
}

impl SpanBuilder {
    #[must_use]
    pub fn new(tenant_id: Uuid, run_id: Uuid) -> Self {
        Self {
            event_id: None,
            trace_id: String::new(),
            span_id: String::new(),
            parent_span_id: None,
            kind: SpanKind::RunStart,
            tenant_id,
            run_id,
            agent_type: String::new(),
            agent_id: Uuid::nil(),
            task_category: String::new(),
            tool_name: String::new(),
            tool_args_fingerprint: String::new(),
            model_id: String::new(),
            cost_usd: 0.0,
            input_tokens: 0,
            output_tokens: 0,
            step_index: 0,
            progress_score: 0.0,
            progress_delta: 0.0,
            write_target_uri: String::new(),
            write_operation: String::new(),
            net_host: String::new(),
            net_method: String::new(),
            attributes: HashMap::new(),
            sdk_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    #[must_use]
    pub fn event_id(mut self, id: Uuid) -> Self {
        self.event_id = Some(id);
        self
    }

    #[must_use]
    pub fn trace_id(mut self, id: &str) -> Self {
        self.trace_id = id.to_owned();
        self
    }

    #[must_use]
    pub fn span_id(mut self, id: &str) -> Self {
        self.span_id = id.to_owned();
        self
    }

    #[must_use]
    pub fn parent_span_id(mut self, id: &str) -> Self {
        self.parent_span_id = Some(id.to_owned());
        self
    }

    #[must_use]
    pub fn kind(mut self, kind: SpanKind) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    pub fn tool_call(mut self, name: &str, args_fingerprint: &str) -> Self {
        self.tool_name = name.to_owned();
        self.tool_args_fingerprint = args_fingerprint.to_owned();
        self
    }

    #[must_use]
    pub fn model_call(mut self, model_id: &str, input_tokens: u64, output_tokens: u64) -> Self {
        self.model_id = model_id.to_owned();
        self.input_tokens = input_tokens;
        self.output_tokens = output_tokens;
        self
    }

    #[must_use]
    pub fn write_op(mut self, target_uri: &str, operation: &str) -> Self {
        self.write_target_uri = target_uri.to_owned();
        self.write_operation = operation.to_owned();
        self
    }

    #[must_use]
    pub fn cost(mut self, usd: f64) -> Self {
        self.cost_usd = usd;
        self
    }

    #[must_use]
    pub fn progress(mut self, score: f32, delta: f32) -> Self {
        self.progress_score = score;
        self.progress_delta = delta;
        self
    }

    #[must_use]
    pub fn step(mut self, index: u32) -> Self {
        self.step_index = index;
        self
    }

    #[must_use]
    pub fn attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_owned(), value.to_owned());
        self
    }

    #[must_use]
    pub fn build(self) -> SpanEvent {
        SpanEvent {
            event_id: self.event_id.unwrap_or_else(Uuid::new_v4),
            trace_id: self.trace_id,
            span_id: self.span_id,
            parent_span_id: self.parent_span_id,
            ts: Utc::now(),
            tenant_id: self.tenant_id,
            workspace_id: None,
            project_id: None,
            agent_type: self.agent_type,
            agent_id: self.agent_id,
            task_category: self.task_category,
            run_id: self.run_id,
            kind: self.kind.as_str().to_owned(),
            tool_name: self.tool_name,
            tool_args_fingerprint: self.tool_args_fingerprint,
            model_id: self.model_id,
            cost_usd: self.cost_usd,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            step_index: self.step_index,
            progress_score: self.progress_score,
            progress_delta: self.progress_delta,
            write_target_uri: self.write_target_uri,
            write_operation: self.write_operation,
            net_host: self.net_host,
            net_method: self.net_method,
            attributes: self.attributes,
            sdk_version: self.sdk_version,
        }
    }
}

/// Declarative redaction rule for span attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPattern {
    pub field: String,
    pub replacement: String,
}

/// Removes or masks sensitive attribute values before emission.
pub struct SpanRedactor;

impl SpanRedactor {
    pub fn redact(span: &mut SpanEvent, patterns: &[RedactionPattern]) {
        for p in patterns {
            if let Some(v) = span.attributes.get_mut(&p.field) {
                *v = p.replacement.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_builder_defaults() {
        let tid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let b = SpanBuilder::new(tid, rid);
        let ev = b.build();
        assert_eq!(ev.tenant_id, tid);
        assert_eq!(ev.run_id, rid);
        assert_eq!(ev.kind, "run_start");
        assert_eq!(ev.trace_id, "");
        assert_eq!(ev.span_id, "");
        assert_eq!(ev.parent_span_id, None);
        assert_eq!(ev.cost_usd, 0.0);
        assert_eq!(ev.step_index, 0);
        assert!(ev.attributes.is_empty());
        assert_eq!(ev.sdk_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn span_builder_fluent_chain() {
        let eid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let ev = SpanBuilder::new(tid, rid)
            .event_id(eid)
            .trace_id("t1")
            .span_id("s1")
            .parent_span_id("p1")
            .kind(SpanKind::ToolCall)
            .tool_call("read_file", "fp:abc")
            .model_call("gpt-4", 10, 20)
            .write_op("file:///x", "append")
            .cost(0.01)
            .progress(0.9, 0.1)
            .step(3)
            .attribute("k", "v")
            .build();

        assert_eq!(ev.event_id, eid);
        assert_eq!(ev.trace_id, "t1");
        assert_eq!(ev.span_id, "s1");
        assert_eq!(ev.parent_span_id.as_deref(), Some("p1"));
        assert_eq!(ev.kind, "tool_call");
        assert_eq!(ev.tool_name, "read_file");
        assert_eq!(ev.tool_args_fingerprint, "fp:abc");
        assert_eq!(ev.model_id, "gpt-4");
        assert_eq!(ev.input_tokens, 10);
        assert_eq!(ev.output_tokens, 20);
        assert_eq!(ev.write_target_uri, "file:///x");
        assert_eq!(ev.write_operation, "append");
        assert_eq!(ev.cost_usd, 0.01);
        assert_eq!(ev.progress_score, 0.9);
        assert_eq!(ev.progress_delta, 0.1);
        assert_eq!(ev.step_index, 3);
        assert_eq!(ev.attributes.get("k").map(String::as_str), Some("v"));
        assert_eq!(ev.agent_id, Uuid::nil());
        assert!(ev.agent_type.is_empty());
        assert!(ev.task_category.is_empty());
        assert_eq!(ev.sdk_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn span_kind_as_str_and_display() {
        let cases = [
            (SpanKind::RunStart, "run_start"),
            (SpanKind::RunEnd, "run_end"),
            (SpanKind::ToolCall, "tool_call"),
            (SpanKind::ModelCall, "model_call"),
            (SpanKind::Write, "write"),
            (SpanKind::Delegation, "delegation"),
            (SpanKind::SentinelSample, "sentinel_sample"),
            (SpanKind::PolicyDecision, "policy_decision"),
            (SpanKind::Custom("my.custom".into()), "my.custom"),
        ];
        for (k, s) in cases {
            assert_eq!(k.as_str(), s);
            assert_eq!(k.to_string(), s);
        }
    }

    #[test]
    fn redaction_patterns() {
        let mut ev = SpanBuilder::new(Uuid::nil(), Uuid::nil())
            .attribute("secret", "hunter2")
            .attribute("ok", "visible")
            .build();

        SpanRedactor::redact(
            &mut ev,
            &[RedactionPattern {
                field: "secret".into(),
                replacement: "[REDACTED]".into(),
            }],
        );

        assert_eq!(
            ev.attributes.get("secret").map(String::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(ev.attributes.get("ok").map(String::as_str), Some("visible"));
    }

    #[test]
    fn custom_kind_in_event_kind_field() {
        let ev = SpanBuilder::new(Uuid::nil(), Uuid::nil())
            .kind(SpanKind::Custom("plugin/foo".into()))
            .build();
        assert_eq!(ev.kind, "plugin/foo");
    }
}
