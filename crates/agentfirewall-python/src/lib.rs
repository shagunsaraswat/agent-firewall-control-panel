//! PyO3 extension: top-level module `agentfirewall` with `core`, `sentinel`, `witness`, and `learner` submodules.

mod util;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use agentfirewall_core::policy::{CompiledPolicySet, PolicyEvaluator, PolicyRule};
use agentfirewall_core::reason::{ReasonCodeRegistry, ReasonEntry, ReasonFamily, Severity};
use agentfirewall_core::run::{RunConfig, RunContextManager};
use agentfirewall_core::types::{
    ActionDescriptor, ActionType, BudgetSnapshot, InterventionLevel, LearnerMode, PolicyDecision,
    ProgressSnapshot, ReasonCode, RunContext, SpanEvent,
};
use agentfirewall_embed::EmbedEngine;
use agentfirewall_learner::{LearnerClient, LearnerClientConfig, LearnerError};
use agentfirewall_sentinel::{MockSentinelEmbedder, SentinelConfig, SentinelError, SentinelTracker};
use agentfirewall_witness::capture::StateSnapshot;
use agentfirewall_witness::guard::WitnessGuard;
use agentfirewall_witness::revalidation::RevalidationOutcome;
use parking_lot::Mutex;
use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAnyMethods, PyDict, PyModule};
use pyo3_async_runtimes::tokio::future_into_py;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use uuid::Uuid;

// --- core --------------------------------------------------------------------

#[pyclass(name = "PolicyDecision", module = "agentfirewall.core")]
#[derive(Clone)]
struct PyPolicyDecision {
    inner: PolicyDecision,
}

#[pymethods]
impl PyPolicyDecision {
    #[getter]
    fn kind(&self) -> String {
        policy_decision_kind(&self.inner)
    }

    #[getter]
    fn reason_code(&self) -> String {
        match &self.inner {
            PolicyDecision::Allow { reason_code }
            | PolicyDecision::Deny { reason_code, .. }
            | PolicyDecision::Downgrade { reason_code, .. }
            | PolicyDecision::Pause { reason_code, .. }
            | PolicyDecision::RequireApproval { reason_code, .. } => reason_code.to_string(),
        }
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let v = serde_json::to_value(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("serialize PolicyDecision: {e}")))?;
        util::json_value_to_py(py, &v)
    }

    fn __repr__(&self) -> String {
        format!(
            "PolicyDecision(kind={:?})",
            policy_decision_kind(&self.inner)
        )
    }

    fn __str__(&self) -> String {
        serde_json::to_string(&self.inner).unwrap_or_else(|_| "<PolicyDecision>".into())
    }
}

fn policy_decision_kind(d: &PolicyDecision) -> String {
    match d {
        PolicyDecision::Allow { .. } => "allow".into(),
        PolicyDecision::Deny { .. } => "deny".into(),
        PolicyDecision::Downgrade { .. } => "downgrade".into(),
        PolicyDecision::Pause { .. } => "pause".into(),
        PolicyDecision::RequireApproval { .. } => "require_approval".into(),
    }
}

#[pyclass(name = "ReasonCode", module = "agentfirewall.core")]
#[derive(Clone)]
struct PyReasonCode {
    inner: ReasonCode,
}

#[pymethods]
impl PyReasonCode {
    #[new]
    fn new(code: &str) -> Self {
        Self {
            inner: ReasonCode::new(code),
        }
    }

    #[getter]
    fn code(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("ReasonCode({:?})", self.inner.as_str())
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

#[pyclass(name = "BudgetSnapshot", module = "agentfirewall.core")]
#[derive(Clone)]
struct PyBudgetSnapshot {
    inner: BudgetSnapshot,
}

#[pymethods]
impl PyBudgetSnapshot {
    #[getter]
    fn reserved_usd(&self) -> String {
        self.inner.reserved_usd.to_string()
    }

    #[getter]
    fn estimated_usd(&self) -> String {
        self.inner.estimated_usd.to_string()
    }

    #[getter]
    fn actual_usd(&self) -> String {
        self.inner.actual_usd.to_string()
    }

    #[getter]
    fn limit_usd(&self) -> String {
        self.inner.limit_usd.to_string()
    }

    #[getter]
    fn updated_at(&self) -> String {
        self.inner.updated_at.to_rfc3339()
    }

    fn __repr__(&self) -> String {
        format!(
            "BudgetSnapshot(actual_usd={}, limit_usd={})",
            self.inner.actual_usd, self.inner.limit_usd
        )
    }

    fn __str__(&self) -> String {
        serde_json::to_string(&self.inner).unwrap_or_else(|_| "<BudgetSnapshot>".into())
    }
}

#[pyclass(name = "InterventionLevel", module = "agentfirewall.core", eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PyInterventionLevel {
    Warn,
    Downgrade,
    Pause,
    Deny,
}

impl From<InterventionLevel> for PyInterventionLevel {
    fn from(v: InterventionLevel) -> Self {
        match v {
            InterventionLevel::Warn => Self::Warn,
            InterventionLevel::Downgrade => Self::Downgrade,
            InterventionLevel::Pause => Self::Pause,
            InterventionLevel::Deny => Self::Deny,
        }
    }
}

impl From<PyInterventionLevel> for InterventionLevel {
    fn from(v: PyInterventionLevel) -> Self {
        match v {
            PyInterventionLevel::Warn => InterventionLevel::Warn,
            PyInterventionLevel::Downgrade => InterventionLevel::Downgrade,
            PyInterventionLevel::Pause => InterventionLevel::Pause,
            PyInterventionLevel::Deny => InterventionLevel::Deny,
        }
    }
}

#[pymethods]
impl PyInterventionLevel {
    fn __repr__(&self) -> String {
        format!("InterventionLevel.{self:?}")
    }

    fn __str__(&self) -> String {
        serde_json::to_value(InterventionLevel::from(*self))
            .ok()
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))
            .unwrap_or_else(|| format!("{self:?}"))
    }
}

#[pyclass(name = "LearnerMode", module = "agentfirewall.core", eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PyLearnerMode {
    ObserveOnly,
    Recommend,
    AutoPromoteSafe,
}

impl From<LearnerMode> for PyLearnerMode {
    fn from(v: LearnerMode) -> Self {
        match v {
            LearnerMode::ObserveOnly => Self::ObserveOnly,
            LearnerMode::Recommend => Self::Recommend,
            LearnerMode::AutoPromoteSafe => Self::AutoPromoteSafe,
        }
    }
}

impl From<PyLearnerMode> for LearnerMode {
    fn from(v: PyLearnerMode) -> Self {
        match v {
            PyLearnerMode::ObserveOnly => LearnerMode::ObserveOnly,
            PyLearnerMode::Recommend => LearnerMode::Recommend,
            PyLearnerMode::AutoPromoteSafe => LearnerMode::AutoPromoteSafe,
        }
    }
}

#[pymethods]
impl PyLearnerMode {
    fn __repr__(&self) -> String {
        format!("LearnerMode.{self:?}")
    }

    fn __str__(&self) -> String {
        serde_json::to_value(LearnerMode::from(*self))
            .ok()
            .and_then(|v| v.as_str().map(std::string::ToString::to_string))
            .unwrap_or_else(|| format!("{self:?}"))
    }
}

#[pyclass(name = "ProgressSnapshot", module = "agentfirewall.core")]
#[derive(Clone)]
struct PyProgressSnapshot {
    inner: ProgressSnapshot,
}

#[pymethods]
impl PyProgressSnapshot {
    #[getter]
    fn run_id(&self) -> String {
        self.inner.run_id.to_string()
    }

    #[getter]
    fn step_index(&self) -> u64 {
        self.inner.step_index
    }

    #[getter]
    fn similarity(&self) -> f32 {
        self.inner.similarity
    }

    #[getter]
    fn delta(&self) -> f32 {
        self.inner.delta
    }

    #[getter]
    fn ema_similarity(&self) -> f32 {
        self.inner.ema_similarity
    }

    #[getter]
    fn ema_delta(&self) -> f32 {
        self.inner.ema_delta
    }

    #[getter]
    fn consecutive_stalls(&self) -> u32 {
        self.inner.consecutive_stalls
    }

    #[getter]
    fn embedding_model_revision(&self) -> String {
        self.inner.embedding_model_revision.clone()
    }

    #[getter]
    fn observed_at(&self) -> String {
        self.inner.observed_at.to_rfc3339()
    }

    fn __repr__(&self) -> String {
        format!(
            "ProgressSnapshot(run_id={}, step_index={}, similarity={})",
            self.inner.run_id, self.inner.step_index, self.inner.similarity
        )
    }

    fn __str__(&self) -> String {
        serde_json::to_string(&self.inner).unwrap_or_else(|_| "<ProgressSnapshot>".into())
    }
}

#[pyclass(name = "PolicyEvaluator", module = "agentfirewall.core")]
struct PyPolicyEvaluator {
    inner: Mutex<PolicyEvaluator>,
}

#[pymethods]
impl PyPolicyEvaluator {
    #[new]
    fn new() -> Self {
        Self {
            inner: Mutex::new(PolicyEvaluator::new()),
        }
    }

    fn load_rules_json(&self, rules: &str) -> PyResult<()> {
        let set: CompiledPolicySet = serde_json::from_str(rules)
            .map_err(|e| PyValueError::new_err(format!("invalid policy JSON: {e}")))?;
        self.inner.lock().load_policy_set(set);
        Ok(())
    }

    fn evaluate(
        &self,
        py: Python<'_>,
        action_type: &str,
        resource: &str,
        context: &Bound<'_, PyAny>,
    ) -> PyResult<PyPolicyDecision> {
        let mut ctx_val = util::py_to_json_value(py, context)?;
        let cost = ctx_val
            .get("cost_estimate_usd")
            .or_else(|| ctx_val.get("projected_cost_usd"))
            .cloned();
        if let Some(m) = ctx_val.as_object_mut() {
            m.remove("cost_estimate_usd");
            m.remove("projected_cost_usd");
        }
        let ctx: RunContext = serde_json::from_value(ctx_val).map_err(|e| {
            PyValueError::new_err(format!("invalid RunContext in context dict: {e}"))
        })?;
        let cost_dec = decimal_from_json_value(cost)?;
        let action = ActionDescriptor {
            action_type: parse_action_type(action_type)?,
            resource: resource.to_string(),
            cost_estimate_usd: cost_dec,
            metadata: HashMap::new(),
        };
        let decision = self.inner.lock().evaluate(&ctx, &action);
        Ok(PyPolicyDecision { inner: decision })
    }

    fn add_rule(&self, rule_json: &str) -> PyResult<()> {
        let rule: PolicyRule = serde_json::from_str(rule_json)
            .map_err(|e| PyValueError::new_err(format!("invalid rule JSON: {e}")))?;
        let mut ev = self.inner.lock();
        let Some(mut snap) = ev.active_snapshot() else {
            return Err(PyRuntimeError::new_err(
                "load_rules_json must be called before add_rule",
            ));
        };
        snap.rules.push(rule);
        let new_set = CompiledPolicySet::new(
            snap.rules,
            snap.default_action,
            snap.version_id,
            snap.tenant_id,
        );
        ev.load_policy_set(new_set);
        Ok(())
    }

    fn __repr__(&self) -> String {
        "PolicyEvaluator()".into()
    }
}

#[pyclass(name = "RunContextManager", module = "agentfirewall.core")]
#[derive(Clone)]
struct PyRunContextManager {
    inner: RunContextManager,
}

#[pymethods]
impl PyRunContextManager {
    #[new]
    #[pyo3(signature = (run_id, tenant_id, goal))]
    fn new(run_id: &str, tenant_id: &str, goal: &str) -> PyResult<Self> {
        let run_id = Uuid::parse_str(run_id)
            .map_err(|e| PyValueError::new_err(format!("invalid run_id: {e}")))?;
        let tenant_id = Uuid::parse_str(tenant_id)
            .map_err(|e| PyValueError::new_err(format!("invalid tenant_id: {e}")))?;
        let cfg = RunConfig {
            tenant_id,
            run_id,
            agent_id: Uuid::new_v4(),
            workspace_id: None,
            project_id: None,
            mode: agentfirewall_core::types::RunMode::Enforce,
            goal_text: goal.to_string(),
            budget_limit_usd: Decimal::new(1_000_000, 0),
            labels: HashMap::new(),
            metadata: Value::Null,
        };
        Ok(Self {
            inner: RunContextManager::new(cfg),
        })
    }

    fn start(&self) -> PyResult<()> {
        Ok(())
    }

    fn record_cost(&self, amount: f64, unit: &str) -> PyResult<()> {
        if !unit.eq_ignore_ascii_case("usd") {
            return Err(PyValueError::new_err(format!(
                "unsupported cost unit (only 'usd' supported): {unit}"
            )));
        }
        let d = Decimal::try_from(amount)
            .map_err(|_| PyValueError::new_err("amount is not a valid decimal"))?;
        self.inner
            .update_budget(d)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    fn record_step(&self, step_id: &str, tool: &str) -> PyResult<()> {
        self.inner.advance_step();
        let mut meta = HashMap::new();
        meta.insert("step_id".into(), Value::String(step_id.to_string()));
        let action = ActionDescriptor {
            action_type: ActionType::ToolCall,
            resource: tool.to_string(),
            cost_estimate_usd: None,
            metadata: meta,
        };
        self.inner.record_step(
            action,
            PolicyDecision::Allow {
                reason_code: ReasonCode::new("STEP_RECORDED"),
            },
            None,
        );
        Ok(())
    }

    fn budget(&self) -> PyBudgetSnapshot {
        PyBudgetSnapshot {
            inner: self.inner.context().budget,
        }
    }

    fn context<'py>(&self, py: Python<'py>) -> PyResult<PyObject> {
        let v = serde_json::to_value(self.inner.context())
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        util::json_value_to_py(py, &v)
    }

    fn __repr__(&self) -> String {
        let c = self.inner.context();
        format!(
            "RunContextManager(run_id={}, tenant_id={})",
            c.run_id, c.tenant_id
        )
    }
}

#[pyclass(name = "ReasonCodeRegistry", module = "agentfirewall.core")]
struct PyReasonCodeRegistry {
    inner: Mutex<ReasonCodeRegistry>,
}

#[pymethods]
impl PyReasonCodeRegistry {
    #[new]
    fn new() -> Self {
        Self {
            inner: Mutex::new(ReasonCodeRegistry::new()),
        }
    }

    fn register(&self, code: &str, description: &str) -> PyResult<()> {
        let entry = ReasonEntry {
            code: ReasonCode::new(code),
            family: ReasonFamily::System,
            human_message: description.to_string(),
            severity: Severity::Info,
        };
        self.inner
            .lock()
            .register(entry)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn lookup(&self, code: &str) -> Option<String> {
        self.inner
            .lock()
            .lookup(&ReasonCode::new(code))
            .map(|e| e.human_message.clone())
    }

    fn __repr__(&self) -> String {
        format!("ReasonCodeRegistry(len={})", self.inner.lock().len())
    }
}

fn register_core_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "agentfirewall.core")?;
    m.add_class::<PyPolicyDecision>()?;
    m.add_class::<PyReasonCode>()?;
    m.add_class::<PyBudgetSnapshot>()?;
    m.add_class::<PyInterventionLevel>()?;
    m.add_class::<PyLearnerMode>()?;
    m.add_class::<PyProgressSnapshot>()?;
    m.add_class::<PyPolicyEvaluator>()?;
    m.add_class::<PyRunContextManager>()?;
    m.add_class::<PyReasonCodeRegistry>()?;
    parent.add_submodule(&m)?;
    let sys_mod = py.import("sys")?;
    let modules = sys_mod.getattr("modules")?;
    modules.set_item("agentfirewall.core", &m)?;
    Ok(())
}

// --- sentinel ----------------------------------------------------------------

fn parse_intervention_level(s: &str) -> PyResult<InterventionLevel> {
    match s.to_ascii_lowercase().as_str() {
        "warn" => Ok(InterventionLevel::Warn),
        "downgrade" => Ok(InterventionLevel::Downgrade),
        "pause" => Ok(InterventionLevel::Pause),
        "deny" => Ok(InterventionLevel::Deny),
        _ => Err(PyValueError::new_err(format!(
            "unknown intervention level: {s}"
        ))),
    }
}

fn sentinel_config_from_py(obj: &Bound<'_, PyAny>) -> PyResult<(SentinelConfig, bool)> {
    let d = obj
        .downcast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("config must be a dict"))?;
    let mut c = SentinelConfig::default();
    let mut use_fastembed = false;

    if let Ok(Some(v)) = d.get_item("enabled") {
        if !v.is_none() {
            c.enabled = v.extract::<bool>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("model_id") {
        if !v.is_none() {
            c.model_id = v.extract::<String>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("stall_threshold") {
        if !v.is_none() {
            c.stall_threshold = v.extract::<f32>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("stall_window") {
        if !v.is_none() {
            c.stall_window = v.extract::<u32>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("regression_threshold") {
        if !v.is_none() {
            c.regression_threshold = v.extract::<f32>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("max_intervention") {
        if !v.is_none() {
            let s: String = v.extract()?;
            c.max_intervention = parse_intervention_level(&s)?;
        }
    }
    if let Ok(Some(v)) = d.get_item("intervention") {
        if !v.is_none() {
            let s: String = v.extract()?;
            c.max_intervention = parse_intervention_level(&s)?;
        }
    }
    if let Ok(Some(v)) = d.get_item("max_embed_input_bytes") {
        if !v.is_none() {
            c.max_embed_input_bytes = v.extract::<usize>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("ema_alpha") {
        if !v.is_none() {
            c.ema_alpha = v.extract::<f32>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("use_fastembed") {
        if !v.is_none() {
            use_fastembed = v.extract::<bool>()?;
        }
    }

    Ok((c, use_fastembed))
}

fn step_evaluation_to_py(
    py: Python<'_>,
    ev: &agentfirewall_sentinel::StepEvaluation,
) -> PyResult<PyObject> {
    let intervention = ev.intervention.as_ref().map(|i| {
        json!({
            "level": serde_json::to_value(i.level).unwrap_or(Value::Null),
            "reason_code": i.reason_code.to_string(),
            "message": &i.message,
            "snapshot": serde_json::to_value(&i.snapshot).unwrap_or(Value::Null),
        })
    });
    let v = json!({
        "progress": serde_json::to_value(&ev.progress).unwrap_or(Value::Null),
        "intervention": intervention,
    });
    util::json_value_to_py(py, &v)
}

#[pyclass(name = "SentinelTracker", module = "agentfirewall.sentinel")]
struct PySentinelTracker {
    inner: Mutex<SentinelTracker>,
}

#[pymethods]
impl PySentinelTracker {
    #[new]
    #[pyo3(signature = (config=None))]
    fn new(config: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let (cfg, use_fastembed) = match config {
            None => (SentinelConfig::default(), false),
            Some(obj) if obj.is_none() => (SentinelConfig::default(), false),
            Some(obj) => sentinel_config_from_py(obj)?,
        };

        let tracker = if use_fastembed {
            let engine = EmbedEngine::new(&cfg.model_id, cfg.max_embed_input_bytes)
                .map_err(|e| PyRuntimeError::new_err(format!("FastEmbed init failed: {e}")))?;
            let handle = engine.into_handle();
            SentinelTracker::new(cfg, handle).map_err(sentinel_err_to_py)?
        } else {
            SentinelTracker::new_with_embedder(
                cfg,
                Arc::new(MockSentinelEmbedder::new(384, "mock")),
            )
            .map_err(sentinel_err_to_py)?
        };

        Ok(Self {
            inner: Mutex::new(tracker),
        })
    }

    fn register_goal(&self, run_id: &str, goal: &str) -> PyResult<()> {
        let rid = Uuid::parse_str(run_id)
            .map_err(|e| PyValueError::new_err(format!("invalid run_id: {e}")))?;
        self.inner
            .lock()
            .register_goal(rid, goal)
            .map_err(sentinel_err_to_py)
    }

    fn evaluate_step(
        &self,
        py: Python<'_>,
        run_id: &str,
        step: u64,
        summary: &str,
    ) -> PyResult<PyObject> {
        let rid = Uuid::parse_str(run_id)
            .map_err(|e| PyValueError::new_err(format!("invalid run_id: {e}")))?;
        let ev = self
            .inner
            .lock()
            .evaluate_step(rid, step, summary)
            .map_err(sentinel_err_to_py)?;
        step_evaluation_to_py(py, &ev)
    }

    fn reset(&self, run_id: &str) -> PyResult<()> {
        let rid = Uuid::parse_str(run_id)
            .map_err(|e| PyValueError::new_err(format!("invalid run_id: {e}")))?;
        self.inner.lock().reset(rid);
        Ok(())
    }

    fn __repr__(&self) -> String {
        "SentinelTracker(...)".into()
    }
}

fn sentinel_err_to_py(e: SentinelError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn register_sentinel_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "agentfirewall.sentinel")?;
    m.add_class::<PySentinelTracker>()?;
    parent.add_submodule(&m)?;
    let sys_mod = py.import("sys")?;
    sys_mod
        .getattr("modules")?
        .set_item("agentfirewall.sentinel", &m)?;
    Ok(())
}

// --- witness -----------------------------------------------------------------

fn revalidation_to_value(o: &RevalidationOutcome) -> PyResult<Value> {
    Ok(json!({
        "result": serde_json::to_value(&o.result)
            .map_err(|e| PyValueError::new_err(e.to_string()))?,
        "original_hash": serde_json::to_value(o.original_hash)
            .map_err(|e| PyValueError::new_err(e.to_string()))?,
        "current_hash": serde_json::to_value(o.current_hash)
            .map_err(|e| PyValueError::new_err(e.to_string()))?,
        "revalidated_at": o.revalidated_at.to_rfc3339(),
        "elapsed_since_capture_ms": o.elapsed_since_capture_ms,
    }))
}

#[pyclass(name = "WitnessGuard", module = "agentfirewall.witness")]
#[derive(Clone, Default)]
struct PyWitnessGuard;

#[pymethods]
impl PyWitnessGuard {
    #[new]
    fn new() -> Self {
        Self
    }

    fn capture_json<'py>(&self, py: Python<'py>, value: &str, uri: &str) -> PyResult<PyObject> {
        let v: Value = util::json_str_to_value(value)?;
        let guard = WitnessGuard::new();
        let snap = guard
            .capture_json_for_approval(&v, uri)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let j = serde_json::to_value(&snap).map_err(|e| PyValueError::new_err(e.to_string()))?;
        util::json_value_to_py(py, &j)
    }

    fn verify_json<'py>(
        &self,
        py: Python<'py>,
        snapshot: &Bound<'_, PyAny>,
        current: &str,
    ) -> PyResult<PyObject> {
        let snap_val = util::py_to_json_value(py, snapshot)?;
        let original: StateSnapshot = serde_json::from_value(snap_val)
            .map_err(|e| PyValueError::new_err(format!("invalid snapshot dict: {e}")))?;
        let cur: Value = util::json_str_to_value(current)?;
        let guard = WitnessGuard::new();
        let out = guard
            .verify_json_before_execution(&original, &cur)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let j = revalidation_to_value(&out)?;
        util::json_value_to_py(py, &j)
    }

    fn __repr__(&self) -> String {
        "WitnessGuard()".into()
    }
}

fn register_witness_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "agentfirewall.witness")?;
    m.add_class::<PyWitnessGuard>()?;
    parent.add_submodule(&m)?;
    let sys_mod = py.import("sys")?;
    sys_mod
        .getattr("modules")?
        .set_item("agentfirewall.witness", &m)?;
    Ok(())
}

// --- learner -----------------------------------------------------------------

fn learner_err_to_py(e: LearnerError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn learner_config_from_py(obj: &Bound<'_, PyAny>) -> PyResult<LearnerClientConfig> {
    let d = obj
        .downcast::<PyDict>()
        .map_err(|_| PyTypeError::new_err("config must be a dict"))?;
    let mut c = LearnerClientConfig::default();

    if let Ok(Some(v)) = d.get_item("nats_url") {
        if !v.is_none() {
            c.nats_url = v.extract::<String>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("subject_prefix") {
        if !v.is_none() {
            c.subject_prefix = v.extract::<String>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("tenant_id") {
        if !v.is_none() {
            c.tenant_id = v.extract::<String>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("sample_rate") {
        if !v.is_none() {
            c.sample_rate = v.extract::<f32>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("publish_queue_capacity") {
        if !v.is_none() {
            c.publish_queue_capacity = v.extract::<usize>()?;
        }
    }
    if let Ok(Some(v)) = d.get_item("max_span_bytes") {
        if !v.is_none() {
            c.max_span_bytes = v.extract::<usize>()?;
        }
    }

    c.validate()
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(c)
}

fn learner_mode_to_str(m: LearnerMode) -> String {
    serde_json::to_value(m)
        .ok()
        .and_then(|v| v.as_str().map(std::string::ToString::to_string))
        .unwrap_or_else(|| format!("{m:?}"))
}

fn parse_learner_mode_str(s: &str) -> PyResult<LearnerMode> {
    match s.trim() {
        "observe_only" => Ok(LearnerMode::ObserveOnly),
        "recommend" => Ok(LearnerMode::Recommend),
        "auto_promote_safe" => Ok(LearnerMode::AutoPromoteSafe),
        _ => Err(PyValueError::new_err(format!("unknown learner mode: {s}"))),
    }
}

#[pyclass(name = "LearnerClient", module = "agentfirewall.learner")]
#[derive(Clone)]
struct PyLearnerClient {
    inner: LearnerClient,
}

#[pymethods]
impl PyLearnerClient {
    #[new]
    fn new(config: &Bound<'_, PyAny>) -> PyResult<Self> {
        let cfg = learner_config_from_py(config)?;
        let inner = LearnerClient::new(cfg).map_err(learner_err_to_py)?;
        Ok(Self { inner })
    }

    fn connect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let c = self.inner.clone();
        future_into_py(
            py,
            async move { c.connect().await.map_err(learner_err_to_py) },
        )
    }

    fn emit_span(&self, py: Python<'_>, span: &Bound<'_, PyAny>) -> PyResult<()> {
        let v = util::py_to_json_value(py, span)?;
        let ev: SpanEvent = serde_json::from_value(v)
            .map_err(|e| PyValueError::new_err(format!("invalid span dict: {e}")))?;
        self.inner.emit_span(ev).map_err(learner_err_to_py)
    }

    fn mode(&self) -> String {
        learner_mode_to_str(self.inner.mode())
    }

    fn set_mode(&self, mode: &str) -> PyResult<String> {
        let m = parse_learner_mode_str(mode)?;
        let prev = self.inner.set_mode(m).map_err(learner_err_to_py)?;
        Ok(learner_mode_to_str(prev))
    }

    fn __repr__(&self) -> String {
        format!(
            "LearnerClient(mode={})",
            learner_mode_to_str(self.inner.mode())
        )
    }
}

fn register_learner_module(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "agentfirewall.learner")?;
    m.add_class::<PyLearnerClient>()?;
    parent.add_submodule(&m)?;
    let sys_mod = py.import("sys")?;
    sys_mod
        .getattr("modules")?
        .set_item("agentfirewall.learner", &m)?;
    Ok(())
}

// --- helpers -----------------------------------------------------------------

fn parse_action_type(s: &str) -> PyResult<ActionType> {
    match s.trim().to_ascii_lowercase().as_str() {
        "tool_call" => Ok(ActionType::ToolCall),
        "model_call" => Ok(ActionType::ModelCall),
        "write" => Ok(ActionType::Write),
        "delegation" => Ok(ActionType::Delegation),
        x if x.starts_with("custom:") => Ok(ActionType::Custom(
            x.trim_start_matches("custom:").trim().to_string(),
        )),
        _ => Err(PyValueError::new_err(format!(
            "unknown action_type '{s}' (expected tool_call, model_call, write, delegation, or custom:...)"
        ))),
    }
}

fn decimal_from_json_value(v: Option<Value>) -> PyResult<Option<Decimal>> {
    let Some(v) = v else {
        return Ok(None);
    };
    match v {
        Value::String(s) => Decimal::from_str_exact(&s)
            .or_else(|_| Decimal::from_str(&s))
            .map(Some)
            .map_err(|e| PyValueError::new_err(format!("invalid decimal: {e}"))),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Some(Decimal::from(i)))
            } else if let Some(f) = n.as_f64() {
                Decimal::try_from(f)
                    .map(Some)
                    .map_err(|_| PyValueError::new_err("cost is not a valid decimal"))
            } else {
                Err(PyValueError::new_err("cost number not supported"))
            }
        }
        _ => Err(PyValueError::new_err(
            "cost_estimate_usd must be string or number",
        )),
    }
}

// --- pymodule ----------------------------------------------------------------

#[pymodule]
fn agentfirewall(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.setattr("__doc__", "Agent FirewallKit Python SDK (native extension).")?;
    register_core_module(py, m)?;
    register_sentinel_module(py, m)?;
    register_witness_module(py, m)?;
    register_learner_module(py, m)?;
    Ok(())
}
