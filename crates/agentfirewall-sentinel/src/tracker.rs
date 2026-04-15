//! Orchestrates goal registration, embedding similarity, and interventions.

use std::collections::HashMap;
use std::sync::Arc;

use agentfirewall_core::ProgressSnapshot;
use agentfirewall_embed::{cosine_similarity, EmbedEngineHandle};
use thiserror::Error;
use uuid::Uuid;

use crate::config::SentinelConfig;
use crate::intervention::{InterventionEngine, InterventionSignal};
use crate::progress::{ProgressComputer, SnapshotParams};

/// Outcome of evaluating one step against the registered goal.
#[derive(Debug, Clone, PartialEq)]
pub struct StepEvaluation {
    pub progress: ProgressSnapshot,
    pub intervention: Option<InterventionSignal>,
}

/// Sentinel failures surfaced to callers.
#[derive(Debug, Error)]
pub enum SentinelError {
    #[error("invalid sentinel config: {0}")]
    ConfigInvalid(String),
    #[error("embedding failed: {0}")]
    EmbedFailure(String),
    #[error("no goal registered for run {0}")]
    GoalNotRegistered(Uuid),
}

impl From<crate::config::ConfigError> for SentinelError {
    fn from(e: crate::config::ConfigError) -> Self {
        SentinelError::ConfigInvalid(e.to_string())
    }
}

pub trait SentinelEmbed: Send + Sync {
    fn embed_for_sentinel(&self, text: &str) -> Result<Vec<f32>, SentinelError>;
    fn model_label(&self) -> &str;
}

struct HandleEmbedder(EmbedEngineHandle);

impl SentinelEmbed for HandleEmbedder {
    fn embed_for_sentinel(&self, text: &str) -> Result<Vec<f32>, SentinelError> {
        self.0
            .embed_text(text)
            .map_err(|e| SentinelError::EmbedFailure(e.to_string()))
    }

    fn model_label(&self) -> &str {
        self.0.model_id()
    }
}

/// Deterministic pseudo-embeddings (no ONNX) for tests and hosts that skip FastEmbed.
#[derive(Debug, Clone)]
pub struct MockSentinelEmbedder {
    dim: usize,
    label: String,
}

impl MockSentinelEmbedder {
    #[must_use]
    pub fn new(dim: usize, label: impl Into<String>) -> Self {
        Self {
            dim,
            label: label.into(),
        }
    }

    fn vec_for(text: &str, dim: usize) -> Vec<f32> {
        let mut v = vec![0.0_f32; dim];
        for (i, b) in text.bytes().enumerate() {
            let j = i % dim;
            v[j] += b as f32 * 0.01 + i as f32 * 1e-4;
        }
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 1e-6 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }
}

impl SentinelEmbed for MockSentinelEmbedder {
    fn embed_for_sentinel(&self, text: &str) -> Result<Vec<f32>, SentinelError> {
        Ok(Self::vec_for(text, self.dim))
    }

    fn model_label(&self) -> &str {
        self.label.as_str()
    }
}

#[derive(Debug, Clone)]
struct RunTrackingState {
    goal_embedding: Vec<f32>,
    previous_similarity: Option<f32>,
    ema_similarity: f32,
    ema_delta: f32,
    consecutive_stalls: u32,
    step_count: u64,
}

impl RunTrackingState {
    fn new(goal_embedding: Vec<f32>) -> Self {
        Self {
            goal_embedding,
            previous_similarity: None,
            ema_similarity: 0.0,
            ema_delta: 0.0,
            consecutive_stalls: 0,
            step_count: 0,
        }
    }
}

/// Goal-aware progress tracker backed by an embedding engine.
pub struct SentinelTracker {
    config: SentinelConfig,
    embed: Arc<dyn SentinelEmbed>,
    runs: HashMap<Uuid, RunTrackingState>,
    intervention: InterventionEngine,
}

impl SentinelTracker {
    /// Builds a tracker after validating config and wiring the shared embed handle.
    pub fn new(config: SentinelConfig, embed: EmbedEngineHandle) -> Result<Self, SentinelError> {
        config.validate()?;
        let intervention = InterventionEngine::new(&config);
        Ok(Self {
            config,
            embed: Arc::new(HandleEmbedder(embed)),
            runs: HashMap::new(),
            intervention,
        })
    }

    /// Wires a custom embed backend (for example [`MockSentinelEmbedder`]).
    pub fn new_with_embedder(
        config: SentinelConfig,
        embed: Arc<dyn SentinelEmbed>,
    ) -> Result<Self, SentinelError> {
        config.validate()?;
        let intervention = InterventionEngine::new(&config);
        Ok(Self {
            config,
            embed,
            runs: HashMap::new(),
            intervention,
        })
    }

    /// Same as [`Self::new_with_embedder`] with [`MockSentinelEmbedder`] at 384 dimensions.
    pub fn new_with_mock_embeddings(config: SentinelConfig) -> Result<Self, SentinelError> {
        Self::new_with_embedder(config, Arc::new(MockSentinelEmbedder::new(384, "mock")))
    }

    /// Embeds and caches the goal vector for `run_id`.
    pub fn register_goal(&mut self, run_id: Uuid, goal_text: &str) -> Result<(), SentinelError> {
        if !self.config.enabled {
            self.runs.insert(run_id, RunTrackingState::new(Vec::new()));
            return Ok(());
        }
        let text = truncate_utf8(goal_text, self.config.max_embed_input_bytes);
        let goal_embedding = self.embed.embed_for_sentinel(text)?;
        self.runs
            .insert(run_id, RunTrackingState::new(goal_embedding));
        Ok(())
    }

    /// Scores `state_summary` against the cached goal, updates EMA / stall state, and evaluates rules.
    pub fn evaluate_step(
        &mut self,
        run_id: Uuid,
        step_index: u64,
        state_summary: &str,
    ) -> Result<StepEvaluation, SentinelError> {
        let Some(state) = self.runs.get_mut(&run_id) else {
            return Err(SentinelError::GoalNotRegistered(run_id));
        };

        if !self.config.enabled {
            let progress = ProgressComputer::build_snapshot(SnapshotParams {
                run_id,
                step: step_index,
                similarity: 1.0,
                delta: 0.0,
                ema_sim: 1.0,
                ema_delta: 0.0,
                stalls: 0,
                model: self.embed.model_label(),
            });
            return Ok(StepEvaluation {
                progress,
                intervention: None,
            });
        }

        if state.goal_embedding.is_empty() {
            return Err(SentinelError::GoalNotRegistered(run_id));
        }

        let text = truncate_utf8(state_summary, self.config.max_embed_input_bytes);
        let state_embedding = self.embed.embed_for_sentinel(text)?;
        let similarity = cosine_similarity(&state_embedding, &state.goal_embedding);

        let delta = match state.previous_similarity {
            Some(prev) => ProgressComputer::compute_delta(similarity, prev),
            None => 0.0,
        };

        let alpha = self.config.ema_alpha;
        let ema_sim = match state.previous_similarity {
            None => similarity,
            Some(_) => ProgressComputer::compute_ema(similarity, state.ema_similarity, alpha),
        };
        let ema_delta = match state.previous_similarity {
            None => 0.0,
            Some(_) => ProgressComputer::compute_ema(delta, state.ema_delta, alpha),
        };

        let stall = state.previous_similarity.is_some()
            && ProgressComputer::is_stall(delta, self.config.stall_threshold);
        if stall {
            state.consecutive_stalls = state.consecutive_stalls.saturating_add(1);
        } else {
            state.consecutive_stalls = 0;
        }

        state.ema_similarity = ema_sim;
        state.ema_delta = ema_delta;
        state.previous_similarity = Some(similarity);
        state.step_count = state.step_count.saturating_add(1);

        let stalls = state.consecutive_stalls;
        let progress = ProgressComputer::build_snapshot(SnapshotParams {
            run_id,
            step: step_index,
            similarity,
            delta,
            ema_sim,
            ema_delta,
            stalls,
            model: self.embed.model_label(),
        });

        let intervention = self.intervention.evaluate(&progress);

        Ok(StepEvaluation {
            progress,
            intervention,
        })
    }

    /// Drops all tracking state for `run_id`.
    pub fn reset(&mut self, run_id: Uuid) {
        self.runs.remove(&run_id);
    }
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfirewall_core::InterventionLevel;

    struct TestEmbedder {
        dim: usize,
        label: &'static str,
    }

    impl TestEmbedder {
        fn vec_for(text: &str, dim: usize) -> Vec<f32> {
            let mut v = vec![0.0_f32; dim];
            for (i, b) in text.bytes().enumerate() {
                let j = i % dim;
                v[j] += b as f32 * 0.01 + i as f32 * 1e-4;
            }
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 1e-6 {
                for x in &mut v {
                    *x /= norm;
                }
            }
            v
        }
    }

    impl SentinelEmbed for TestEmbedder {
        fn embed_for_sentinel(&self, text: &str) -> Result<Vec<f32>, SentinelError> {
            Ok(Self::vec_for(text, self.dim))
        }

        fn model_label(&self) -> &str {
            self.label
        }
    }

    fn test_config() -> SentinelConfig {
        SentinelConfig {
            enabled: true,
            stall_threshold: 0.02,
            stall_window: 3,
            regression_threshold: -0.05,
            ema_alpha: 0.3,
            max_intervention: InterventionLevel::Deny,
            ..SentinelConfig::default()
        }
    }

    #[test]
    fn new_rejects_invalid_config() {
        let c = SentinelConfig {
            stall_window: 0,
            ..SentinelConfig::default()
        };
        let embed = Arc::new(TestEmbedder { dim: 4, label: "x" });
        assert!(matches!(
            SentinelTracker::new_with_embedder(c, embed),
            Err(SentinelError::ConfigInvalid(_))
        ));
    }

    #[test]
    fn goal_not_registered() {
        let c = test_config();
        let embed = Arc::new(TestEmbedder {
            dim: 8,
            label: "test",
        });
        let mut t = SentinelTracker::new_with_embedder(c, embed).unwrap();
        let rid = Uuid::new_v4();
        let err = t.evaluate_step(rid, 0, "hello").expect_err("unregistered");
        assert!(matches!(err, SentinelError::GoalNotRegistered(id) if id == rid));
    }

    #[test]
    fn full_flow_stall_escalation() {
        let c = test_config();
        let embed = Arc::new(TestEmbedder {
            dim: 16,
            label: "test",
        });
        let mut t = SentinelTracker::new_with_embedder(c, embed).unwrap();
        let rid = Uuid::new_v4();
        t.register_goal(rid, "finish the refactor").unwrap();

        // Same summary repeatedly → similarity stable → stalls accumulate
        let summary = "still working on it same as before";
        let w = t.config.stall_window;
        let mut last = None;
        for i in 0u64..(w as u64 * 4 + 2) {
            last = Some(
                t.evaluate_step(rid, i, summary)
                    .unwrap_or_else(|e| panic!("step {i}: {e}")),
            );
        }
        let last = last.unwrap();
        assert_eq!(
            last.intervention.as_ref().unwrap().level,
            InterventionLevel::Deny
        );
        assert_eq!(
            last.intervention.as_ref().unwrap().reason_code.as_str(),
            "PROGRESS_STALL"
        );
    }

    #[test]
    fn reset_clears_run() {
        let c = test_config();
        let embed = Arc::new(TestEmbedder { dim: 8, label: "t" });
        let mut t = SentinelTracker::new_with_embedder(c, embed).unwrap();
        let rid = Uuid::new_v4();
        t.register_goal(rid, "goal").unwrap();
        t.reset(rid);
        assert!(matches!(
            t.evaluate_step(rid, 0, "x").unwrap_err(),
            SentinelError::GoalNotRegistered(_)
        ));
    }

    #[test]
    fn disabled_skips_embed_and_neutral() {
        let c = SentinelConfig {
            enabled: false,
            ..SentinelConfig::default()
        };
        let embed = Arc::new(TestEmbedder { dim: 8, label: "t" });
        let mut t = SentinelTracker::new_with_embedder(c, embed).unwrap();
        let rid = Uuid::new_v4();
        t.register_goal(rid, "any").unwrap();
        let ev = t.evaluate_step(rid, 1, "anything").unwrap();
        assert!((ev.progress.similarity - 1.0).abs() < 1e-6);
        assert!(ev.intervention.is_none());
    }

    #[test]
    fn truncate_utf8_respects_char_boundary() {
        let s = "é".repeat(100);
        let t = truncate_utf8(&s, 1);
        assert!(t.len() <= 1);
    }

    #[test]
    fn tracker_ema_similarity_blends_second_step() {
        let c = test_config();
        let embed = Arc::new(TestEmbedder {
            dim: 32,
            label: "test",
        });
        let mut t = SentinelTracker::new_with_embedder(c, embed).unwrap();
        let rid = Uuid::new_v4();
        t.register_goal(rid, "unique goal alpha").unwrap();

        let e0 = t.evaluate_step(rid, 0, "token_a").unwrap();
        let e1 = t.evaluate_step(rid, 1, "token_b").unwrap();
        let alpha = t.config.ema_alpha;
        let expected = alpha * e1.progress.similarity + (1.0 - alpha) * e0.progress.similarity;
        assert!(
            (e1.progress.ema_similarity - expected).abs() < 1e-4,
            "ema {} vs expected {}",
            e1.progress.ema_similarity,
            expected
        );
    }
}
