//! FastEmbed-backed embedding inference for Sentinel and related components.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
use parking_lot::RwLock;
use thiserror::Error;

/// Default HuggingFace-style id for [`EmbeddingModel::BGESmallENV15`] (fast, strong quality).
pub const DEFAULT_EMBEDDING_MODEL_ID: &str = "BAAI/bge-small-en-v1.5";

/// Errors from model lifecycle and embedding inference.
#[derive(Debug, Error)]
pub enum EmbedError {
    #[error("model load failed: {0}")]
    ModelLoad(String),
    #[error("embedding inference failed: {0}")]
    Inference(String),
    #[error("input size {size} exceeds maximum {max} bytes")]
    InputTooLarge { size: usize, max: usize },
    #[error("embedding model is not loaded or not ready")]
    ModelNotReady,
}

/// Semantic embedding engine (FastEmbed / ONNX Runtime).
///
/// The underlying [`TextEmbedding`] is shared behind a read-write lock so many callers can run
/// concurrent `embed` calls while keeping the public surface `Send + Sync`.
pub struct EmbedEngine {
    model: RwLock<Option<TextEmbedding>>,
    model_id: String,
    max_input_bytes: usize,
    embedding_dim: usize,
    ready: AtomicBool,
}

impl std::fmt::Debug for EmbedEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbedEngine")
            .field("model_id", &self.model_id)
            .field("max_input_bytes", &self.max_input_bytes)
            .field("embedding_dim", &self.embedding_dim)
            .field(
                "ready",
                &self.ready.load(std::sync::atomic::Ordering::Relaxed),
            )
            .finish()
    }
}

impl EmbedEngine {
    /// Builds a new engine and loads the ONNX model for `model_id`.
    ///
    /// An empty or whitespace-only `model_id` selects [`DEFAULT_EMBEDDING_MODEL_ID`].
    /// Recognized ids include each model's `model_code` from [`TextEmbedding::list_supported_models`]
    /// and the [`EmbeddingModel`] `Display` string (for example `BGESmallENV15`).
    pub fn new(model_id: &str, max_input_bytes: usize) -> Result<Self, EmbedError> {
        let canonical_id = canonical_model_id(model_id);
        let embedding_model = resolve_embedding_model(&canonical_id)?;
        let dim = TextEmbedding::get_model_info(&embedding_model)
            .map_err(|e| EmbedError::ModelLoad(e.to_string()))?
            .dim;

        let options = InitOptions::new(embedding_model).with_show_download_progress(false);
        let text_model =
            TextEmbedding::try_new(options).map_err(|e| EmbedError::ModelLoad(e.to_string()))?;

        Ok(Self {
            model: RwLock::new(Some(text_model)),
            model_id: canonical_id,
            max_input_bytes,
            embedding_dim: dim,
            ready: AtomicBool::new(true),
        })
    }

    fn ensure_input_len(&self, byte_len: usize) -> Result<(), EmbedError> {
        if byte_len > self.max_input_bytes {
            return Err(EmbedError::InputTooLarge {
                size: byte_len,
                max: self.max_input_bytes,
            });
        }
        Ok(())
    }

    /// Embeds a single piece of text.
    pub fn embed_text(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
        self.ensure_input_len(text.len())?;
        if !self.is_ready() {
            return Err(EmbedError::ModelNotReady);
        }
        let start = Instant::now();
        let guard = self.model.read();
        let Some(m) = guard.as_ref() else {
            return Err(EmbedError::ModelNotReady);
        };
        let out = m
            .embed(vec![text], None)
            .map_err(|e| EmbedError::Inference(e.to_string()))?;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
        tracing::debug!(
            target: "agentfirewall_embed",
            elapsed_ms,
            input_bytes = text.len(),
            batch = 1,
            "embed_text"
        );
        out.into_iter()
            .next()
            .ok_or_else(|| EmbedError::Inference("empty embedding output".into()))
    }

    /// Batch embedding; order matches `texts`.
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        for t in texts {
            self.ensure_input_len(t.len())?;
        }
        if !self.is_ready() {
            return Err(EmbedError::ModelNotReady);
        }
        let start = Instant::now();
        let guard = self.model.read();
        let Some(m) = guard.as_ref() else {
            return Err(EmbedError::ModelNotReady);
        };
        let out = m
            .embed(texts.to_vec(), None)
            .map_err(|e| EmbedError::Inference(e.to_string()))?;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
        tracing::debug!(
            target: "agentfirewall_embed",
            elapsed_ms,
            batch = texts.len(),
            total_input_bytes = texts.iter().map(|s| s.len()).sum::<usize>(),
            "embed_batch"
        );
        Ok(out)
    }

    /// `true` when the model finished loading and is usable.
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Canonical model identifier (HuggingFace-style when applicable).
    #[inline]
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Output dimension for this model (from FastEmbed metadata).
    #[inline]
    pub fn embedding_dimension(&self) -> usize {
        self.embedding_dim
    }

    /// Wrap this engine in an [`Arc`] for cheap cloning across tasks.
    #[inline]
    pub fn into_handle(self) -> EmbedEngineHandle {
        EmbedEngineHandle(Arc::new(self))
    }

    #[cfg(test)]
    pub(crate) fn new_without_model_for_tests(max_input_bytes: usize) -> Self {
        Self {
            model: RwLock::new(None),
            model_id: "test".into(),
            max_input_bytes,
            embedding_dim: 384,
            ready: AtomicBool::new(false),
        }
    }
}

/// Shared handle to an [`EmbedEngine`].
#[derive(Clone, Debug)]
pub struct EmbedEngineHandle(Arc<EmbedEngine>);

impl EmbedEngineHandle {
    pub fn new(engine: EmbedEngine) -> Self {
        Self(Arc::new(engine))
    }

    #[inline]
    pub fn inner(&self) -> &EmbedEngine {
        &self.0
    }
}

impl std::ops::Deref for EmbedEngineHandle {
    type Target = EmbedEngine;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<EmbedEngine> for EmbedEngineHandle {
    fn from(engine: EmbedEngine) -> Self {
        Self::new(engine)
    }
}

fn canonical_model_id(model_id: &str) -> String {
    let t = model_id.trim();
    if t.is_empty() {
        DEFAULT_EMBEDDING_MODEL_ID.to_string()
    } else {
        t.to_string()
    }
}

fn resolve_embedding_model(model_id: &str) -> Result<EmbeddingModel, EmbedError> {
    let key = model_id.trim();
    if key.is_empty() {
        return Ok(EmbeddingModel::BGESmallENV15);
    }
    for info in TextEmbedding::list_supported_models() {
        if info.model_code.eq_ignore_ascii_case(key) || info.model_code == key {
            return Ok(info.model.clone());
        }
        let disp = info.model.to_string();
        if disp.eq_ignore_ascii_case(key) || disp == key {
            return Ok(info.model.clone());
        }
    }
    Err(EmbedError::ModelLoad(format!(
        "unknown embedding model_id {key:?}; expected a HuggingFace model_code or EmbeddingModel label from TextEmbedding::list_supported_models()"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_model_id_fails_without_download() {
        let err = EmbedEngine::new("___not_a_supported_model_id___", 4096).unwrap_err();
        match err {
            EmbedError::ModelLoad(_) => {}
            other => panic!("expected ModelLoad, got {other:?}"),
        }
    }

    #[test]
    fn empty_model_id_selects_default_name() {
        let id = canonical_model_id("  \t  ");
        assert_eq!(id, DEFAULT_EMBEDDING_MODEL_ID);
    }

    #[test]
    fn input_too_large_before_ready_check_order() {
        let eng = EmbedEngine::new_without_model_for_tests(4);
        let long = "hello world";
        let err = eng.embed_text(long).unwrap_err();
        match err {
            EmbedError::InputTooLarge { size, max } => {
                assert!(size > max);
            }
            e => panic!("expected InputTooLarge, got {e:?}"),
        }
    }

    #[test]
    fn model_not_ready_when_unloaded() {
        let eng = EmbedEngine::new_without_model_for_tests(10_000);
        assert!(!eng.is_ready());
        let err = eng.embed_text("ok").unwrap_err();
        assert!(matches!(err, EmbedError::ModelNotReady));
    }

    #[test]
    fn batch_empty_ok_without_model() {
        let eng = EmbedEngine::new_without_model_for_tests(100);
        assert_eq!(eng.embed_batch(&[]).unwrap(), Vec::<Vec<f32>>::new());
    }

    #[test]
    fn handle_deref() {
        let eng = EmbedEngine::new_without_model_for_tests(100);
        let h = EmbedEngineHandle::new(eng);
        assert_eq!(h.embedding_dimension(), 384);
    }

    /// Downloads and loads the default small model; run with `cargo test -p agentfirewall-embed load_default_model -- --ignored`.
    #[test]
    #[ignore = "downloads ONNX weights and runs inference"]
    fn load_default_model_and_embed() {
        let eng = EmbedEngine::new("", 16_384).expect("model load");
        assert!(eng.is_ready());
        let v = eng.embed_text("hello").expect("embed");
        assert_eq!(v.len(), eng.embedding_dimension());
    }
}
