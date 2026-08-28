//! Engine errors.
//!
//! `thiserror` here (typed, matchable errors that a library consumer can act
//! on) and `anyhow` in the CLI shell (where errors are only ever contextualised
//! and printed).

/// Everything that can go wrong inside the engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A manifest or config document could not be parsed.
    #[error("invalid manifest{}: {message}", .source_hint.as_deref().map(|s| format!(" ({s})")).unwrap_or_default())]
    Manifest {
        message: String,
        source_hint: Option<String>,
    },

    /// A rule set failed to compile.
    #[error("invalid rule set: {0}")]
    Rules(String),

    /// Underlying JSON error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Reading a target off disk failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn manifest(message: impl Into<String>) -> Self {
        Self::Manifest {
            message: message.into(),
            source_hint: None,
        }
    }
}

/// Engine result alias.
pub type Result<T> = std::result::Result<T, Error>;
