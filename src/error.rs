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

    /// An endpoint URL given on the command line is not usable.
    #[error("invalid endpoint `{url}`: {message}")]
    Endpoint { url: String, message: String },

    /// A `--header` argument could not be used.
    ///
    /// Deliberately never echoes the header *value*: it is usually a secret.
    #[error("invalid header{}: {message}", .name.as_deref().map(|n| format!(" `{n}`")).unwrap_or_default())]
    Header {
        name: Option<String>,
        message: String,
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
    pub fn endpoint(url: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Endpoint {
            url: url.into(),
            message: message.into(),
        }
    }

    pub fn header(name: Option<String>, message: impl Into<String>) -> Self {
        Self::Header {
            name,
            message: message.into(),
        }
    }

    pub fn manifest(message: impl Into<String>) -> Self {
        Self::Manifest {
            message: message.into(),
            source_hint: None,
        }
    }
}

/// Engine result alias.
pub type Result<T> = std::result::Result<T, Error>;
