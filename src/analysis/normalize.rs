//! Unicode normalisation of the free-form text an MCP server sends us.
//!
//! Attackers hide instructions from human reviewers with zero-width joiners,
//! bidi overrides, homoglyphs and confusables. Everything downstream (`rules`,
//! `roles`) must analyse the *normalised* form while findings quote the
//! *original* one, so this module reports what it stripped instead of silently
//! rewriting.
//!
//! Not implemented yet.

/// The result of normalising a piece of description text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Normalized {
    /// Text after NFKC folding + invisible-character removal.
    pub text: String,
    /// What had to be removed or folded to get there.
    pub notes: Vec<NormalizationNote>,
}

impl Normalized {
    /// True when the original text was already clean.
    pub fn is_clean(&self) -> bool {
        self.notes.is_empty()
    }
}

/// One suspicious transformation applied during normalisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationNote {
    pub kind: NoteKind,
    /// Byte offset in the *original* string.
    pub offset: usize,
    /// The offending characters, escaped for display.
    pub raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NoteKind {
    /// Zero-width space / joiner / non-joiner, soft hyphen, ...
    InvisibleCharacter,
    /// RTL/LTR override or embedding (Trojan Source style).
    BidiControl,
    /// Character folded to a different-looking ASCII one (Cyrillic `а` -> `a`).
    Homoglyph,
    /// Private-use or unassigned code point.
    UnusualCodePoint,
    /// Tag characters (U+E0000 block) used to smuggle ASCII.
    TagCharacter,
}

/// Normalise a description for analysis.
///
/// Currently a pass-through stub: returns the input unchanged with no notes.
pub fn normalize(text: &str) -> Normalized {
    Normalized {
        text: text.to_owned(),
        notes: Vec::new(),
    }
}
