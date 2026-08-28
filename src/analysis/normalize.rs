//! Unicode normalisation of the free-form text an MCP server sends us.
//!
//! # Two jobs, one module
//!
//! This is both a **utility** and the input to a **check**, and the split
//! matters:
//!
//! 1. [`normalize`] turns raw text into [`Normalized`]: a `cleaned` string for
//!    other analysers to work on, plus a report of what was found.
//! 2. [`super::obfuscation`] consumes that report and turns it into findings.
//!
//! **Every future semantic analyser must read `cleaned`, never the raw text.**
//! Poisoning and shadowing detection match on words; a single zero-width space
//! dropped inside a keyword defeats any matcher run on the raw string, and
//! costs an attacker nothing. Normalising first closes that door once for every
//! check instead of once per check.
//!
//! # What is removed, and what is only reported
//!
//! Invisible characters, bidi controls, tag characters and stray control
//! characters are **removed** from `cleaned`: they carry no legitimate meaning
//! in a tool description, so dropping them is lossless for analysis.
//!
//! Homoglyphs are **reported but not rewritten**. The UTS #39 skeleton
//! transform is deliberately lossy: `skeleton("l") == skeleton("1")`, and
//! whole scripts collapse onto Latin, so applying it to `cleaned` would
//! corrupt legitimate non-Latin text and invent matches downstream. Analysers
//! that want confusable-insensitive comparison call [`skeleton`] explicitly on
//! the specific token they care about.
//!
//! After stripping, `cleaned` is put through NFKC so that compatibility forms
//! (fullwidth, ligatures, circled letters) compare equal to their plain
//! equivalents downstream.
//!
//! Character properties come from `unicode-security`, which implements
//! [UTS #39], because the confusables table and mixed-script detection are large,
//! versioned Unicode data files, and hand-rolling them would mean shipping a
//! stale, partial copy.
//!
//! [UTS #39]: https://www.unicode.org/reports/tr39/

use std::fmt::Write as _;

use unicode_normalization::UnicodeNormalization;
use unicode_script::Script;
use unicode_security::mixed_script::AugmentedScriptSet;
use unicode_security::GeneralSecurityProfile;

/// The result of normalising a piece of text.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Normalized {
    /// Analysis-ready text: invisibles stripped, then NFKC. **This** is what
    /// other checks match on.
    pub cleaned: String,
    /// What was found on the way. Empty means the text was ordinary.
    pub notes: Vec<NormalizationNote>,
}

impl Normalized {
    /// True when nothing suspicious was found.
    pub fn is_clean(&self) -> bool {
        self.notes.is_empty()
    }

    /// Every note of one kind.
    pub fn notes_of(&self, kind: NoteKind) -> impl Iterator<Item = &NormalizationNote> {
        self.notes.iter().filter(move |n| n.kind == kind)
    }

    /// The distinct kinds found, in the order [`NoteKind::ALL`] declares them
    /// (most severe first), so a caller reports them in a stable order.
    pub fn kinds(&self) -> Vec<NoteKind> {
        NoteKind::ALL
            .iter()
            .copied()
            .filter(|kind| self.notes.iter().any(|n| n.kind == *kind))
            .collect()
    }
}

/// One suspicious element found in the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationNote {
    pub kind: NoteKind,
    /// Byte offset in the **original** string, so findings can quote the source.
    pub offset: usize,
    /// The offending characters, escaped for display (`U+200B` style).
    pub raw: String,
    /// The codepoints involved.
    pub codepoints: Vec<u32>,
    /// Extra context: the decoded hidden text for tag characters, the scripts
    /// involved for a mixed-script word.
    pub detail: Option<String>,
}

impl NormalizationNote {
    /// `U+200B U+200C`: the codepoints, for a finding message.
    pub fn codepoints_display(&self) -> String {
        self.codepoints
            .iter()
            .map(|cp| format!("U+{cp:04X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What kind of suspicious element a note records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NoteKind {
    /// Unicode tag characters, U+E0000-U+E007F. ASCII text encoded as
    /// invisible codepoints: readable by a model, invisible to a human.
    TagCharacter,
    /// Zero-width space / joiner / non-joiner, word joiner, BOM, soft hyphen.
    InvisibleCharacter,
    /// Bidirectional override or embedding: the Trojan Source family.
    BidiControl,
    /// A single word mixing scripts, e.g. Latin with one Cyrillic letter.
    MixedScript,
    /// A C0/C1 control character outside ordinary whitespace.
    ControlCharacter,
    /// A run of base64 or hex that decodes to readable text.
    EncodedPayload,
}

impl NoteKind {
    /// Declared most severe first.
    pub const ALL: [NoteKind; 6] = [
        NoteKind::TagCharacter,
        NoteKind::InvisibleCharacter,
        NoteKind::BidiControl,
        NoteKind::EncodedPayload,
        NoteKind::MixedScript,
        NoteKind::ControlCharacter,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            NoteKind::TagCharacter => "tag-characters",
            NoteKind::InvisibleCharacter => "invisible-characters",
            NoteKind::BidiControl => "bidi-control",
            NoteKind::MixedScript => "mixed-script",
            NoteKind::ControlCharacter => "control-characters",
            NoteKind::EncodedPayload => "encoded-payload",
        }
    }
}

impl std::fmt::Display for NoteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.slug())
    }
}

// ---------------------------------------------------------------------------
// Character classification
// ---------------------------------------------------------------------------

/// Unicode tag characters: the U+E0000 block.
///
/// U+E0020-U+E007E mirror printable ASCII one-for-one, so an entire sentence
/// can be smuggled through them. There is no legitimate use in a tool
/// description; the block's only sanctioned role is language tags in emoji
/// sequences, which never appear in prose.
fn is_tag_char(c: char) -> bool {
    matches!(c, '\u{E0000}'..='\u{E007F}')
}

/// Invisible or zero-width characters that can hide inside a word.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'      // zero-width space
        | '\u{200C}'    // zero-width non-joiner
        | '\u{200D}'    // zero-width joiner
        | '\u{2060}'    // word joiner
        | '\u{2061}'
            ..='\u{2064}' // invisible operators
        | '\u{FEFF}'    // zero-width no-break space / BOM
        | '\u{00AD}'    // soft hyphen
        | '\u{180E}'    // Mongolian vowel separator
        | '\u{115F}'    // Hangul choseong filler
        | '\u{1160}'    // Hangul jungseong filler
        | '\u{3164}'    // Hangul filler
        | '\u{FFA0}'    // halfwidth Hangul filler
        | '\u{2800}' // braille blank
    )
}

/// Bidirectional controls, including the overrides used by Trojan Source.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}'   // LRE RLE PDF LRO RLO
        | '\u{2066}'..='\u{2069}' // LRI RLI FSI PDI
        | '\u{061C}'              // Arabic letter mark
        | '\u{200E}' | '\u{200F}' // LRM RLM
    )
}

/// A control character that has no business in a description.
///
/// Tab, newline and carriage return are ordinary formatting and are kept.
fn is_unexpected_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{8}' | '\u{B}' | '\u{C}' | '\u{E}'..='\u{1F}' | '\u{7F}'..='\u{9F}')
}

/// Decode a run of tag characters back to the ASCII it encodes.
///
/// U+E0020..U+E007E map to ASCII 0x20..0x7E. This is the payload an attacker
/// hid, and quoting it in the finding is the single most useful thing the
/// scanner can say about it.
fn decode_tag_run(chars: &[char]) -> Option<String> {
    let decoded: String = chars
        .iter()
        .filter_map(|&c| {
            let cp = c as u32;
            (0xE0020..=0xE007E)
                .contains(&cp)
                .then(|| char::from_u32(cp - 0xE0000))
                .flatten()
        })
        .collect();
    (!decoded.trim().is_empty()).then_some(decoded)
}

/// Escape a run of characters for display.
fn escape(chars: &[char]) -> String {
    let mut out = String::new();
    for &c in chars {
        let _ = write!(out, "U+{:04X} ", c as u32);
    }
    out.trim_end().to_owned()
}

// ---------------------------------------------------------------------------
// The normaliser
// ---------------------------------------------------------------------------

/// Normalise text for analysis, reporting what was suspicious about it.
///
/// Never fails and never panics: the input is attacker-controlled.
pub fn normalize(text: &str) -> Normalized {
    let mut stripped = String::with_capacity(text.len());
    let mut notes = Vec::new();

    // Adjacent characters of the same kind are collected into one note: a
    // smuggled sentence is one problem, not ninety.
    let mut run: Vec<char> = Vec::new();
    let mut run_kind: Option<NoteKind> = None;
    let mut run_offset = 0usize;

    let mut flush = |run: &mut Vec<char>, kind: &mut Option<NoteKind>, offset: usize| {
        if let (Some(k), false) = (*kind, run.is_empty()) {
            notes.push(NormalizationNote {
                kind: k,
                offset,
                raw: escape(run),
                codepoints: run.iter().map(|&c| c as u32).collect(),
                detail: (k == NoteKind::TagCharacter)
                    .then(|| decode_tag_run(run))
                    .flatten()
                    .map(|decoded| format!("decodes to: {decoded:?}")),
            });
        }
        run.clear();
        *kind = None;
    };

    for (offset, c) in text.char_indices() {
        let kind = if is_tag_char(c) {
            Some(NoteKind::TagCharacter)
        } else if is_invisible(c) {
            Some(NoteKind::InvisibleCharacter)
        } else if is_bidi_control(c) {
            Some(NoteKind::BidiControl)
        } else if is_unexpected_control(c) {
            Some(NoteKind::ControlCharacter)
        } else {
            None
        };

        match kind {
            Some(kind) => {
                if run_kind != Some(kind) {
                    flush(&mut run, &mut run_kind, run_offset);
                    run_kind = Some(kind);
                    run_offset = offset;
                }
                run.push(c);
                // Dropped from `cleaned`: it carries no meaning for analysis.
            }
            None => {
                flush(&mut run, &mut run_kind, run_offset);
                stripped.push(c);
            }
        }
    }
    flush(&mut run, &mut run_kind, run_offset);

    // Mixed-script detection runs on the *stripped* text: an invisible
    // character between two letters must not split a word and hide the mix.
    notes.extend(mixed_script_notes(&stripped));
    notes.extend(encoded_payload_notes(&stripped));

    Normalized {
        cleaned: stripped.nfkc().collect(),
        notes,
    }
}

/// Words that mix scripts, e.g. Latin with a lone Cyrillic `а`.
///
/// The signal is the **mix inside one word**, not the presence of non-Latin
/// text. A description written entirely in Russian, or one containing emoji, is
/// perfectly ordinary and must not be flagged, so each word is tested on its
/// own with the UTS #39 resolved script set, which is empty exactly when the
/// word is not single-script.
fn mixed_script_notes(text: &str) -> Vec<NormalizationNote> {
    let mut notes = Vec::new();

    for (offset, word) in words(text) {
        // Only letters carry a script; punctuation, digits and emoji are
        // script-neutral and would otherwise be noise.
        let letters: String = word.chars().filter(|c| c.is_alphabetic()).collect();
        if letters.chars().count() < 2 {
            continue;
        }

        let set = AugmentedScriptSet::for_str(&letters);
        if !set.is_empty() {
            continue; // single-script: ordinary, whatever the script is.
        }

        // Mixed. Report the *intruders* (the letters in the minority script),
        // not the whole word: in `updаte_config` the finding is the single
        // Cyrillic `а`, and naming all ten letters buries it.
        let Some((dominant, intruders)) = minority_letters(&letters) else {
            continue;
        };

        // Report only when an intruder is a known cross-script confusable. That
        // is the difference between an attack and a legitimately multilingual
        // token.
        let confusables: Vec<char> = intruders
            .into_iter()
            .filter(|c| {
                c.identifier_allowed()
                    && unicode_security::is_potential_mixed_script_confusable_char(*c)
            })
            .collect();
        if confusables.is_empty() {
            continue;
        }

        let intruder_scripts: Vec<String> = confusables
            .iter()
            .map(|&c| format!("{:?}", Script::from(c)))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        notes.push(NormalizationNote {
            kind: NoteKind::MixedScript,
            offset,
            raw: word.to_owned(),
            codepoints: confusables.iter().map(|&c| c as u32).collect(),
            detail: Some(format!(
                "the word {word:?} is mostly {dominant:?} but contains {} ({}): {}",
                intruder_scripts.join(" + "),
                confusables.iter().collect::<String>(),
                escape(&confusables)
            )),
        });
    }

    notes
}

/// The dominant script of a word and the letters that do not belong to it.
///
/// `Common` and `Inherited` carry no script of their own (digits, combining
/// marks) and are ignored on both sides.
fn minority_letters(letters: &str) -> Option<(Script, Vec<char>)> {
    // `Script` is Eq + Hash but not Ord, and the list is a handful of entries,
    // so a Vec is both simpler and faster than a map here.
    let mut counts: Vec<(Script, usize)> = Vec::new();
    for c in letters.chars() {
        let script = Script::from(c);
        if matches!(script, Script::Common | Script::Inherited | Script::Unknown) {
            continue;
        }
        match counts.iter_mut().find(|(s, _)| *s == script) {
            Some((_, n)) => *n += 1,
            None => counts.push((script, 1)),
        }
    }
    if counts.len() < 2 {
        return None;
    }

    // Ties resolve to the first script seen, which keeps the output stable.
    let dominant = counts.iter().max_by_key(|(_, n)| *n)?.0;
    let intruders: Vec<char> = letters
        .chars()
        .filter(|&c| {
            let script = Script::from(c);
            !matches!(script, Script::Common | Script::Inherited | Script::Unknown)
                && script != dominant
        })
        .collect();
    Some((dominant, intruders))
}

/// Split on whitespace and ASCII punctuation, keeping byte offsets.
fn words(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;

    for (offset, c) in text.char_indices() {
        let is_separator = c.is_whitespace() || (c.is_ascii_punctuation() && c != '_');
        match (is_separator, start) {
            (true, Some(begin)) => {
                out.push((begin, &text[begin..offset]));
                start = None;
            }
            (false, None) => start = Some(offset),
            _ => {}
        }
    }
    if let Some(begin) = start {
        out.push((begin, &text[begin..]));
    }
    out
}

/// Runs of base64 or hex that decode to readable text.
///
/// A description reading `Reads a file. SWdub3JlIHByZXZpb3Vz...` looks like
/// noise to a reviewer, and plenty of models will decode it. This is hiding in
/// plain sight rather than hiding in invisible codepoints, and it is the
/// obvious next move once tag characters are caught.
///
/// The bar is deliberately high: a long enough run, valid decoding, and a
/// decoded result that is *mostly printable ASCII words*. Hashes, ids and
/// base64 image data decode to bytes that fail that last test, which is what
/// keeps this from firing on every checksum in a description.
fn encoded_payload_notes(text: &str) -> Vec<NormalizationNote> {
    const MIN_RUN: usize = 24;
    let mut notes = Vec::new();

    for (offset, token) in words(text) {
        if token.len() < MIN_RUN {
            continue;
        }
        let Some((label, decoded)) = decode_candidate(token) else {
            continue;
        };
        if !looks_like_prose(&decoded) {
            continue;
        }
        notes.push(NormalizationNote {
            kind: NoteKind::EncodedPayload,
            offset,
            raw: token.chars().take(48).collect(),
            codepoints: Vec::new(),
            detail: Some(format!(
                "{label} decoding to: {:?}",
                decoded.chars().take(200).collect::<String>()
            )),
        });
    }
    notes
}

fn decode_candidate(token: &str) -> Option<(&'static str, String)> {
    if token.len() % 2 == 0 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Vec<u8> = (0..token.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&token[i..i + 2], 16).ok())
            .collect();
        return String::from_utf8(bytes).ok().map(|s| ("hex", s));
    }
    base64_decode(token)
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| ("base64", s))
}

/// Minimal base64 decoder: a dependency would be absurd for this.
fn base64_decode(token: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let trimmed = token.trim_end_matches('=');
    if trimmed.len() < 16 {
        return None;
    }

    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    for byte in trimmed.bytes() {
        let value = ALPHABET.iter().position(|&c| c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Whether decoded bytes read as language rather than as data.
fn looks_like_prose(decoded: &str) -> bool {
    if decoded.chars().count() < 12 {
        return false;
    }
    let printable = decoded
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .count();
    // Almost entirely printable...
    if (printable as f64) < decoded.chars().count() as f64 * 0.95 {
        return false;
    }
    // ...and made of words, not one unbroken blob.
    let words = decoded.split_whitespace().count();
    words >= 3 && decoded.chars().filter(|c| c.is_alphabetic()).count() > decoded.len() / 2
}

/// The UTS #39 confusable skeleton of a string.
///
/// Exposed for analysers that want confusable-insensitive comparison of one
/// specific token. **Not** applied to [`Normalized::cleaned`]: the transform is
/// lossy by design (`skeleton("l") == skeleton("1")`), so using it as general
/// text would invent matches.
pub fn skeleton(text: &str) -> String {
    unicode_security::confusable_detection::skeleton(text).collect()
}
