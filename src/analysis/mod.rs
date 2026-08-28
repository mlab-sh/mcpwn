//! The detection modules.
//!
//! Each one takes manifests (plus, later, shared normalised state) and returns
//! [`crate::finding::Finding`]s. They are orchestrated by
//! [`crate::analyzer::Analyzer`] and never talk to the terminal.

pub mod capabilities;
pub mod check;
pub mod flow;
pub mod normalize;
pub mod obfuscation;
pub mod registry;
pub mod roles;
pub mod rugpull;
pub mod rules;
pub mod schema;
