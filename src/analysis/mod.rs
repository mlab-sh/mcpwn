//! The detection modules.
//!
//! Each one takes manifests (plus, later, shared normalised state) and returns
//! [`crate::finding::Finding`]s. They are orchestrated by
//! [`crate::analyzer::Analyzer`] and never talk to the terminal.

pub mod flow;
pub mod normalize;
pub mod roles;
pub mod rules;
pub mod schema;
