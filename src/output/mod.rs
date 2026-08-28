//! Turning a [`crate::report::Report`] into something a human or a tool reads.
//!
//! The engine itself does no I/O; everything that writes bytes lives here.

pub mod inventory;
pub mod render;
pub mod sarif;
