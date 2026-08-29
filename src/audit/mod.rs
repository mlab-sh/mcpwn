//! `mcpwn audit`: interacting with a live server, under an engagement.
//!
//! This is the only part of the project that launches a local process, and the
//! only part that calls a tool. Both happen **here and nowhere else**: `scan`,
//! `view` and `discover` are unchanged, and every guarantee they document still
//! holds.
//!
//! Nothing here runs without an engagement file naming one target, and nothing
//! is called that the engagement did not name.

pub mod budget;
pub mod caller;
pub mod probes;
pub mod stdio;

pub use budget::{Budget, Transcript};
pub use caller::{CallOutcome, HttpCaller, StdioCaller, ToolCaller};
