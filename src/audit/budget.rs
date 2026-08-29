//! What bounds a run, and what records it.
//!
//! An audit that can send unlimited requests is an outage waiting to happen,
//! and one that leaves no record is unusable as a deliverable and indefensible
//! afterwards. Both go through here: every call is counted, paced, and written
//! down before it happens.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::engagement::Engagement;

/// A line-delimited record of everything the run sent and received.
///
/// Written as it goes, not at the end: a run that is interrupted still leaves
/// an account of what it had already done to the target.
#[derive(Debug)]
pub struct Transcript {
    writer: BufWriter<File>,
    path: String,
}

impl Transcript {
    /// Open a transcript and write its header, which records the engagement
    /// itself: what was authorised, by whom, and against what.
    pub fn open(path: &Path, engagement: &Engagement) -> crate::Result<Self> {
        let file = File::create(path)?;
        let mut transcript = Self {
            writer: BufWriter::new(file),
            path: path.display().to_string(),
        };
        transcript.write(json!({
            "kind": "engagement",
            "tool": format!("{}-audit {}", crate::NAME, crate::VERSION),
            "target": engagement.target,
            "authorized_by": engagement.authorized_by,
            "reference": engagement.reference,
            "tools_allowed": engagement.tools.allow,
            "limits": engagement.limits,
        }))?;
        Ok(transcript)
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn write(&mut self, entry: Value) -> crate::Result<()> {
        writeln!(self.writer, "{entry}")?;
        // Flushed per line, so an interrupted run still has a complete record
        // up to the point it stopped.
        self.writer.flush()?;
        Ok(())
    }
}

/// The ceiling and the pace.
#[derive(Debug)]
pub struct Budget {
    remaining: usize,
    spent: usize,
    min_interval: Duration,
    last_call: Option<Instant>,
}

impl Budget {
    pub fn new(max_requests: usize, rate_per_second: f64) -> Self {
        Self {
            remaining: max_requests,
            spent: 0,
            min_interval: Duration::from_secs_f64(1.0 / rate_per_second.max(0.001)),
            last_call: None,
        }
    }

    pub fn spent(&self) -> usize {
        self.spent
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Take one request from the budget, waiting if the pace requires it.
    ///
    /// Refusing when exhausted rather than slowing down: a ceiling that bends
    /// is not a ceiling, and the engagement named a number.
    pub fn take(&mut self) -> Result<(), String> {
        if self.remaining == 0 {
            return Err(format!(
                "the engagement's ceiling of {} requests is reached; the run stops here",
                self.spent
            ));
        }
        if let Some(last) = self.last_call {
            let elapsed = last.elapsed();
            if elapsed < self.min_interval {
                std::thread::sleep(self.min_interval - elapsed);
            }
        }
        self.remaining -= 1;
        self.spent += 1;
        self.last_call = Some(Instant::now());
        Ok(())
    }
}
