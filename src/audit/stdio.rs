//! Launching a local MCP server and talking to it over its standard streams.
//!
//! This is the one place in mcpwn that executes something, and it is reachable
//! only through `mcpwn audit`, under an engagement that names the command.
//! Scanning still never spawns a process:
//! `tests/enumerate.rs::stdio_server_is_never_executed` is unchanged and still
//! passes.
//!
//! # What running the thing you are auditing costs
//!
//! It cannot be made safe. What it can be is narrow, and honest about what is
//! left:
//!
//! * **No shell.** The command and arguments go to `exec` directly, so nothing
//!   in the engagement file is expanded, globbed or chained.
//! * **A minimal environment.** A short allowlist of what a process needs to
//!   start, plus whatever the engagement declares. The rest of the parent
//!   environment, which is where your credentials live, is not inherited.
//! * **A deadline**, and a kill on every exit path including a panic.
//! * **Bounded output**, so neither stream can make the run allocate freely.
//!
//! Not solved: the process runs with your privileges for as long as it lives,
//! and killing it does not kill what it spawned. The answer to that is an OS
//! sandbox, which is a separate piece of work.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

/// Variables a server needs simply to start. Everything else is dropped.
const KEEP_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TERM",
    "SystemRoot",
    "SystemDrive",
    "COMSPEC",
    "PATHEXT",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "TEMP",
    "TMP",
];

const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// A running child process and the channels to talk to it.
///
/// Dropping it kills the child. No path out of this module, panic included,
/// leaves a process behind.
pub struct StdioSession {
    child: Child,
    stdout: Receiver<String>,
    stderr: Receiver<String>,
    timeout: Duration,
    next_id: i64,
    diagnostics: Vec<String>,
}

impl StdioSession {
    pub fn spawn(
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let mut builder = Command::new(command);
        builder
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        builder.env_clear();
        for name in KEEP_ENV {
            if let Some(value) = std::env::var_os(name) {
                builder.env(name, value);
            }
        }
        for (name, value) in env {
            builder.env(name, value);
        }

        let mut child = builder
            .spawn()
            .map_err(|err| format!("could not launch `{command}`: {err}"))?;

        let stdout = pipe_lines(child.stdout.take().expect("stdout is piped"));
        let stderr = pipe_lines(child.stderr.take().expect("stderr is piped"));

        Ok(Self {
            child,
            stdout,
            stderr,
            timeout,
            next_id: 1,
            diagnostics: Vec::new(),
        })
    }

    /// Send a JSON-RPC request and wait for its response.
    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;

        let message = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params
        });
        self.notify(&message)?;

        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| self.describe_failure("timed out"))?;

            match self.stdout.recv_timeout(remaining) {
                Ok(line) => {
                    // Servers do log to stdout, in violation of the transport.
                    // Skip what is not the answer rather than failing.
                    if let Ok(value) = serde_json::from_str::<Value>(line.trim()) {
                        if value.get("id").and_then(Value::as_i64) == Some(id)
                            && (value.get("result").is_some() || value.get("error").is_some())
                        {
                            return Ok(value);
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => return Err(self.describe_failure("timed out")),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(self.describe_failure("the server closed its output"))
                }
            }
        }
    }

    /// Write one line exactly as given, valid JSON or not.
    pub fn write_line(&mut self, line: &str) -> Result<(), String> {
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| "the server's stdin is closed".to_owned())?;
        writeln!(stdin, "{line}").map_err(|err| format!("could not write to the server: {err}"))?;
        stdin
            .flush()
            .map_err(|err| format!("could not write to the server: {err}"))
    }

    /// Read whatever comes back next, without requiring it to match an id.
    ///
    /// Silence is an answer here: a server that says nothing to a malformed
    /// message is behaving, and one that dies is the finding.
    ///
    /// `patience` is deliberately shorter than the request timeout. A server
    /// answers a malformed message immediately or not at all, and waiting the
    /// full deadline on every silent case turns a ten-case probe into a minute
    /// of nothing.
    pub fn read_any(&mut self, patience: Duration) -> Result<String, String> {
        match self.stdout.recv_timeout(patience.min(self.timeout)) {
            Ok(line) => Ok(line),
            Err(RecvTimeoutError::Timeout) => Ok(String::new()),
            Err(RecvTimeoutError::Disconnected) => {
                Err(self.describe_failure("the server closed its output"))
            }
        }
    }

    /// Send a message that expects no reply.
    pub fn notify(&mut self, message: &Value) -> Result<(), String> {
        let payload = serde_json::to_string(message)
            .map_err(|err| format!("could not encode the request: {err}"))?;
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| "the server's stdin is closed".to_owned())?;
        // Newline-delimited JSON-RPC: the whole stdio framing.
        writeln!(stdin, "{payload}")
            .map_err(|err| format!("could not write to the server: {err}"))?;
        stdin
            .flush()
            .map_err(|err| format!("could not write to the server: {err}"))
    }

    pub fn is_finished(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Build a failure message, quoting what the server said on stderr.
    fn describe_failure(&mut self, reason: &str) -> String {
        while let Ok(line) = self.stderr.try_recv() {
            if self.diagnostics.len() < 5 {
                self.diagnostics.push(line.trim_end().to_owned());
            }
        }
        let exited = match self.child.try_wait() {
            Ok(Some(status)) => format!(" (the process exited with {status})"),
            _ => String::new(),
        };
        if self.diagnostics.is_empty() {
            format!("{reason}{exited}")
        } else {
            format!("{reason}{exited}: {}", self.diagnostics.join(" | "))
        }
    }
}

impl Drop for StdioSession {
    fn drop(&mut self) {
        // A server that ignores a closed stdin still has to go, and a zombie is
        // worse than a kill.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read a pipe line by line on its own thread, bounded.
///
/// A thread rather than a blocking read, because a deadline is the only thing
/// between a run and a server that never answers. Draining stderr also stops a
/// chatty child from blocking on a full pipe.
fn pipe_lines(pipe: impl Read + Send + 'static) -> Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut total = 0usize;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n;
                    if total > MAX_OUTPUT_BYTES || sender.send(std::mem::take(&mut line)).is_err() {
                        break;
                    }
                }
            }
        }
    });
    receiver
}
