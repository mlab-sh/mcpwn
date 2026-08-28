//! Shared test scaffolding: a throwaway directory and a minimal HTTP server.
//!
//! Deliberately dependency-free — the point of these tests is to prove mcpwn
//! reaches out over the network only when it is safe to, so the harness stays
//! something we can read end to end.

#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

// --- temp dir ---------------------------------------------------------------

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let unique = format!(
            "mcpwn-test-{}-{}-{}",
            tag,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Write `contents` to `rel`, creating parent directories.
    pub fn write(&self, rel: &str, contents: &str) -> PathBuf {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().expect("has parent")).expect("create parents");
        fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// --- mock MCP server --------------------------------------------------------

/// One request as the mock saw it.
pub struct MockRequest {
    /// The raw header block, lower-cased for easy matching.
    pub headers: String,
    pub body: String,
}

impl MockRequest {
    /// Whether the request carried exactly this header: name matched
    /// case-insensitively, value matched exactly.
    pub fn has_header(&self, name: &str, value: &str) -> bool {
        self.headers.lines().any(|line| match line.split_once(':') {
            Some((n, v)) => n.trim().eq_ignore_ascii_case(name) && v.trim() == value,
            None => false,
        })
    }
}

/// Serve `responder(request_body) -> raw HTTP response` on a loopback port.
///
/// Returns the MCP endpoint URL. The listener thread is detached and dies with
/// the test process.
pub fn spawn_mock(responder: impl Fn(String) -> String + Send + Sync + 'static) -> String {
    spawn_mock_req(move |request| responder(request.body))
}

/// Like [`spawn_mock`], but the responder also sees the request headers.
pub fn spawn_mock_req(responder: impl Fn(MockRequest) -> String + Send + Sync + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some(request) = read_http_request(&mut stream) else {
                continue;
            };
            let response = responder(request);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    format!("http://{addr}/mcp")
}

/// A server that accepts the connection and then never answers.
pub fn spawn_blackhole() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(30));
                drop(stream);
            });
        }
    });

    format!("http://{addr}/mcp")
}

/// A URL nothing is listening on.
pub fn dead_url() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    format!("http://{addr}/mcp")
}

fn read_http_request(stream: &mut std::net::TcpStream) -> Option<MockRequest> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];

    // Headers, byte by byte: small requests, and it keeps the framing obvious.
    while !buf.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => buf.push(byte[0]),
            Err(_) => return None,
        }
    }

    // Kept verbatim: header *values* are case-sensitive and tests match on
    // them. Only the name lookup below folds case.
    let headers = String::from_utf8_lossy(&buf).into_owned();
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then_some(value)
        })
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    let mut body = vec![0u8; length];
    if length > 0 && stream.read_exact(&mut body).is_err() {
        return None;
    }
    Some(MockRequest {
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Build a raw HTTP response.
pub fn http_response(status: u16, reason: &str, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub fn json_200(body: &str) -> String {
    http_response(200, "OK", "application/json", body)
}

pub fn json_400(body: &str) -> String {
    http_response(400, "Bad Request", "application/json", body)
}
