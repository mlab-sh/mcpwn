//! Hand-written HTTP, for the one thing a real client will not do.
//!
//! Lifting C3 means sending a header value containing a carriage return, and
//! no HTTP library will carry that: the `http` crate rejects such a value
//! before the socket, which is correct of it and the reason the attack is worth
//! testing at all.
//!
//! So the request is assembled and written by hand over a `TcpStream`.
//!
//! **Plaintext only.** Doing this over TLS means driving `rustls` directly to
//! get a raw byte stream, which is a different piece of work; an `https://`
//! target is reported as not covered rather than quietly skipped, because a
//! probe that silently does nothing is worse than one that says it did not run.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::audit::caller::RawResponse;

/// Send a POST whose headers are written verbatim, control characters included.
///
/// `raw_headers` are emitted exactly as given, between the standard ones and
/// the body.
pub fn post_raw_headers(
    url: &str,
    raw_headers: &[(String, String)],
    body: &str,
    timeout: Duration,
) -> Result<RawResponse, String> {
    let (host, port, path) = split(url)?;
    let started = Instant::now();

    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|err| format!("could not connect to {host}:{port}: {err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|_| stream.set_write_timeout(Some(timeout)))
        .map_err(|err| format!("could not set a deadline: {err}"))?;

    let mut request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {}/{}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        crate::NAME,
        crate::VERSION,
        body.len()
    );
    for (name, value) in raw_headers {
        // Verbatim on purpose: this is the whole point of the module.
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);

    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|err| format!("could not write the request: {err}"))?;

    let mut buffer = Vec::new();
    // Bounded: a hostile answer must not make the run allocate freely.
    let _ = stream.take(256 * 1024).read_to_end(&mut buffer);
    let text = String::from_utf8_lossy(&buffer).into_owned();

    let (headers, response_body) = match text.split_once("\r\n\r\n") {
        Some((headers, body)) => (headers.to_owned(), body.to_owned()),
        None => (text.clone(), String::new()),
    };
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok());

    Ok(RawResponse {
        status,
        headers,
        body: response_body,
        duration: started.elapsed(),
    })
}

/// Whether a URL can be reached without TLS, which is what this module needs.
pub fn is_plaintext(url: &str) -> bool {
    url.starts_with("http://")
}

/// `http://host:port/path` into its pieces.
fn split(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "only plaintext http is supported here".to_owned())?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse().map_err(|_| format!("bad port in {url}"))?,
        ),
        None => (authority.to_owned(), 80),
    };
    if host.is_empty() {
        return Err(format!("no host in {url}"));
    }
    Ok((host, port, path.to_owned()))
}
