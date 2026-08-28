//! Checks on what a remote endpoint reveals about itself.
//!
//! Every one of these reads a [`ServerProbe`], so they are silent unless
//! `--probe` was passed. The probe is read-only: no tool is ever called.
//!
//! Two of them check rules the specification states as MUSTs. Those are the
//! most useful findings in the family, because a server that skips them is
//! telling you something about how carefully the rest of it was written.

use crate::analysis::check::{ScanContext, ServerCheck};
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};
use crate::manifest::ServerManifest;
use crate::recon::ServerProbe;

/// Reports what the reconnaissance pass found.
#[derive(Debug, Default, Clone, Copy)]
pub struct NetworkCheck;

impl NetworkCheck {
    pub fn new() -> Self {
        Self
    }
}

impl ServerCheck for NetworkCheck {
    fn id(&self) -> &'static str {
        "network"
    }

    fn description(&self) -> &'static str {
        "Reports what a remote endpoint reveals: whether it needs the credential \
         it was given, how it advertises authentication, what else it serves, and \
         whether it validates the protocol as specified."
    }

    fn check(&self, server: &ServerManifest, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let Some(probe) = ctx.probe(server) else {
            return Vec::new();
        };
        let mut findings = Vec::new();

        if let Some(finding) = credential_not_required(server, probe) {
            findings.push(finding);
        }
        if let Some(finding) = missing_auth_discovery(server, probe) {
            findings.push(finding);
        }
        if let Some(finding) = legacy_transport(server, probe) {
            findings.push(finding);
        }
        if let Some(finding) = plaintext_downgrade(server, probe) {
            findings.push(finding);
        }
        if let Some(finding) = version_not_validated(server, probe) {
            findings.push(finding);
        }
        if let Some(finding) = header_mismatch_accepted(server, probe) {
            findings.push(finding);
        }
        findings
    }
}

/// The endpoint answers without the credential the caller supplied.
///
/// Only reported when a credential *was* supplied: an endpoint that is simply
/// public is not a finding, and every public documentation server would fire.
/// The finding is the mismatch between what the operator believes is protected
/// and what actually is.
fn credential_not_required(server: &ServerManifest, probe: &ServerProbe) -> Option<Finding> {
    if !probe.credentials_supplied || probe.anonymous_tools_list != Some(true) {
        return None;
    }

    Some(
        Finding::builder(
            "MCPWN-NET-001",
            Category::Capability,
            Severity::High,
            "The endpoint answers without the credential it was given",
        )
        .message(format!(
            "`{}` returned its full tool list to a request carrying no credentials at all, even \
             though one was supplied for the scan. Either the credential is not needed, or it is \
             not checked on this method. Anyone who knows the URL can read every tool name, \
             description and schema this server exposes.",
            server.name
        ))
        .confidence(Confidence::High)
        .server(&server.name)
        .remediation(
            "Confirm which methods are meant to be reachable anonymously. If the answer is none, \
             the credential is not being enforced.",
        )
        .evidence(Evidence::new(
            "anonymous tools/list",
            format!(
                "HTTP {} with a JSON-RPC result",
                probe.anonymous_status.unwrap_or(0)
            ),
        ))
        .build(),
    )
}

/// A protected endpoint that does not say how to authenticate.
fn missing_auth_discovery(server: &ServerManifest, probe: &ServerProbe) -> Option<Finding> {
    if !matches!(probe.anonymous_status, Some(401 | 403)) {
        return None;
    }
    if probe.www_authenticate.is_some() || probe.protected_resource_metadata == Some(true) {
        return None;
    }

    Some(
        Finding::builder(
            "MCPWN-NET-002",
            Category::Capability,
            Severity::Low,
            "Protected endpoint with no authentication discovery",
        )
        .message(format!(
            "`{}` refuses unauthenticated requests but returns no `WWW-Authenticate` header and \
             serves no `/.well-known/oauth-protected-resource`. A client has no way to discover \
             how to authenticate, so every integration ends up hard-coding a credential it was \
             handed out of band, which is how tokens end up in configuration files.",
            server.name
        ))
        .confidence(Confidence::High)
        .server(&server.name)
        .remediation(
            "Return `WWW-Authenticate` on a 401 pointing at the resource metadata, as the \
             specification's authorization flow expects.",
        )
        .evidence(Evidence::new(
            "anonymous request",
            format!("HTTP {}", probe.anonymous_status.unwrap_or(0)),
        ))
        .build(),
    )
}

/// The deprecated HTTP+SSE transport, still up.
fn legacy_transport(server: &ServerManifest, probe: &ServerProbe) -> Option<Finding> {
    let endpoint = probe.legacy_sse_endpoint.as_ref()?;

    Some(
        Finding::builder(
            "MCPWN-NET-003",
            Category::Capability,
            Severity::Medium,
            "Deprecated HTTP+SSE transport still served",
        )
        .message(format!(
            "Alongside its Streamable HTTP endpoint, `{}` still answers the HTTP+SSE transport at \
             `{endpoint}`. That transport has been deprecated since protocol revision 2025-03-26. \
             A client that falls back to it, or is made to fall back to it, negotiates an older \
             protocol and loses everything the newer revisions added, including the header \
             validation that stops an intermediary and the server disagreeing about a request.",
            server.name
        ))
        .confidence(Confidence::High)
        .server(&server.name)
        .remediation("Retire the SSE endpoint once no client depends on it.")
        .evidence(Evidence::new("legacy endpoint", endpoint.clone()))
        .build(),
    )
}

/// The same endpoint answering over plaintext.
fn plaintext_downgrade(server: &ServerManifest, probe: &ServerProbe) -> Option<Finding> {
    let endpoint = probe.plaintext_endpoint.as_ref()?;

    Some(
        Finding::builder(
            "MCPWN-NET-004",
            Category::Capability,
            Severity::High,
            "The endpoint also answers over plaintext HTTP",
        )
        .message(format!(
            "`{}` is configured over https, but the same endpoint answers at `{endpoint}` without \
             redirecting. The encryption is therefore optional: anything that can influence which \
             URL a client uses, from a copied config to a rewritten link, gets a session it can \
             read and modify. A tampered `tools/list` response is tool poisoning that needs no \
             compromised server at all.",
            server.name
        ))
        .confidence(Confidence::High)
        .server(&server.name)
        .remediation("Redirect http to https, or stop listening on the plaintext port entirely.")
        .evidence(Evidence::new("plaintext endpoint", endpoint.clone()))
        .build(),
    )
}

/// The server never looked at the protocol version.
fn version_not_validated(server: &ServerManifest, probe: &ServerProbe) -> Option<Finding> {
    if probe.accepts_impossible_version != Some(true) {
        return None;
    }

    Some(
        Finding::builder(
            "MCPWN-NET-005",
            Category::Capability,
            Severity::Medium,
            "The protocol version is not validated",
        )
        .message(format!(
            "`{}` answered normally to a request declaring protocol version `1900-01-01`, which \
             no server can implement. The specification requires an `UnsupportedProtocolVersion` \
             error instead. The server is therefore serving requests without knowing which \
             revision they were written against, so a client and this server can disagree about \
             what a field means with nothing to catch it.",
            server.name
        ))
        .confidence(Confidence::High)
        .server(&server.name)
        .remediation(
            "Reject unknown protocol versions with error -32022, listing the versions supported.",
        )
        .evidence(Evidence::new(
            "probe",
            "MCP-Protocol-Version: 1900-01-01 returned a result".to_owned(),
        ))
        .build(),
    )
}

/// The server does not check its headers against its body.
fn header_mismatch_accepted(server: &ServerManifest, probe: &ServerProbe) -> Option<Finding> {
    if probe.accepts_header_mismatch != Some(true) {
        return None;
    }

    Some(
        Finding::builder(
            "MCPWN-NET-006",
            Category::Capability,
            Severity::Medium,
            "Request headers are not validated against the body",
        )
        .message(format!(
            "`{}` accepted a request whose `Mcp-Method` header said `tools/call` while its body \
             said `tools/list`. The specification requires a `HeaderMismatch` error, and says why: \
             gateways, load balancers and rate limiters route and authorise on the header while \
             the server acts on the body. Where those disagree, a request can be authorised as one \
             thing and executed as another.",
            server.name
        ))
        .confidence(Confidence::High)
        .server(&server.name)
        .remediation(
            "Reject a header that disagrees with the body with error -32020, as the transport \
             requires.",
        )
        .evidence(Evidence::new(
            "probe",
            "Mcp-Method: tools/call with a tools/list body returned a result".to_owned(),
        ))
        .build(),
    )
}
