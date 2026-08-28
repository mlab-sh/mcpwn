//! Toxic-flow detection: the first global check.
//!
//! The two anti-false-positive tests are the ones to watch. Without an ingest
//! there is no injection point and therefore no flow, however much private data
//! and network access sit side by side — and a pile of benign tools must stay
//! silent.

use serde_json::json;

use mcpwn::analysis::capabilities::Capability;
use mcpwn::analysis::check::ScanContext;
use mcpwn::analysis::flow::FlowGraph;
use mcpwn::analysis::roles::{self, Role, RoleConfidence};
use mcpwn::finding::{Category, Finding, Severity};
use mcpwn::manifest::{ServerManifest, ToolManifest};
use mcpwn::Analyzer;

// --- helpers ----------------------------------------------------------------

fn tool(name: &str, description: &str, schema: serde_json::Value) -> ToolManifest {
    let mut tool = ToolManifest::new(name);
    tool.description = description.to_owned();
    tool.input_schema = Some(schema);
    tool
}

fn string_param(name: &str) -> serde_json::Value {
    json!({ "type": "object", "properties": { name: { "type": "string" } } })
}

fn server(name: &str, tools: Vec<ToolManifest>) -> ServerManifest {
    let mut server = ServerManifest::new(name);
    server.tools = tools;
    server
}

fn flows(servers: &[ServerManifest]) -> Vec<Finding> {
    Analyzer::new()
        .analyze(servers)
        .findings
        .into_iter()
        .filter(|f| f.category == Category::ToxicFlow)
        .collect()
}

fn fetch() -> ToolManifest {
    tool(
        "fetch_url",
        "Fetches a web page and returns its content.",
        string_param("url"),
    )
}

fn read_file() -> ToolManifest {
    tool(
        "read_file",
        "Reads a local file from disk.",
        string_param("path"),
    )
}

fn send_email() -> ToolManifest {
    tool(
        "send_email",
        "Sends an email to a recipient.",
        json!({ "type": "object", "properties": { "to": {"type":"string"}, "body": {"type":"string"} } }),
    )
}

// --- role tagging -----------------------------------------------------------

fn roles_of(tool: &ToolManifest, capabilities: &[Capability]) -> roles::RoleTags {
    let servers = [server("srv", vec![tool.clone()])];
    let ctx = ScanContext::new(&servers);
    // Bound to a local so `ctx` outlives the iterator borrowed from it.
    let tags = roles::tag_tool(&ctx.tools().next().expect("one tool"), capabilities);
    tags
}

#[test]
fn the_verb_and_the_object_together_decide_the_role() {
    // Same verb, opposite roles: what it reads is what matters.
    assert!(roles_of(&read_file(), &[]).has(Role::Source));
    assert!(!roles_of(&read_file(), &[]).has(Role::Ingest));

    let remote = tool(
        "read_wiki_contents",
        "View documentation about a repository.",
        string_param("repoName"),
    );
    assert!(roles_of(&remote, &[]).has(Role::Ingest));
    assert!(!roles_of(&remote, &[]).has(Role::Source));
}

#[test]
fn a_shell_tool_is_both_source_and_sink() {
    let shell = tool("run", "Runs something.", string_param("command"));
    let tags = roles_of(&shell, &[Capability::CommandExecution]);

    assert!(tags.has(Role::Source), "{tags:#?}");
    assert!(tags.has(Role::Sink), "{tags:#?}");
    assert_eq!(
        tags.get(Role::Sink).unwrap().confidence,
        RoleConfidence::Clear
    );
}

#[test]
fn an_ambiguous_network_tool_is_tagged_both_ways() {
    // No direction in the name, none in the schema: assume both, and say so.
    let ambiguous = tool("http_request", "Performs a request.", string_param("url"));
    let tags = roles_of(&ambiguous, &[Capability::NetworkAccess]);

    assert!(tags.has(Role::Ingest), "{tags:#?}");
    assert!(tags.has(Role::Sink), "{tags:#?}");
    for role in [Role::Ingest, Role::Sink] {
        assert_eq!(
            tags.get(role).unwrap().confidence,
            RoleConfidence::Ambiguous,
            "the guess must be marked as one"
        );
    }
}

#[test]
fn a_declared_http_method_settles_the_direction() {
    let posting = tool(
        "call_api",
        "Calls an API.",
        json!({
            "type": "object",
            "properties": {
                "url": { "type": "string" },
                "method": { "type": "string", "enum": ["POST"] }
            }
        }),
    );
    let tags = roles_of(&posting, &[Capability::NetworkAccess]);

    assert_eq!(
        tags.get(Role::Sink).unwrap().confidence,
        RoleConfidence::Clear
    );
    assert!(
        !tags.has(Role::Ingest),
        "a declared POST is not an ingest: {tags:#?}"
    );
}

#[test]
fn a_benign_tool_carries_no_role() {
    let add = tool(
        "add",
        "Adds two numbers.",
        json!({ "type": "object", "properties": { "a": {"type":"number"}, "b": {"type":"number"} } }),
    );
    assert!(roles_of(&add, &[]).is_empty());
}

// --- flow detection ---------------------------------------------------------

#[test]
fn the_three_roles_on_one_server_are_a_flow() {
    let findings = flows(&[server("srv", vec![fetch(), read_file(), send_email()])]);

    assert_eq!(findings.len(), 1, "{findings:#?}");
    let finding = &findings[0];
    assert_eq!(finding.id.as_str(), "MCPWN-FLOW-001");
    assert_eq!(finding.severity, Severity::Critical);

    // The chain is ordered: injection, then read, then exit.
    let chain = finding.flow.as_ref().expect("the chain is carried");
    assert_eq!(chain.len(), 3);
    assert_eq!(
        chain.steps.iter().map(|s| s.role).collect::<Vec<_>>(),
        [Role::Ingest, Role::Source, Role::Sink]
    );
    assert_eq!(chain.steps[0].tool.tool, "fetch_url");
    assert_eq!(chain.steps[1].tool.tool, "read_file");
    assert_eq!(chain.steps[2].tool.tool, "send_email");
    assert!(chain.is_exfiltrating());
    assert!(
        chain.steps.iter().all(|s| s.note.is_some()),
        "each link explains itself"
    );

    // Factual, not accusatory.
    assert!(
        finding.message.contains("structural risk"),
        "{}",
        finding.message
    );
    assert!(
        finding.message.contains("not an attack in progress"),
        "{}",
        finding.message
    );
}

#[test]
fn a_flow_is_found_across_three_separate_servers() {
    // The interesting case: each server is entirely legitimate on its own.
    let findings = flows(&[
        server("browser", vec![fetch()]),
        server("files", vec![read_file()]),
        server("mailer", vec![send_email()]),
    ]);

    assert_eq!(findings.len(), 1, "{findings:#?}");
    let chain = findings[0].flow.as_ref().expect("chain");
    let servers: Vec<&str> = chain.steps.iter().map(|s| s.tool.server.as_str()).collect();
    assert_eq!(servers, ["browser", "files", "mailer"]);
    assert!(
        findings[0].message.contains("crosses 3 servers"),
        "{}",
        findings[0].message
    );
}

#[test]
fn an_ambiguous_link_downgrades_the_finding_to_high() {
    let ambiguous = tool("http_request", "Performs a request.", string_param("url"));
    let findings = flows(&[server("srv", vec![ambiguous, read_file()])]);

    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(
        findings[0].severity,
        Severity::High,
        "a chain resting on a guess is not reported as a certainty"
    );
    assert!(
        findings[0].message.contains("ambiguous"),
        "{}",
        findings[0].message
    );
}

// --- not crying wolf --------------------------------------------------------

#[test]
fn source_and_sink_without_an_ingest_is_not_a_flow() {
    // No untrusted content can enter, so nothing steers the agent into the
    // chain. Private data next to a way out is not, on its own, a toxic flow.
    let findings = flows(&[server("srv", vec![read_file(), send_email()])]);
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn ingest_and_sink_without_a_source_is_not_a_flow() {
    let findings = flows(&[server("srv", vec![fetch(), send_email()])]);
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn benign_tools_produce_no_flow() {
    let findings = flows(&[server(
        "calc",
        vec![
            tool(
                "add",
                "Adds two numbers.",
                json!({ "type": "object", "properties": { "a": {"type":"number"} } }),
            ),
            tool(
                "multiply",
                "Multiplies two numbers.",
                json!({ "type": "object", "properties": { "a": {"type":"number"} } }),
            ),
        ],
    )]);
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn an_empty_environment_produces_no_flow() {
    assert!(flows(&[]).is_empty());
}

// --- no combinatorial explosion ---------------------------------------------

#[test]
fn many_tools_per_role_still_produce_one_finding() {
    // Five of each would be 125 triples. All 125 say the same thing.
    let mut tools = Vec::new();
    for i in 0..5 {
        tools.push(tool(
            &format!("fetch_url_{i}"),
            "Fetches a web page.",
            string_param("url"),
        ));
        tools.push(tool(
            &format!("read_file_{i}"),
            "Reads a local file from disk.",
            string_param("path"),
        ));
        tools.push(tool(
            &format!("send_email_{i}"),
            "Sends an email.",
            string_param("body"),
        ));
    }

    let findings = flows(&[server("srv", tools)]);

    assert_eq!(findings.len(), 1, "one finding, not the cartesian product");

    // ...but every alternative is listed, so the width of the exposure is not
    // lost.
    let evidence: Vec<&str> = findings[0]
        .evidence
        .iter()
        .map(|e| e.excerpt.as_str())
        .collect();
    let joined = evidence.join(" | ");
    for i in 0..5 {
        assert!(joined.contains(&format!("fetch_url_{i}")), "{joined}");
        assert!(joined.contains(&format!("send_email_{i}")), "{joined}");
    }
}

#[test]
fn the_graph_lists_every_candidate_per_role() {
    let servers = [server("srv", vec![fetch(), read_file(), send_email()])];
    let ctx = ScanContext::new(&servers);
    let graph = FlowGraph::build(&ctx, &[]);

    assert_eq!(graph.candidates(Role::Ingest).len(), 1);
    assert_eq!(graph.candidates(Role::Source).len(), 1);
    assert_eq!(graph.candidates(Role::Sink).len(), 1);
    assert!(graph.chain().is_some());
}

#[test]
fn the_finding_admits_the_tagging_is_not_exhaustive() {
    let findings = flows(&[server("srv", vec![fetch(), read_file(), send_email()])]);
    let coverage = findings[0]
        .evidence
        .iter()
        .find(|e| e.label == "coverage")
        .expect("the finding states its own limits");
    assert!(
        coverage.excerpt.contains("heuristic"),
        "{}",
        coverage.excerpt
    );
}
