//! The capability analyser and the pipeline that runs it.
//!
//! The most important test here is `a_benign_tool_produces_no_findings`: an
//! analyser that flags everything is worthless, and every pattern added to the
//! table is a chance to break it.

use serde_json::json;

use mcpwn::analysis::capabilities::{Capability, CapabilityCheck};
use mcpwn::analysis::check::{GlobalCheck, ScanContext, ToolCheck, ToolContext};
use mcpwn::analysis::registry::Registry;
use mcpwn::finding::{Category, Confidence, Finding, Severity};
use mcpwn::manifest::{ServerManifest, ToolManifest};
use mcpwn::{Analyzer, AnalyzerConfig};

// --- helpers ----------------------------------------------------------------

fn tool(name: &str, schema: serde_json::Value) -> ToolManifest {
    let mut tool = ToolManifest::new(name);
    tool.input_schema = Some(schema);
    tool
}

fn server(name: &str, tools: Vec<ToolManifest>) -> ServerManifest {
    let mut server = ServerManifest::new(name);
    server.tools = tools;
    server
}

/// Run the capability check alone over one tool.
fn check(tool: &ToolManifest) -> Vec<Finding> {
    let server = server("srv", vec![tool.clone()]);
    let servers = [server];
    let ctx = ScanContext::new(&servers);
    let tool_ctx = ctx.tools().next().expect("one tool");
    CapabilityCheck::new().check(&tool_ctx, &ctx)
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.id.as_str()).collect()
}

fn only(findings: &[Finding]) -> &Finding {
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding: {findings:#?}"
    );
    &findings[0]
}

// --- the capabilities -------------------------------------------------------

#[test]
fn a_command_parameter_is_reported_as_command_execution() {
    let findings = check(&tool(
        "run_command",
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "description": "The shell command to run." }
            },
            "required": ["command"]
        }),
    ));

    let finding = only(&findings);
    assert_eq!(
        finding.id.as_str(),
        Capability::CommandExecution.finding_id()
    );
    assert_eq!(finding.category, Category::Capability);
    assert_eq!(finding.severity, Severity::Critical);
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(
        finding.primary_subject().map(ToString::to_string),
        Some("srv::run_command".to_owned())
    );

    // Factual, not accusatory: a legitimate `run_command` gets this finding and
    // the wording has to survive that.
    assert!(
        finding.message.contains("can run commands"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .message
            .contains("not evidence that it is malicious"),
        "{}",
        finding.message
    );
}

#[test]
fn name_variants_are_all_caught() {
    for name in [
        "command",
        "cmd",
        "shell_command",
        "shellCommand",
        "exec",
        "bash",
        "subprocess",
    ] {
        let findings = check(&tool(
            "t",
            json!({ "type": "object", "properties": { name: { "type": "string" } } }),
        ));
        assert_eq!(
            ids(&findings),
            vec![Capability::CommandExecution.finding_id()],
            "`{name}` should read as command execution"
        );
    }
}

#[test]
fn a_path_parameter_is_reported_as_filesystem_access() {
    let findings = check(&tool(
        "read_file",
        json!({
            "type": "object",
            "properties": { "path": { "type": "string", "description": "Absolute path to read." } }
        }),
    ));

    let finding = only(&findings);
    assert_eq!(finding.id.as_str(), Capability::FileAccess.finding_id());
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn a_url_parameter_is_reported_as_network_access() {
    let findings = check(&tool(
        "fetch",
        json!({
            "type": "object",
            "properties": { "url": { "type": "string", "description": "URL to fetch." } }
        }),
    ));

    let finding = only(&findings);
    assert_eq!(finding.id.as_str(), Capability::NetworkAccess.finding_id());
    assert_eq!(finding.severity, Severity::High);
}

#[test]
fn an_x_mcp_header_annotation_is_reported() {
    let findings = check(&tool(
        "execute_sql_ish",
        json!({
            "type": "object",
            "properties": {
                "region": {
                    "type": "string",
                    "description": "The region to use",
                    "x-mcp-header": "Region"
                }
            }
        }),
    ));

    let finding = only(&findings);
    assert_eq!(
        finding.id.as_str(),
        Capability::HeaderSmuggling.finding_id()
    );
    assert_eq!(finding.severity, Severity::Medium);
    assert!(
        finding.message.contains("Mcp-Param-Region"),
        "{}",
        finding.message
    );
}

#[test]
fn a_nested_schema_is_walked_in_depth() {
    let findings = check(&tool(
        "configure",
        json!({
            "type": "object",
            "properties": {
                "label": { "type": "string" },
                "options": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "object",
                            "properties": { "path": { "type": "string" } }
                        }
                    }
                }
            }
        }),
    ));

    let finding = only(&findings);
    assert_eq!(finding.id.as_str(), Capability::FileAccess.finding_id());
    assert!(
        finding.title.contains("options.target.path"),
        "the dotted path must be reported: {}",
        finding.title
    );
    assert!(
        finding.message.contains("nested 2 level(s) deep"),
        "{}",
        finding.message
    );
}

#[test]
fn an_array_of_objects_is_walked_too() {
    let findings = check(&tool(
        "batch",
        json!({
            "type": "object",
            "properties": {
                "jobs": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": { "command": { "type": "string" } }
                    }
                }
            }
        }),
    ));

    assert_eq!(
        ids(&findings),
        vec![Capability::CommandExecution.finding_id()]
    );
    assert!(
        findings[0].title.contains("jobs[].command"),
        "{}",
        findings[0].title
    );
}

// --- not crying wolf --------------------------------------------------------

#[test]
fn a_benign_tool_produces_no_findings() {
    let findings = check(&tool(
        "send_greeting",
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "Who to greet." },
                "message": { "type": "string", "description": "What to say." }
            },
            "required": ["name", "message"]
        }),
    ));

    assert!(findings.is_empty(), "false positives: {findings:#?}");
}

#[test]
fn common_words_that_merely_contain_a_keyword_are_not_flagged() {
    // Substring matching would flag every one of these. Tokenised matching
    // must not.
    for name in [
        "recommendation", // contains "command"
        "curl_options",   // contains "url"
        "sympathy",       // contains "path"
        "runtime",        // contains "run"
        "hostility",      // contains "host"
        "codec",          // contains "code"
        "profile_id",     // contains "file"
    ] {
        let findings = check(&tool(
            "t",
            json!({ "type": "object", "properties": { name: { "type": "string" } } }),
        ));
        assert!(
            findings.is_empty(),
            "`{name}` is a false positive: {findings:#?}"
        );
    }
}

#[test]
fn a_non_text_parameter_cannot_carry_a_command() {
    // `dry_run` is a boolean: it cannot hold a command line.
    let findings = check(&tool(
        "deploy",
        json!({
            "type": "object",
            "properties": {
                "dry_run": { "type": "boolean" },
                "run_id": { "type": "integer" }
            }
        }),
    ));

    assert!(findings.is_empty(), "false positives: {findings:#?}");
}

#[test]
fn a_bare_query_parameter_is_not_code_evaluation() {
    // The single most common parameter name in search tools. Flagging it would
    // drown every real finding — verified against three live public servers.
    let findings = check(&tool(
        "search_docs",
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What to look up in the documentation. Returns code examples."
                }
            }
        }),
    ));

    assert!(findings.is_empty(), "false positives: {findings:#?}");
}

#[test]
fn a_sql_query_parameter_is_code_evaluation() {
    // ...but the same name *is* reported when the description says SQL.
    let findings = check(&tool(
        "run_sql",
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "The SQL to execute against the database." }
            }
        }),
    ));

    assert_eq!(
        ids(&findings),
        vec![Capability::CodeEvaluation.finding_id()]
    );
}

#[test]
fn an_enum_constrained_parameter_is_downgraded() {
    let findings = check(&tool(
        "run_preset",
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string", "enum": ["start", "stop", "status"] }
            }
        }),
    ));

    let finding = only(&findings);
    assert_eq!(
        finding.severity,
        Severity::High,
        "an enum-constrained command cannot carry arbitrary input"
    );
    assert!(
        finding.message.contains("constrained by an enum"),
        "{}",
        finding.message
    );
}

#[test]
fn a_language_enum_mentioning_a_shell_is_not_command_execution() {
    // Regression from a live scan: `language` was reported CRITICAL because its
    // description listed "bash" and "powershell" among the values.
    let findings = check(&tool(
        "search_code",
        json!({
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "description": "Programming language, e.g. 'python', 'bash', 'powershell', 'shell'."
                }
            }
        }),
    ));

    assert!(findings.is_empty(), "false positive: {findings:#?}");
}

#[test]
fn a_tool_without_a_schema_is_skipped() {
    assert!(check(&ToolManifest::new("no_schema")).is_empty());
}

// --- the pipeline -----------------------------------------------------------

#[test]
fn the_pipeline_aggregates_findings_across_tools_and_servers() {
    let servers = vec![
        server(
            "alpha",
            vec![
                tool(
                    "shell",
                    json!({ "type": "object", "properties": { "command": { "type": "string" } } }),
                ),
                tool(
                    "greet",
                    json!({ "type": "object", "properties": { "name": { "type": "string" } } }),
                ),
            ],
        ),
        server(
            "beta",
            vec![tool(
                "fetch",
                json!({
                    "type": "object",
                    "properties": {
                        "url": { "type": "string" },
                        "out": { "type": "object", "properties": { "path": { "type": "string" } } }
                    }
                }),
            )],
        ),
    ];

    let report = Analyzer::new().analyze(&servers);

    assert_eq!(report.meta.servers, 2);
    assert_eq!(report.meta.tools, 3);
    assert_eq!(report.findings.len(), 3, "{:#?}", report.findings);

    // Sorted most severe first.
    assert_eq!(report.max_severity(), Some(Severity::Critical));
    assert_eq!(report.findings[0].severity, Severity::Critical);
    assert!(report
        .findings
        .windows(2)
        .all(|w| w[0].severity >= w[1].severity));

    // Findings are attributed to the right server.
    let subjects: Vec<String> = report
        .findings
        .iter()
        .filter_map(|f| f.primary_subject().map(ToString::to_string))
        .collect();
    assert!(subjects.contains(&"alpha::shell".to_owned()));
    assert!(subjects.contains(&"beta::fetch".to_owned()));
    assert!(!subjects.iter().any(|s| s.contains("greet")));
}

#[test]
fn the_registry_carries_both_levels() {
    let registry = Registry::builtin();

    assert_eq!(registry.tool_checks().count(), 1);
    assert_eq!(
        registry.global_checks().count(),
        1,
        "the global level must be wired even while its checks are stubs"
    );
    assert!(registry.tool_checks().any(|c| c.id() == "capabilities"));
    assert!(registry.global_checks().any(|c| c.id() == "toxic-flow"));
}

#[test]
fn a_custom_registry_replaces_the_builtin_checks() {
    #[derive(Debug)]
    struct Noisy;
    impl ToolCheck for Noisy {
        fn id(&self) -> &'static str {
            "noisy"
        }
        fn description(&self) -> &'static str {
            "flags everything"
        }
        fn check(&self, tool: &ToolContext<'_>, _: &ScanContext<'_>) -> Vec<Finding> {
            vec![
                Finding::builder("TEST-001", Category::Capability, Severity::Low, "noise")
                    .subject(tool.tool_ref())
                    .build(),
            ]
        }
    }

    #[derive(Debug)]
    struct Counter;
    impl GlobalCheck for Counter {
        fn id(&self) -> &'static str {
            "counter"
        }
        fn description(&self) -> &'static str {
            "reports how many tools it saw"
        }
        fn check(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
            vec![Finding::builder(
                "TEST-002",
                Category::Capability,
                Severity::Info,
                format!("saw {} tool(s)", ctx.tool_count()),
            )
            .build()]
        }
    }

    let servers = vec![server(
        "srv",
        vec![
            tool("a", json!({ "type": "object", "properties": {} })),
            tool("b", json!({ "type": "object", "properties": {} })),
        ],
    )];

    let report = Analyzer::new()
        .with_registry(
            Registry::empty()
                .with_tool_check(Noisy)
                .with_global_check(Counter),
        )
        .analyze(&servers);

    // Two per-tool findings plus one global one — both levels ran.
    assert_eq!(report.findings.len(), 3);
    assert!(report.findings.iter().any(|f| f.title == "saw 2 tool(s)"));
}

#[test]
fn global_checks_can_be_skipped() {
    let servers = vec![server("srv", vec![tool("a", json!({}))])];

    #[derive(Debug)]
    struct Global;
    impl GlobalCheck for Global {
        fn id(&self) -> &'static str {
            "g"
        }
        fn description(&self) -> &'static str {
            "always fires"
        }
        fn check(&self, _: &ScanContext<'_>) -> Vec<Finding> {
            vec![
                Finding::builder("TEST-003", Category::Capability, Severity::Info, "fired").build(),
            ]
        }
    }

    let registry = || Registry::empty().with_global_check(Global);

    assert_eq!(
        Analyzer::new()
            .with_registry(registry())
            .analyze(&servers)
            .findings
            .len(),
        1
    );
    assert!(Analyzer::with_config(AnalyzerConfig {
        target: None,
        skip_global: true,
    })
    .with_registry(registry())
    .analyze(&servers)
    .is_empty());
}
