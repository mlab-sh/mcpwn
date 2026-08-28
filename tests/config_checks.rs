//! Checks that read a server's configuration rather than its tools: secrets,
//! unpinned launch packages, transport hygiene.
//!
//! These are the only checks that say anything at all about stdio servers,
//! which are never enumerated, so they are also the only place a local server
//! gets looked at.

use std::collections::BTreeMap;

use mcpwn::analysis::check::{ScanContext, ServerCheck};
use mcpwn::analysis::config::{PinningCheck, SecretsCheck, TransportCheck};
use mcpwn::finding::{Finding, Severity};
use mcpwn::manifest::{ServerManifest, Transport};
use mcpwn::Analyzer;

// --- helpers ----------------------------------------------------------------

fn stdio(name: &str, command: &str, args: &[&str], env: &[(&str, &str)]) -> ServerManifest {
    let mut server = ServerManifest::new(name);
    server.transport = Some(Transport::Stdio {
        command: command.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
    });
    server
}

fn http(name: &str, url: &str) -> ServerManifest {
    let mut server = ServerManifest::new(name);
    server.transport = Some(Transport::Http {
        url: url.to_owned(),
    });
    server
}

fn run(check: &dyn ServerCheck, server: &ServerManifest) -> Vec<Finding> {
    let servers = [server.clone()];
    let ctx = ScanContext::new(&servers);
    check.check(server, &ctx)
}

fn ids(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.id.as_str()).collect()
}

// --- secrets ----------------------------------------------------------------

#[test]
fn a_known_token_prefix_is_reported_as_critical() {
    let server = stdio(
        "github",
        "node",
        &["server.js"],
        &[(
            "GITHUB_PERSONAL_ACCESS_TOKEN",
            "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        )],
    );

    let findings = run(&SecretsCheck::new(), &server);
    assert_eq!(ids(&findings), vec!["MCPWN-CFG-001"]);
    assert_eq!(findings[0].severity, Severity::Critical);
    assert_eq!(findings[0].server.as_deref(), Some("github"));
    assert!(
        findings[0].message.contains("GitHub"),
        "{}",
        findings[0].message
    );
}

#[test]
fn every_documented_prefix_is_actually_matched() {
    for (name, value) in [
        ("OPENAI_API_KEY", "sk-proj-abcdefghijklmnopqrstuvwxyz012345"),
        (
            "ANTHROPIC_API_KEY",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
        ),
        ("AWS_ACCESS_KEY_ID", "AKIA4KJQ2NVB7XZLM3PW"),
        ("SLACK_BOT_TOKEN", "xoxb-1234567890-abcdefghijklm"),
        ("GOOGLE_API_KEY", "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
        ("STRIPE_KEY", "sk_live_abcdefghijklmnopqrstuvwx"),
        ("HF_TOKEN", "hf_abcdefghijklmnopqrstuvwxyz0123456789"),
    ] {
        let server = stdio("s", "node", &[], &[(name, value)]);
        let findings = run(&SecretsCheck::new(), &server);
        assert_eq!(ids(&findings), vec!["MCPWN-CFG-001"], "{name} was missed");
    }
}

#[test]
fn a_credential_shaped_name_with_a_high_entropy_value_is_reported() {
    let server = stdio(
        "api",
        "node",
        &[],
        &[("SERVICE_API_KEY", "8f3Kq2vZpL9xR4mN7wTbY1cJ6hD0sA5e")],
    );

    let findings = run(&SecretsCheck::new(), &server);
    assert_eq!(ids(&findings), vec!["MCPWN-CFG-001"]);
    assert_eq!(
        findings[0].severity,
        Severity::High,
        "weaker evidence, lower severity"
    );
}

#[test]
fn a_finding_never_prints_the_credential() {
    const SECRET: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
    let server = stdio("github", "node", &[], &[("GITHUB_TOKEN", SECRET)]);

    let findings = run(&SecretsCheck::new(), &server);
    let rendered = format!("{:?}", findings[0]);

    assert!(
        !rendered.contains(SECRET),
        "the secret leaked into the finding"
    );
    assert!(rendered.contains("redacted"), "{rendered}");
}

#[test]
fn ordinary_settings_are_not_secrets() {
    for (name, value) in [
        ("LOG_LEVEL", "debug"),
        ("PORT", "3000"),
        ("NODE_ENV", "production"),
        ("ALLOWED_DIR", "/Users/alice/projects"),
        ("TIMEOUT_MS", "30000"),
        // A name that says credential but a value that plainly is not one.
        ("API_KEY_FILE", "/etc/keys/api"),
    ] {
        let server = stdio("s", "node", &[], &[(name, value)]);
        assert!(
            run(&SecretsCheck::new(), &server).is_empty(),
            "false positive on {name}={value}"
        );
    }
}

#[test]
fn a_scoped_npm_package_is_not_mistaken_for_a_version() {
    // Regression: `@scope/name` has a leading `@` that is not a version
    // separator. Reading it as one misreported the scope as a version range.
    let server = stdio(
        "gh",
        "npx",
        &["-y", "@modelcontextprotocol/server-github"],
        &[],
    );
    let findings = run(&PinningCheck::new(), &server);

    assert_eq!(ids(&findings), vec!["MCPWN-CFG-002"]);
    assert!(
        findings[0].message.contains("no version is specified"),
        "the scope was read as a version: {}",
        findings[0].message
    );

    // ...and a scoped package *with* a version is correctly seen as pinned.
    let pinned = stdio(
        "gh",
        "npx",
        &["-y", "@modelcontextprotocol/server-github@2026.1.0"],
        &[],
    );
    assert!(run(&PinningCheck::new(), &pinned).is_empty());
}

#[test]
fn documentation_examples_are_not_reported_as_live_credentials() {
    // AWS's own documented sample key. Firing on copied documentation trains
    // people to ignore the rule.
    let server = stdio(
        "s",
        "node",
        &[],
        &[("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")],
    );
    assert!(run(&SecretsCheck::new(), &server).is_empty());
}

#[test]
fn placeholders_are_not_secrets() {
    for value in [
        "your-token-here",
        "${GITHUB_TOKEN}",
        "changeme",
        "sk-XXXXXXXXXXXXXXXXXXXXXXXX",
        "<your-api-key>",
        "",
    ] {
        let server = stdio("s", "node", &[], &[("GITHUB_TOKEN", value)]);
        assert!(
            run(&SecretsCheck::new(), &server).is_empty(),
            "false positive on placeholder {value:?}"
        );
    }
}

#[test]
fn an_http_server_has_no_env_to_scan() {
    assert!(run(&SecretsCheck::new(), &http("remote", "https://x.test/mcp")).is_empty());
}

// --- pinning ----------------------------------------------------------------

#[test]
fn an_unpinned_npx_package_is_reported() {
    let server = stdio(
        "gh",
        "npx",
        &["-y", "@modelcontextprotocol/server-github"],
        &[],
    );

    let findings = run(&PinningCheck::new(), &server);
    assert_eq!(ids(&findings), vec!["MCPWN-CFG-002"]);
    // `-y` makes a silent first fetch, so it is the worse variant.
    assert_eq!(findings[0].severity, Severity::High);
    assert!(
        findings[0].message.contains("no version is specified"),
        "{}",
        findings[0].message
    );
    assert!(
        findings[0].message.contains("`mcp.lock` cannot catch it"),
        "{}",
        findings[0].message
    );
}

#[test]
fn a_pinned_package_is_not_reported() {
    for spec in ["some-mcp@1.4.2", "@vendor/mcp@0.1.0", "pkg@2026.1.0-beta.1"] {
        let server = stdio("s", "npx", &["-y", spec], &[]);
        assert!(
            run(&PinningCheck::new(), &server).is_empty(),
            "{spec} is pinned and must not be reported"
        );
    }
}

#[test]
fn a_version_range_is_not_a_pin() {
    for spec in ["pkg@latest", "pkg@^1.2.0", "pkg@~2.0", "pkg@*", "pkg@next"] {
        let server = stdio("s", "npx", &[spec], &[]);
        assert_eq!(
            ids(&run(&PinningCheck::new(), &server)),
            vec!["MCPWN-CFG-002"],
            "{spec} is not a pin"
        );
    }
}

#[test]
fn without_the_auto_confirm_flag_it_is_only_medium() {
    let server = stdio("s", "npx", &["some-mcp"], &[]);
    let findings = run(&PinningCheck::new(), &server);
    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn every_package_runner_is_recognised() {
    for runner in [
        "npx",
        "uvx",
        "bunx",
        "pipx",
        "/usr/local/bin/npx",
        "npx.exe",
    ] {
        let server = stdio("s", runner, &["some-mcp"], &[]);
        assert_eq!(
            ids(&run(&PinningCheck::new(), &server)),
            vec!["MCPWN-CFG-002"],
            "{runner} was missed"
        );
    }
}

#[test]
fn a_directly_launched_binary_is_not_a_pinning_problem() {
    for (command, args) in [
        ("node", vec!["/opt/mcp/server.js"]),
        ("/usr/local/bin/my-mcp-server", vec![]),
        ("python3", vec!["-m", "my_mcp"]),
    ] {
        let server = stdio("s", command, &args, &[]);
        assert!(
            run(&PinningCheck::new(), &server).is_empty(),
            "false positive on {command}"
        );
    }
}

// --- transport --------------------------------------------------------------

#[test]
fn plaintext_http_to_a_remote_host_is_reported() {
    let findings = run(
        &TransportCheck::new(),
        &http("s", "http://mcp.example.com/mcp"),
    );
    assert_eq!(ids(&findings), vec!["MCPWN-CFG-003"]);
    assert_eq!(findings[0].severity, Severity::High);
    // The tampering half matters more than the eavesdropping half.
    assert!(
        findings[0].message.contains("tool-poisoning"),
        "{}",
        findings[0].message
    );
}

#[test]
fn plaintext_http_to_loopback_is_not_reported() {
    for url in [
        "http://localhost:3000/mcp",
        "http://127.0.0.1:8080/mcp",
        "http://[::1]:8080/mcp",
    ] {
        assert!(
            run(&TransportCheck::new(), &http("s", url)).is_empty(),
            "false positive on {url}"
        );
    }
}

#[test]
fn credentials_in_the_url_are_reported_and_redacted() {
    let findings = run(
        &TransportCheck::new(),
        &http("s", "https://user:s3cr3t@mcp.example.com/mcp"),
    );

    assert_eq!(ids(&findings), vec!["MCPWN-CFG-004"]);
    let rendered = format!("{findings:?}");
    assert!(
        !rendered.contains("s3cr3t"),
        "the credential leaked: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn a_clean_https_endpoint_is_not_reported() {
    assert!(run(
        &TransportCheck::new(),
        &http("s", "https://mcp.example.com/mcp")
    )
    .is_empty());
}

// --- pipeline ---------------------------------------------------------------

#[test]
fn server_checks_run_in_the_pipeline_and_carry_the_server() {
    let servers = vec![
        stdio(
            "github",
            "npx",
            &["-y", "@modelcontextprotocol/server-github"],
            &[("GITHUB_TOKEN", "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")],
        ),
        http("plain", "http://mcp.example.com/mcp"),
    ];

    let report = Analyzer::new().analyze(&servers);
    let mut found = ids(&report.findings);
    found.sort_unstable();
    assert_eq!(
        found,
        ["MCPWN-CFG-001", "MCPWN-CFG-002", "MCPWN-CFG-003"],
        "{:#?}",
        report.findings
    );

    // Server-scoped findings have no tool subject, but must still say what they
    // are about.
    for finding in &report.findings {
        assert!(finding.subjects.is_empty(), "{}", finding.id);
        assert!(finding.scope().is_some(), "{} has no scope", finding.id);
    }
}
