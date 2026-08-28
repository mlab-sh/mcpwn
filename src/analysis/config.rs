//! Checks on a server's *configuration* rather than on its tools.
//!
//! These run before any tool is enumerated and work on stdio servers too, which
//! the tool-level checks never see: a local server's launch command and
//! environment are the only things mcpwn can observe about it without running
//! it, and both carry real risk.

use crate::analysis::check::{ScanContext, ServerCheck};
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};
use crate::manifest::{ServerManifest, Transport};

// ---------------------------------------------------------------------------
// Secrets in the configuration
// ---------------------------------------------------------------------------

/// A credential format recognisable from its shape alone.
///
/// Prefix matching, not entropy alone: `ghp_` is a GitHub token whatever its
/// entropy, and a high-entropy string is not a secret just because it is
/// random. Entropy is used only as a fallback for values whose *name* says
/// secret.
#[derive(Debug, Clone, Copy)]
pub struct SecretPattern {
    pub label: &'static str,
    pub prefix: &'static str,
    /// Minimum total length for the value to be worth reporting.
    pub min_len: usize,
}

/// THE TABLE. Prefixes are published by the issuers themselves.
pub const SECRET_PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        label: "GitHub personal access token",
        prefix: "ghp_",
        min_len: 20,
    },
    SecretPattern {
        label: "GitHub OAuth token",
        prefix: "gho_",
        min_len: 20,
    },
    SecretPattern {
        label: "GitHub app token",
        prefix: "ghs_",
        min_len: 20,
    },
    SecretPattern {
        label: "GitHub fine-grained token",
        prefix: "github_pat_",
        min_len: 30,
    },
    SecretPattern {
        label: "OpenAI API key",
        prefix: "sk-",
        min_len: 20,
    },
    SecretPattern {
        label: "Anthropic API key",
        prefix: "sk-ant-",
        min_len: 30,
    },
    SecretPattern {
        label: "AWS access key id",
        prefix: "AKIA",
        min_len: 16,
    },
    SecretPattern {
        label: "AWS temporary access key id",
        prefix: "ASIA",
        min_len: 16,
    },
    SecretPattern {
        label: "Slack bot token",
        prefix: "xoxb-",
        min_len: 20,
    },
    SecretPattern {
        label: "Slack user token",
        prefix: "xoxp-",
        min_len: 20,
    },
    SecretPattern {
        label: "Slack app token",
        prefix: "xapp-",
        min_len: 20,
    },
    SecretPattern {
        label: "Google API key",
        prefix: "AIza",
        min_len: 30,
    },
    SecretPattern {
        label: "Stripe live secret key",
        prefix: "sk_live_",
        min_len: 20,
    },
    SecretPattern {
        label: "Stripe test secret key",
        prefix: "sk_test_",
        min_len: 20,
    },
    SecretPattern {
        label: "npm token",
        prefix: "npm_",
        min_len: 30,
    },
    SecretPattern {
        label: "Hugging Face token",
        prefix: "hf_",
        min_len: 30,
    },
    SecretPattern {
        label: "Discord bot token",
        prefix: "MTA",
        min_len: 50,
    },
    SecretPattern {
        label: "SendGrid API key",
        prefix: "SG.",
        min_len: 30,
    },
    SecretPattern {
        label: "Telegram bot token",
        prefix: "bot",
        min_len: 40,
    },
    SecretPattern {
        label: "private key block",
        prefix: "-----BEGIN",
        min_len: 20,
    },
];

/// Environment variable names that say the value is a credential.
const SECRET_NAMES: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "key",
    "credential",
    "credentials",
    "auth",
    "authorization",
    "access_key",
    "private_key",
    "session",
    "cookie",
    "pat",
    "dsn",
];

/// Values that are obviously placeholders rather than live credentials.
const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "xxx",
    "todo",
    "your",
    "example",
    "placeholder",
    "dummy",
    "test",
    "none",
    "null",
    "redacted",
    "<",
    "${",
    "$(",
    "%%",
];

/// Reports credentials written in plain text inside an MCP client config.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecretsCheck;

impl SecretsCheck {
    pub fn new() -> Self {
        Self
    }
}

impl ServerCheck for SecretsCheck {
    fn id(&self) -> &'static str {
        "config-secrets"
    }

    fn description(&self) -> &'static str {
        "Finds credentials written in plain text in an MCP client configuration."
    }

    fn check(&self, server: &ServerManifest, _ctx: &ScanContext<'_>) -> Vec<Finding> {
        let Some(Transport::Stdio { env, .. }) = server.transport.as_ref() else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        for (name, value) in env {
            if is_placeholder(value) {
                continue;
            }

            // A recognised issuer prefix is proof enough on its own.
            if let Some(pattern) = SECRET_PATTERNS
                .iter()
                .find(|p| value.starts_with(p.prefix) && value.len() >= p.min_len)
            {
                findings.push(secret_finding(
                    server,
                    name,
                    value,
                    Severity::Critical,
                    Confidence::High,
                    &format!("its value has the shape of a {}", pattern.label),
                ));
                continue;
            }

            // Otherwise: the variable's *name* says credential and the value
            // looks like one rather than a setting.
            let lowered = name.to_ascii_lowercase();
            if SECRET_NAMES.iter().any(|n| lowered.contains(n))
                && value.len() >= 16
                && shannon_entropy(value) >= 3.0
            {
                findings.push(secret_finding(
                    server,
                    name,
                    value,
                    Severity::High,
                    Confidence::Medium,
                    "its name says credential and its value is long and high-entropy",
                ));
            }
        }
        findings
    }
}

fn secret_finding(
    server: &ServerManifest,
    name: &str,
    value: &str,
    severity: Severity,
    confidence: Confidence,
    why: &str,
) -> Finding {
    Finding::builder(
        "MCPWN-CFG-001",
        Category::Capability,
        severity,
        format!("Credential in plain text: `{name}`"),
    )
    .message(format!(
        "The configuration for `{}` sets the environment variable `{name}` to a literal value, \
         and {why}. Anything that can read this config file has the credential: backups, sync \
         clients, other local processes, and anyone the file is shared with. Config files are \
         also committed by accident far more often than they are encrypted.",
        server.name
    ))
    .confidence(confidence)
    .server(&server.name)
    .remediation(
        "Move the value out of the config: read it from the environment at launch, or from a \
         secret manager. If it has already been committed anywhere, rotate it; removing it from \
         the file does not un-leak it.",
    )
    .evidence(Evidence::new(format!("env.{name}"), redact(value)))
    .build()
}

/// Never print a live credential. Enough to identify it, not enough to use it.
fn redact(value: &str) -> String {
    let visible: String = value.chars().take(4).collect();
    format!("{visible}… ({} chars, redacted)", value.chars().count())
}

fn is_placeholder(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    value.trim().is_empty() || PLACEHOLDERS.iter().any(|p| lowered.contains(p))
}

/// Shannon entropy in bits per character.
fn shannon_entropy(value: &str) -> f64 {
    let mut counts = [0usize; 256];
    let bytes = value.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// Unpinned launch commands
// ---------------------------------------------------------------------------

/// Package runners that fetch and execute code at launch time.
const RUNNERS: &[&str] = &["npx", "uvx", "pnpm", "bunx", "yarn", "pipx", "dlx", "deno"];

/// Reports stdio servers whose launch command resolves a package at runtime
/// without pinning a version.
///
/// This is the rug pull that needs no malicious server at all: the package
/// maintainer (or anyone who takes over the account) changes the code under
/// you, and `mcp.lock` cannot see it because the tool list may not change at
/// all. Purely static: the command line is read, never run.
#[derive(Debug, Default, Clone, Copy)]
pub struct PinningCheck;

impl PinningCheck {
    pub fn new() -> Self {
        Self
    }
}

impl ServerCheck for PinningCheck {
    fn id(&self) -> &'static str {
        "config-pinning"
    }

    fn description(&self) -> &'static str {
        "Finds stdio servers launched from an unpinned remote package."
    }

    fn check(&self, server: &ServerManifest, _ctx: &ScanContext<'_>) -> Vec<Finding> {
        let Some(Transport::Stdio { command, args, .. }) = server.transport.as_ref() else {
            return Vec::new();
        };

        let runner = command
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(command)
            .trim_end_matches(".exe");
        if !RUNNERS.contains(&runner) {
            return Vec::new();
        }

        // The package specifier is the first argument that is not a flag.
        let Some(package) = args.iter().find(|a| !a.starts_with('-')) else {
            return Vec::new();
        };

        // `name@1.2.3` is pinned; `name`, `name@latest`, `name@^1` are not.
        //
        // The `@` must not be the first character: `@scope/name` is a scoped
        // npm package with no version at all, and reading its scope as a
        // version specifier would misreport every scoped package.
        let version = package
            .char_indices()
            .rev()
            .find(|(i, c)| *c == '@' && *i > 0)
            .map(|(i, _)| &package[i + 1..])
            .filter(|v| !v.is_empty());
        let pinned = version.is_some_and(|v| {
            v.chars().next().is_some_and(|c| c.is_ascii_digit())
                && !v.contains('^')
                && !v.contains('~')
                && !v.contains('*')
        });
        if pinned {
            return Vec::new();
        }

        let auto_confirm = args.iter().any(|a| a == "-y" || a == "--yes");
        let mut notes = vec![format!("resolved by `{runner}` at every launch")];
        if let Some(version) = version {
            notes.push(format!(
                "the version specifier `{version}` is a range, not a pin"
            ));
        } else {
            notes.push("no version is specified at all".to_owned());
        }
        if auto_confirm {
            notes.push(
                "`-y` suppresses the install prompt, so a first-time fetch is silent".to_owned(),
            );
        }

        vec![Finding::builder(
            "MCPWN-CFG-002",
            Category::RugPull,
            if auto_confirm {
                Severity::High
            } else {
                Severity::Medium
            },
            format!("Unpinned launch package: `{package}`"),
        )
        .message(format!(
            "`{}` is launched with `{command} {}`, which downloads and executes `{package}` fresh: \
             {}. Whoever controls that package controls what runs on this machine, on the next \
             launch, with no change visible in the configuration, and `mcp.lock` cannot catch it, \
             because the code can change while the tool list stays identical.",
            server.name,
            args.join(" "),
            notes.join("; ")
        ))
        .confidence(Confidence::High)
        .server(&server.name)
        .remediation(
            "Pin an exact version (`package@1.2.3`), or install the server once and launch the \
             installed binary directly.",
        )
        .evidence(Evidence::new(
            "command",
            format!("{command} {}", args.join(" ")),
        ))
        .build()]
    }
}

// ---------------------------------------------------------------------------
// Transport hygiene
// ---------------------------------------------------------------------------

/// Reports remote endpoints reached over channels that leak.
#[derive(Debug, Default, Clone, Copy)]
pub struct TransportCheck;

impl TransportCheck {
    pub fn new() -> Self {
        Self
    }
}

impl ServerCheck for TransportCheck {
    fn id(&self) -> &'static str {
        "config-transport"
    }

    fn description(&self) -> &'static str {
        "Finds remote endpoints reached over plaintext or with credentials in the URL."
    }

    fn check(&self, server: &ServerManifest, _ctx: &ScanContext<'_>) -> Vec<Finding> {
        let Some(Transport::Http { url }) = server.transport.as_ref() else {
            return Vec::new();
        };
        let mut findings = Vec::new();
        let lowered = url.to_ascii_lowercase();

        let authority = lowered
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""))
            .unwrap_or("");
        let host = authority.rsplit('@').next().unwrap_or("");
        let loopback = host.starts_with("localhost")
            || host.starts_with("127.")
            || host.starts_with("[::1]")
            || host.starts_with("0.0.0.0");

        // Plaintext HTTP: everything the agent sends and receives, including
        // any Authorization header, crosses the network in the clear.
        if lowered.starts_with("http://") && !loopback {
            findings.push(
                Finding::builder(
                    "MCPWN-CFG-003",
                    Category::Capability,
                    Severity::High,
                    "Remote server reached over plaintext HTTP",
                )
                .message(format!(
                    "`{}` is configured at `{url}`, which is unencrypted. Every tool argument, \
                     every result and any credential sent with the request is readable and \
                     modifiable by anything on the path, and a modified `tools/list` response is \
                     a tool-poisoning attack that needs no compromised server at all.",
                    server.name
                ))
                .confidence(Confidence::High)
                .server(&server.name)
                .remediation("Use https://, or reach the server through a tunnel that provides transport security.")
                .evidence(Evidence::new("url", url.clone()))
                .build(),
            );
        }

        // Credentials in the URL: they end up in logs, proxies and history.
        if authority.contains('@') {
            findings.push(
                Finding::builder(
                    "MCPWN-CFG-004",
                    Category::Capability,
                    Severity::High,
                    "Credentials embedded in the endpoint URL",
                )
                .message(format!(
                    "The endpoint for `{}` carries userinfo before the host. A credential in a URL \
                     is written to proxy logs, browser and shell history, crash reports and \
                     referrer headers: all places nobody thinks to rotate.",
                    server.name
                ))
                .confidence(Confidence::High)
                .server(&server.name)
                .remediation("Send the credential in an Authorization header instead of the URL.")
                .evidence(Evidence::new("url", redact_userinfo(url)))
                .build(),
            );
        }

        findings
    }
}

/// Keep the URL readable without printing the credential in it.
fn redact_userinfo(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_, tail)) => format!("{scheme}://<redacted>@{tail}"),
            None => url.to_owned(),
        },
        None => url.to_owned(),
    }
}
