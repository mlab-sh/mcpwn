//! Capability analysis: what a tool's parameters let it *do*.
//!
//! # What this reports, and what it does not
//!
//! A capability is a statement of attack surface, **not an accusation**. A tool
//! named `run_command` that takes a `command` string will be flagged, and that
//! is correct: it can execute commands. The finding says so and nothing more.
//! Deciding whether that is acceptable is the reader's job, and later checks,
//! poisoning, toxic flows: are what turn a capability into a suspicion.
//!
//! Expect legitimate tools to appear here. A scan of a filesystem server that
//! reported nothing would be the broken one.
//!
//! # How matching works
//!
//! Parameter names are **tokenised**, not substring-matched. `recommendation`
//! does not contain the token `command`; `curl_opts` does not contain `url`.
//! Substring matching on these words produces false positives faster than it
//! finds anything, so a pattern matches only a whole token (or the whole name).
//!
//! Two further filters keep the noise down:
//!
//! * only text-carrying parameters qualify: a boolean `dry_run` cannot hold a
//!   command line (see [`Param::is_texty`]);
//! * a parameter constrained by an `enum` is downgraded one severity level,
//!   since it cannot carry arbitrary input.
//!
//! Descriptions are a **secondary** signal: a name match is high confidence, a
//! description-only match is low. Some patterns are description-gated on
//! purpose: `query` alone is far too common to flag, and only counts when the
//! description says it is SQL or code.

use crate::analysis::check::{ScanContext, ToolCheck, ToolContext};
use crate::analysis::schema::{self, Param};
use crate::finding::{Category, Confidence, Evidence, Finding, Severity};

/// A dangerous capability a parameter can confer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// The parameter supplies a command line run on the host.
    CommandExecution,
    /// The parameter supplies code to be evaluated.
    CodeEvaluation,
    /// The parameter designates a filesystem location.
    FileAccess,
    /// The parameter designates a network destination.
    NetworkAccess,
    /// The parameter's value is mirrored into an HTTP request header.
    HeaderSmuggling,
}

impl Capability {
    /// Stable rule id, quotable in `--explain` and used as the SARIF `ruleId`.
    pub fn finding_id(self) -> &'static str {
        match self {
            Capability::CommandExecution => "MCPWN-CAP-001",
            Capability::CodeEvaluation => "MCPWN-CAP-002",
            Capability::FileAccess => "MCPWN-CAP-003",
            Capability::NetworkAccess => "MCPWN-CAP-004",
            Capability::HeaderSmuggling => "MCPWN-CAP-005",
        }
    }

    /// Recover the capability a finding id denotes.
    ///
    /// Lets a later check consume what this one concluded instead of
    /// re-analysing every schema.
    pub fn from_finding_id(id: &str) -> Option<Self> {
        match id {
            "MCPWN-CAP-001" => Some(Capability::CommandExecution),
            "MCPWN-CAP-002" => Some(Capability::CodeEvaluation),
            "MCPWN-CAP-003" => Some(Capability::FileAccess),
            "MCPWN-CAP-004" => Some(Capability::NetworkAccess),
            "MCPWN-CAP-005" => Some(Capability::HeaderSmuggling),
            _ => None,
        }
    }

    /// Base severity, before contextual adjustment.
    ///
    /// Execution and evaluation are the two that hand an attacker the host, so
    /// they sit at the top. File and network access are a level below: they are
    /// the ingredients of exfiltration rather than exfiltration itself, and
    /// they are extremely common in tools that have every right to them.
    pub fn base_severity(self) -> Severity {
        match self {
            Capability::CommandExecution => Severity::Critical,
            Capability::CodeEvaluation => Severity::Critical,
            Capability::FileAccess => Severity::High,
            Capability::NetworkAccess => Severity::High,
            Capability::HeaderSmuggling => Severity::Medium,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Capability::CommandExecution => "Command execution",
            Capability::CodeEvaluation => "Code evaluation",
            Capability::FileAccess => "Filesystem access",
            Capability::NetworkAccess => "Network access",
            Capability::HeaderSmuggling => "Parameter mirrored into an HTTP header",
        }
    }

    /// The factual statement put in the finding message.
    fn statement(self) -> &'static str {
        match self {
            Capability::CommandExecution => {
                "this tool can run commands on the machine hosting the server"
            }
            Capability::CodeEvaluation => "this tool can evaluate code supplied by the caller",
            Capability::FileAccess => {
                "this tool can reach a caller-chosen filesystem location, so its reach depends \
                 entirely on server-side path validation"
            }
            Capability::NetworkAccess => {
                "this tool can contact a caller-chosen network destination, which is both an \
                 SSRF vector and a way out for data"
            }
            Capability::HeaderSmuggling => {
                "the value of this parameter is copied into an HTTP request header by the client, \
                 so it reaches infrastructure that never sees the tool arguments"
            }
        }
    }

    fn remediation(self) -> &'static str {
        match self {
            Capability::CommandExecution | Capability::CodeEvaluation => {
                "Confirm this tool is meant to have this capability, and that the agent is not \
                 free to call it unattended."
            }
            Capability::FileAccess => {
                "Check that the server confines this path to an intended root."
            }
            Capability::NetworkAccess => {
                "Check that the server restricts the destinations this parameter can reach."
            }
            Capability::HeaderSmuggling => {
                "Check what the receiving infrastructure does with this header."
            }
        }
    }
}

// ---------------------------------------------------------------------------
// THE PATTERN TABLE
//
// This is the whole detection surface: everything the check knows lives here.
// Editing it is how you tune the analyser: there are no keywords buried in the
// code below.
//
//  * `names`: matched against whole tokens of the parameter name.
//                     `shell_command`, `shellCommand` and `command` all
//                     tokenise to include `command`; `recommendation` does not.
//  * `descriptions`: matched as substrings of the lowercased description.
//                     Secondary signal: on its own it yields low confidence.
//  * `name_needs_description`: the name tokens are too common to trust alone
//                     (`query`, `run`); a description match is also required.
// ---------------------------------------------------------------------------

/// One capability and the evidence that suggests it.
#[derive(Debug, Clone, Copy)]
pub struct Pattern {
    pub capability: Capability,
    pub names: &'static [&'static str],
    pub descriptions: &'static [&'static str],
    pub name_needs_description: bool,
}

/// The table. Ordered most severe first so the strongest capability for a
/// parameter is the one reported.
pub const PATTERNS: &[Pattern] = &[
    Pattern {
        capability: Capability::CommandExecution,
        names: &[
            "command",
            "cmd",
            "commandline",
            "shell",
            "exec",
            "execute",
            "argv",
            "bash",
            "sh",
            "powershell",
            "subprocess",
        ],
        descriptions: &[
            "shell command",
            "command to run",
            "command to execute",
            "execute on the host",
            "run a command",
            "runs a command",
            "command line",
            "/bin/sh",
            "subprocess",
        ],
        name_needs_description: false,
    },
    Pattern {
        capability: Capability::CommandExecution,
        // `run` and `script` name plenty of harmless things (`run_id` is
        // already excluded by the type filter, `script` can be a filename), so
        // they need the description to agree.
        names: &["run", "script"],
        descriptions: &[
            "shell",
            "execute",
            "executed",
            "run on the",
            "command",
            "interpreter",
        ],
        name_needs_description: true,
    },
    Pattern {
        capability: Capability::CodeEvaluation,
        names: &[
            "code",
            "eval",
            "expression",
            "expr",
            "snippet",
            "javascript",
            "js",
            "python",
            "sql",
        ],
        descriptions: &[
            "code to evaluate",
            "code to execute",
            "code to run",
            "arbitrary code",
            "python code",
            "javascript code",
            "sql query",
            "sql statement",
            "expression to evaluate",
            "eval(",
        ],
        name_needs_description: false,
    },
    Pattern {
        capability: Capability::CodeEvaluation,
        // `query` is the single most common parameter name in search tools.
        // Flagging it unconditionally would drown every real finding.
        names: &["query", "statement"],
        // Specific phrases only. `code` on its own matches every documentation
        // search tool ("returns code examples"), and `execute` matches any
        // description of a search being run.
        descriptions: &[
            "sql",
            "graphql",
            "cypher",
            "sparql",
            "query language",
            "against the database",
            "code to execute",
            "code to run",
            "evaluated",
        ],
        name_needs_description: true,
    },
    Pattern {
        capability: Capability::FileAccess,
        names: &[
            "path",
            "filepath",
            "filename",
            "file",
            "dir",
            "directory",
            "folder",
            "cwd",
            "workdir",
        ],
        descriptions: &[
            "file path",
            "path to",
            "absolute path",
            "relative path",
            "on disk",
            "filesystem",
            "file system",
            "directory to",
        ],
        name_needs_description: false,
    },
    Pattern {
        capability: Capability::NetworkAccess,
        names: &[
            "url", "uri", "endpoint", "webhook", "host", "hostname", "origin", "callback",
        ],
        descriptions: &[
            "url to",
            "http request",
            "https://",
            "fetch from",
            "endpoint to",
            "send to",
            "post to",
            "webhook",
        ],
        name_needs_description: false,
    },
];

/// Split a parameter name into lowercase tokens.
///
/// `shell_command` -> `["shell", "command"]`, `fileName` -> `["file", "name"]`,
/// `HTTPUrl` -> `["http", "url"]`. The full joined name is included too, so a
/// single-token name like `filepath` still matches the table entry for it.
pub fn tokenize(name: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = name.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        if c == '_' || c == '-' || c == '.' || c == ' ' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        // camelCase / PascalCase boundary, and the ACRONYMWord boundary.
        let starts_word = c.is_uppercase()
            && !current.is_empty()
            && (chars[i - 1].is_lowercase()
                || chars[i - 1].is_ascii_digit()
                || chars.get(i + 1).is_some_and(|n| n.is_lowercase()));
        if starts_word {
            tokens.push(std::mem::take(&mut current));
        }
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    let whole = name.to_ascii_lowercase();
    if !tokens.contains(&whole) {
        tokens.push(whole);
    }
    tokens
}

/// The capability analyser.
#[derive(Debug, Default, Clone, Copy)]
pub struct CapabilityCheck;

impl CapabilityCheck {
    pub fn new() -> Self {
        Self
    }
}

impl ToolCheck for CapabilityCheck {
    fn id(&self) -> &'static str {
        "capabilities"
    }

    fn description(&self) -> &'static str {
        "Reports what a tool's input schema lets it do: run commands, evaluate \
         code, reach the filesystem or the network."
    }

    fn check(&self, tool: &ToolContext<'_>, _ctx: &ScanContext<'_>) -> Vec<Finding> {
        let Some(input_schema) = tool.tool.input_schema.as_ref() else {
            return Vec::new();
        };
        let flattened = schema::flatten(input_schema);
        let subject = tool.tool_ref();
        let mut findings = Vec::new();

        for param in flattened.iter() {
            // Independent of the name patterns: the annotation *is* the
            // capability, whatever the parameter is called.
            if let Some(header) = &param.header_name {
                findings.push(header_finding(&subject, param, header, &tool.tool.name));
            }

            if !param.is_texty() {
                continue;
            }
            if let Some(matched) = strongest_match(param) {
                findings.push(capability_finding(
                    &subject,
                    param,
                    matched,
                    &tool.tool.name,
                ));
            }
        }

        findings
    }
}

/// How a pattern matched, which drives confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence1 {
    /// The parameter name carries the capability.
    Name,
    /// Only the description does. Weaker, and reported as such.
    DescriptionOnly,
}

#[derive(Debug, Clone, Copy)]
struct Match {
    capability: Capability,
    how: Evidence1,
}

/// The most severe capability this parameter matches, if any.
fn strongest_match(param: &Param) -> Option<Match> {
    let tokens = tokenize(&param.name);
    let description = param
        .description
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut best: Option<Match> = None;
    for pattern in PATTERNS {
        let name_hit = pattern
            .names
            .iter()
            .any(|candidate| tokens.iter().any(|t| t == candidate));
        let description_hit = pattern
            .descriptions
            .iter()
            .any(|needle| description.contains(needle));

        let how = if name_hit && (!pattern.name_needs_description || description_hit) {
            Evidence1::Name
        } else if description_hit && !name_hit && !pattern.name_needs_description {
            // A `name_needs_description` entry carries deliberately weak
            // needles (`shell`, `command`) that only serve to confirm a name.
            // Letting them fire alone flags every parameter whose description
            // merely mentions a shell: e.g. a `language` enum listing "bash".
            Evidence1::DescriptionOnly
        } else {
            continue;
        };

        let candidate = Match {
            capability: pattern.capability,
            how,
        };
        best = Some(match best {
            Some(current) if rank(&current) >= rank(&candidate) => current,
            _ => candidate,
        });
    }
    best
}

/// Order matches so the most severe, best-evidenced one wins.
fn rank(m: &Match) -> (Severity, u8) {
    (
        m.capability.base_severity(),
        match m.how {
            Evidence1::Name => 1,
            Evidence1::DescriptionOnly => 0,
        },
    )
}

fn capability_finding(
    subject: &crate::manifest::ToolRef,
    param: &Param,
    matched: Match,
    tool_name: &str,
) -> Finding {
    let capability = matched.capability;
    let mut severity = capability.base_severity();
    let mut notes: Vec<String> = Vec::new();

    // An enum-constrained parameter cannot carry arbitrary input.
    if param.is_constrained() {
        severity = one_level_down(severity);
        notes.push(format!(
            "constrained by an enum of {} value(s), so it cannot carry arbitrary input",
            param.enum_values.len()
        ));
    }
    if param.depth > 0 {
        notes.push(format!(
            "nested {} level(s) deep in the schema",
            param.depth
        ));
    }
    if !param.required {
        notes.push("optional".to_owned());
    }

    let confidence = match matched.how {
        Evidence1::Name => Confidence::High,
        Evidence1::DescriptionOnly => {
            // Weak evidence must not outrank a name match, or low-confidence
            // guesses bury the findings that are actually solid.
            severity = one_level_down(severity);
            notes.push("matched on the parameter description, not its name".to_owned());
            Confidence::Low
        }
    };

    let ty = param.ty.as_deref().unwrap_or("untyped");
    let mut message = format!(
        "`{tool_name}` takes a parameter `{}` ({ty}); {}. This is a statement of what the tool \
         can do, not evidence that it is malicious.",
        param.path,
        capability.statement()
    );
    if !notes.is_empty() {
        message.push_str(&format!(" Notes: {}.", notes.join("; ")));
    }

    let mut builder = Finding::builder(
        capability.finding_id(),
        Category::Capability,
        severity,
        format!("{}: `{}`", capability.title(), param.path),
    )
    .message(message)
    .confidence(confidence)
    .subject(subject.clone())
    .remediation(capability.remediation())
    .evidence(
        Evidence::new(
            format!("inputSchema.{}", param.path),
            param
                .description
                .clone()
                .unwrap_or_else(|| format!("(no description; type {ty})")),
        )
        .with_pointer(json_pointer(&param.path)),
    );

    if param.is_constrained() {
        builder = builder.evidence(Evidence::new(
            format!("inputSchema.{}.enum", param.path),
            param.enum_values.join(", "),
        ));
    }
    builder.build()
}

fn header_finding(
    subject: &crate::manifest::ToolRef,
    param: &Param,
    header: &str,
    tool_name: &str,
) -> Finding {
    let capability = Capability::HeaderSmuggling;
    Finding::builder(
        capability.finding_id(),
        Category::Capability,
        capability.base_severity(),
        format!("{}: `{}`", capability.title(), param.path),
    )
    .message(format!(
        "`{tool_name}` annotates the parameter `{}` with `x-mcp-header: {header}`, so a \
         conforming client copies its value into the HTTP header `Mcp-Param-{header}`; {}. This \
         is a statement of what the tool can do, not evidence that it is malicious.",
        param.path,
        capability.statement()
    ))
    .confidence(Confidence::High)
    .subject(subject.clone())
    .remediation(capability.remediation())
    .evidence(
        Evidence::new(
            format!("inputSchema.{}.x-mcp-header", param.path),
            header.to_owned(),
        )
        .with_pointer(json_pointer(&param.path)),
    )
    .build()
}

fn one_level_down(severity: Severity) -> Severity {
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

/// RFC 6901 pointer to a parameter inside the tool's input schema.
fn json_pointer(path: &str) -> String {
    let mut pointer = String::from("/inputSchema");
    for segment in path.split('.') {
        let segment = segment.strip_suffix("[]").unwrap_or(segment);
        pointer.push_str("/properties/");
        pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
    }
    pointer
}
