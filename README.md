# mcpwn

**Static security scanner for MCP (Model Context Protocol) servers.**

<p align="center"><img src=".github/banner.png" alt="mcpwn"></p>

mcpwn reads the tool definitions an MCP server advertises and flags the ones
that can turn an agent against its user.

It never launches an MCP server.

## Install

```bash
cargo install --locked --git https://github.com/mlab-sh/mcpwn
```

## Usage

Find the MCP configs on this machine, without analysing them:

```bash
mcpwn discover
```

Scan them:

```bash
mcpwn scan
```

Scan a project directory, or a single endpoint:

```bash
mcpwn scan ./my-repo
```

```bash
mcpwn scan --url https://example.com/mcp -H "Authorization: Bearer $TOKEN"
```

Record a baseline so later scans can tell you what changed:

```bash
mcpwn scan --write-lock
```

Understand a finding:

```bash
mcpwn explain MCPWN-CAP-001
```

Exit codes: `0` clean, `1` findings at or above the threshold, `2` error.

## What it detects

22 rules. `mcpwn explain` lists them all; `mcpwn explain <ID>` gives the detail.

| Family | Rules | What |
|---|---|---|
| Configuration | `MCPWN-CFG-001..004` | Plaintext credentials, unpinned launch packages, `http://` endpoints, credentials in URLs |
| Capability | `MCPWN-CAP-001..005` | Command execution, code evaluation, filesystem and network access, `x-mcp-header` mirroring |
| Obfuscation | `MCPWN-OBF-001..006` | Unicode tag characters, zero-width characters, bidi overrides, homoglyphs, encoded payloads |
| Rug pull | `MCPWN-RUG-001..003` | Tools that changed, disappeared or appeared since the lockfile |
| Shadowing | `MCPWN-SHA-001..003` | Colliding tool names, look-alike names, a server giving instructions about another server's tool |
| Toxic flow | `MCPWN-FLOW-001` | An ingest, a source and a sink coexisting in one environment |

## Rug pull detection

`mcp.lock` records what each tool looked like when you approved it. Later scans
compare against it.

```bash
mcpwn scan --write-lock     # record the baseline
mcpwn scan                  # compare against it
mcpwn scan --update-lock    # accept the changes, after reviewing them
mcpwn diff old.lock mcp.lock
```

## In CI

```bash
mcpwn scan --fail-on high --format sarif > mcpwn.sarif
```

`mcpwn init-policy > mcpwn.toml` creates a policy file for rule overrides and
accepted findings:

```toml
fail-on = "high"

[rules]
"MCPWN-CFG-002" = "off"

[[ignore]]
rule = "MCPWN-CAP-001"
scope = "shell::run_command"
reason = "reviewed 2026-08; this server exists to run commands"
```

The GitHub Action wraps all of it:

```yaml
- uses: mlab-sh/mcpwn@main
  with:
    policy: mcpwn.toml
    lock: mcp.lock
    fail-on: high
```

See [`.github/workflows/mcpwn-example.yml`](.github/workflows/mcpwn-example.yml)
for a complete workflow.

## Supported clients

Claude Desktop, Cursor, Windsurf, Continue, Zed, Codex, VS Code. Global
locations are searched by default; a path argument searches project-level
dotfolders instead.

Only JSON configs are parsed. TOML (Codex) and YAML (Continue) files are
discovered and listed, but reported as not yet parseable.

## Limits

* stdio servers are never launched, so their tools are never listed. Only the
  configuration checks apply to them.
* Enumerating a remote server is a network request. The analysis is static; the
  tool list has to come from somewhere.
* Tool poisoning detection is not implemented yet.

## Development

```bash
just test
```

```bash
just ci
```
