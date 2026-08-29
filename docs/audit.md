# How the active audit works

`mcpwn audit` is the only command that launches a process and the only one that
calls a tool. Everything else reads.

That distinction is not cosmetic. Calling a tool means acting on the target: it
creates, sends, writes and spends whatever the tools it is allowed to call
create, send, write and spend. Pointing it at somebody else's server is not
scanning, it is using their infrastructure.

## Four guards

**An engagement file is the only way in.** There is no `--url` and no config
discovery, so one invocation can never reach every server on a machine. The file
names one target and who authorised it, and refuses to load without either. A
flag anyone can type is not a record of anything.

**Nothing is called that the engagement did not name.** `tools.allow` is the
scope, it is empty by default, and it is enforced at the wire rather than in the
report: a test reads the transcript and asserts no out-of-scope tool appears in
it.

**A tool that takes a command line is skipped** unless `tools.allow_dangerous`
is set, because probing it runs what it takes. The check reuses the capability
analysis rather than keeping a second copy of the pattern table.

**Everything is written down** as it happens, one JSON line per exchange,
flushed per line so an interrupted run still accounts for what it had already
done to the target.

## The engagement file

```toml
target = "https://mcp.example.com/mcp"   # or "stdio:npx" with args = [...]
authorized_by = "you@example.com"
reference = "PT-2026-014"

[limits]
rate_per_second = 2      # deliberately slow
max_requests = 500       # a ceiling that refuses rather than bends
timeout_seconds = 20

[tools]
allow = ["read_file", "fetch_url"]
allow_dangerous = false
# probes = ["path-traversal", "ssrf"]    # omit for all the ungated ones
```

`mcpwn audit init` prints a starter. `mcpwn audit run --dry-run` shows exactly
which probe would touch which parameter, and sends nothing.

## Two rules every probe follows

**Nothing destructive is ever sent.** `; echo mcpwn-<nonce>` yes, `; rm` never.
`' OR '1'='1` yes, `DROP TABLE` never. This is not politeness: a payload that
changes the target cannot be re-run, and a finding nobody can reproduce is not a
finding.

**Every hit is checked against a control.** The same tool is called with an
ordinary value and the oracle must *not* fire. A server that returns
`root:x:0:0` whatever you send it is not vulnerable to traversal, it is
returning a fixed string, and without the control that is a critical finding
that wastes somebody's afternoon.

Two calls per finding, visible in the transcript.

## The probes

### Per parameter

| Probe | Payload | Oracle |
|---|---|---|
| `path-traversal` | `../../../../etc/passwd`, `/etc/passwd`, `....//`, Windows form | `root:x:0:0` or `root:*:0:0` or `[fonts]` |
| `command-injection` | `; echo mc""pwn-<nonce>` and shell variants | the unquoted marker in the response |
| `sql-injection` | `'`, `"`, `') OR ('1'='1` | a database error naming its own syntax |
| `ssrf` | `http://169.254.169.254/latest/meta-data/` and GCP form | `ami-id`, `iam/security-credentials`, `computeMetadata` |

The command-injection marker is self-validating. The payload contains
`mc""pwn-<nonce>`, which a shell dequotes: echoed back literally it reads
`mc""pwn-…`, interpreted it reads `mcpwn-…`. A server that merely reflects its
input cannot trigger it.

The traversal oracle carries both spellings of the root entry, `root:x:0:0` on
Linux and `root:*:0:0` on macOS and the BSDs. The second was missing at first
and the probe silently missed a server that was plainly vulnerable. Oracles are
validated on the target platform, not in your head.

SSRF is **in-band**: the answer has to come back through the tool's own
response, so nothing is opened to the outside. A blind SSRF is not detected.

SQL injection is **error-based** only. No timing inference, which is unreliable
over a network.

### Per target

| Probe | What it sends | Oracle |
|---|---|---|
| `session-fixation` | a session identifier the client invented | a server that mints sessions also adopts it |
| `header-injection` | a header value containing a carriage return | the smuggled header comes back |
| `protocol-fuzz` | ten malformed JSON-RPC messages | the server stops answering, or leaks a stack trace |

`session-fixation` is not reported for a stateless server. Revision 2026-07-28
removed sessions, so ignoring the header is correct there and flagging it would
fire on every modern server.

`header-injection` needs the request written by hand over a socket, because no
HTTP library will carry a control character in a header value, which is correct
of them and the reason the attack is worth testing. **Plaintext targets only.**
Over TLS this would mean driving the TLS stack directly; an `https://` target is
reported as not covered rather than quietly skipped.

`protocol-fuzz` is **gated**: it is the only probe that can take a target down,
so it runs only when an engagement names it. Nesting stops at 200 levels and the
oversized case at 64 KiB, enough to find a parser with no limit and far short of
being the outage it is looking for. It stops as soon as the target stops
answering, since there is nothing further to learn from a server that is no
longer there.

## Launching a local server

A `stdio:` target is executed. That cannot be made safe, only narrow:

* **No shell.** Command and arguments go to `exec` directly, so nothing in the
  engagement file is expanded, globbed or chained.
* **A minimal environment.** A short allowlist of what a process needs to start,
  plus what the engagement declares. The rest of the parent environment, which
  is where your credentials live, is not inherited.
* **A deadline**, and a kill on every exit path including a panic.
* **Bounded output** on both streams.

Not solved: the process runs with your privileges for as long as it lives, and
killing it does not kill what it spawned. The answer to that is an OS sandbox,
which is separate work.

`scan`, `view` and `discover` still never launch anything.
[`tests/enumerate.rs`](../tests/enumerate.rs) plants a config whose command
would create a witness file if it ever ran, runs the full scan pipeline, and
asserts the file never appears.

## Output

`--format terminal|json|sarif`, and `--policy` and `--fail-on` exactly as for
`scan`, so a rule accepted for a server is accepted whichever command found it.

The JSON output carries the engagement and the transcript path alongside the
findings. A report that does not say what was authorised, against what, and
where the evidence is, is not a deliverable.

## What is not covered

* Blind SSRF and blind command injection. Both need either an inbound socket or
  timing inference.
* TLS-level testing: certificate validity, protocol version, cipher selection.
* Header injection over TLS.
* A coverage summary of what was *not* tested, which for a pentest report
  matters as much as the findings.
