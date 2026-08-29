# Using mcpwn in GitHub Actions

The action lives in [`action.yml`](../action.yml) at the repository root.

**This example is documentation, not a workflow.** It deliberately does not live
in `.github/workflows/`: a file there runs, and an example that runs against
whatever repository it happens to be in is how a green pipeline turns red for no
reason. That is exactly what happened here once.

## A workflow to copy

```yaml
name: MCP security scan

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    # A remote server can change without your repository changing, so a scan
    # only on push would never see a rug pull.
    - cron: "0 6 * * 1"

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  mcpwn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mlab-sh/mcpwn@main
        with:
          path: .
          policy: mcpwn.toml
          lock: mcp.lock
          fail-on: high
```

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Directory to scan for MCP configurations |
| `policy` | none | Path to `mcpwn.toml`. Skipped with a notice if the file is absent |
| `lock` | none | Path to `mcp.lock`. Rug-pull detection is skipped if absent |
| `fail-on` | `high` | Lowest severity that fails the job |
| `sarif-file` | `mcpwn.sarif` | Where the SARIF report is written |
| `upload-sarif` | `true` | Upload to GitHub code scanning |

`policy` and `lock` are only passed through when the file exists. Naming a file
that is not there is an error in mcpwn, on purpose, and a CI job should not fail
because a baseline has not been recorded yet.

## Findings in the pull request

With `upload-sarif` on, findings appear as code-scanning alerts. Each carries
the same text as `mcpwn explain <ID>`, because both read the one rule catalogue,
and a toxic flow arrives as a clickable ingest to source to sink chain rather
than a line of prose.

The SARIF is uploaded even when the scan fails the job, so the alerts are there
to read rather than only a red cross.

## The schedule matters

Scanning only on push misses the case the lockfile exists for. A server can
change its tool descriptions with nothing changing in your repository, and a
weekly run is what notices. Record the baseline once with
`mcpwn scan --write-lock`, commit `mcp.lock`, and review its diff like any other
file.
