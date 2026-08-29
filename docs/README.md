# Documentation

* [How MCP works](mcp.md): enough of the protocol to follow what mcpwn does, with sources.
* [How the static checks work](detection.md): what each family reads, and what stops it firing on something ordinary.
* [How the active audit works](audit.md): the probes, their oracles, and the guards around them.
* [Using mcpwn in GitHub Actions](github-action.md).

The per-rule reference is not here: run `mcpwn explain` for the list and
`mcpwn explain <ID>` for one rule in full. There is a single rule catalogue, and
a second copy of it in a document would drift.
