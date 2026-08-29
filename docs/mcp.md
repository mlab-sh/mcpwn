# How MCP works

Enough of the protocol to follow what mcpwn does and why. Everything here was
checked against the specification on 2026-08-28; sources are at the bottom.

## The shape of it

MCP connects a **host** (an application with a model in it) to **servers** that
expose capabilities. The host runs one **client** per server, and the model is
shown every tool of every connected server in one flat list.

That last point is the whole security story. The model does not see which server
a tool came from, and nothing in the protocol says what happens when two servers
offer the same tool name. A server is not just code you run: it is text injected
into the model's context, and text in a context is instructions.

Servers offer three kinds of thing. mcpwn only looks at **tools**, because tools
are what the model can invoke.

## The wire

Messages are JSON-RPC 2.0. Two transports are standard:

* **stdio**: newline-delimited JSON-RPC over the standard streams of a process
  the client launches.
* **Streamable HTTP**: one endpoint, one HTTP POST per message. The server
  answers with either a single JSON object or an SSE stream scoped to that
  request. A client must handle both.

Reading a stdio server's tool list means running the binary. That is why
`mcpwn scan` reports stdio servers as not enumerable, and why doing it anyway
lives behind `mcpwn audit` and an engagement file.

## What a tool looks like

`tools/list` returns entries of this shape:

```json
{
  "name": "read_file",
  "description": "Reads a file from disk.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": { "type": "string", "description": "Absolute path to read." }
    },
    "required": ["path"]
  }
}
```

Three fields matter, and all three are model-visible:

* **`name`**: how the model refers to the tool, and what collides when two
  servers pick the same one.
* **`description`**: free-form text the model reads as guidance. Nothing
  validates it. This is where poisoning and hidden instructions live.
* **`inputSchema`**: JSON Schema for the arguments. Its per-parameter
  `description` fields are read by the model exactly like the tool description
  is, which is why mcpwn scans them too.

`mcp.lock` hashes exactly these three, because they are what decides whether the
model calls the tool and with what.

## The 2026-07-28 change, and why the client is dual-era

The current revision made MCP **stateless**. The `initialize` /
`notifications/initialized` handshake was removed, and protocol-level sessions
went with it. Every request now carries its own version, client identity and
capabilities in `_meta`:

```json
"_meta": {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientInfo": { "name": "mcpwn", "version": "1.0.0" },
  "io.modelcontextprotocol/clientCapabilities": {}
}
```

On Streamable HTTP these are mirrored into headers so gateways can route without
parsing the body: `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` on calls.
The specification requires a server to reject a header that disagrees with the
body, which is what `MCPWN-NET-006` tests.

Plenty of deployed servers still speak the older handshake, so mcpwn tries the
stateless call first and falls back on a `400` whose body is not a recognised
modern error. This is not defensive coding for its own sake: of six live public
servers checked, two answered only the legacy path, and one of those also
required a session identifier the older revisions minted on `initialize`.

## The threat model in one paragraph

An agent holds several servers at once. One of them can bring in text an
attacker controls (a fetched page, an issue body, an incoming mail). Another can
read something private. A third can send data out. None of the three is wrong on
its own, and they may come from three different vendors. The instruction that
chains them arrives inside content, not inside code, which is why static
analysis of what servers *declare* is worth doing before anything is connected.

## Sources

Checked 2026-08-28.

* [Specification, current revision](https://modelcontextprotocol.io/specification/latest)
* [2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
  (statelessness, session removal, `_meta` fields, cacheable list results)
* [Transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
* [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
  (headers, header/body validation, backward compatibility)
* [Versioning and compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
  (the era model and the compatibility matrix)
* [UTS #39, Unicode Security Mechanisms](https://www.unicode.org/reports/tr39/)
  (confusables and mixed-script detection, used by the obfuscation checks)
