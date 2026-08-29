# How the static checks work

What each family reads, what makes it fire, and what stops it firing on
something ordinary. The per-rule reference is `mcpwn explain <ID>`; this is the
machinery behind it.

There is one rule catalogue, in [`src/explain.rs`](../src/explain.rs). The
terminal output, the SARIF descriptors and `mcpwn explain` all read it, and two
tests fail the build if a rule the code can emit is undocumented or if a
documented severity stops matching the one actually produced. Documentation that
drifts from the code is worse than none, because it is trusted.

## The pipeline

Three levels, because the detections do not all look at the same thing.

| Trait | Sees | Used by |
|---|---|---|
| `ServerCheck` | one server's configuration | secrets, pinning, transport, reconnaissance |
| `ToolCheck` | one tool | capabilities, obfuscation |
| `GlobalCheck` | every tool of every server | toxic flows, shadowing, rug pull |

Global checks run last and receive what the per-tool pass produced. That
ordering is a guarantee, not an accident: the toxic-flow check reads the
capabilities already found rather than re-analysing every schema.

Adding a detection is one line in
[`Registry::builtin`](../src/analysis/registry.rs). The analyzer never names a
check and no renderer knows any check exists.

## Configuration checks

The only checks that say anything about **stdio servers**, whose tools are never
enumerated. They read the config and never run it.

**Secrets** match on published issuer prefixes (`ghp_`, `sk-ant-`, `AKIA`,
`xoxb-`, and so on), or on a credential-shaped variable name holding a long,
high-entropy value. Placeholders are excluded, including AWS's own documented
sample key, and no finding prints more than the first four characters of a
value. A test asserts the secret never reaches the output.

**Pinning** catches `npx -y pkg`, which downloads and executes fresh code at
every launch. This is the rug pull that needs no malicious server: the package
maintainer changes what runs, and `mcp.lock` cannot see it because the code can
change while the tool list stays byte-identical. Scoped packages are parsed
correctly, since the leading `@` of `@scope/name` is not a version separator.

## Capability analysis

Walks a tool's `inputSchema` and reports what its parameters let the tool do:
run commands, evaluate code, reach the filesystem or the network, or be mirrored
into an HTTP header through `x-mcp-header`.

A capability is a statement of attack surface, not an accusation. A tool named
`run_command` taking a `command` string is reported, and that is correct.

Three rules keep the noise down, all in the pattern table in
[`capabilities.rs`](../src/analysis/capabilities.rs):

* **Names are tokenised, not substring-matched.** `recommendation` does not
  contain the token `command`; `curl_options` does not contain `url`.
* **Only text-carrying parameters qualify.** A boolean `dry_run` cannot hold a
  command line.
* **Some names need their description to agree.** `query` is the most common
  parameter name in search tools and counts only when the description says SQL
  or GraphQL.

Calibrated against six live public servers. The first run produced four
false-positive criticals; those three rules cut it to a single true positive.
Both regressions are pinned by tests.

## Normalisation, and why it exists separately

[`normalize::normalize`](../src/analysis/normalize.rs) turns raw text into a
`cleaned` string plus a report of what was found. **Every semantic analyser
reads `cleaned`, never the raw text.** Poisoning and shadowing detection match
on words, and one zero-width space dropped inside a keyword defeats any matcher
run on the raw string. Normalising once closes that door for every check.

What is removed versus only reported:

* **Removed**: invisibles, bidi controls, tag characters, stray control
  characters. They carry no meaning in a description. `cleaned` then goes
  through NFKC, so fullwidth and ligature forms compare equal downstream.
* **Only reported**: homoglyphs. The UTS #39 skeleton transform is lossy by
  design, `skeleton("l") == skeleton("1")`, so applying it to `cleaned` would
  corrupt legitimate non-Latin text and invent matches. `normalize::skeleton` is
  exposed for callers that want confusable-insensitive comparison of one token.

The lockfile does the **opposite** on purpose: it hashes raw text with no
normalisation, because adding a zero-width character *is* a mutation and
normalising first would hide exactly that. Normalisation exists so a matcher
cannot be evaded; the lock exists so a change cannot be hidden.

## Obfuscation

Text a human reviewer and a model do not read the same. Applied to every
model-visible string: tool name, tool description, and the names and
descriptions of every parameter.

Unicode tag characters sit alone at Critical. The U+E0000 block mirrors
printable ASCII as invisible codepoints, has no use in prose, and text hidden
there was put there to be read by a model and not by a person. mcpwn **decodes
the payload** and quotes it.

Mixed script is the one kind with a real false-positive story, so it is narrow:
the signal is a mix **inside one word**, never the presence of non-Latin text. A
description written entirely in Russian is ordinary. The finding names only the
letters in the minority script, so `updаte_config` reports the single Cyrillic
`а` rather than all ten letters.

## Rug pull

`mcp.lock` records what each tool looked like when it was approved. The digest
covers **name, description and inputSchema**: what the model reads and what
decides whether it calls the tool.

Two decisions define what "changed" means:

* **Canonical serialisation before hashing.** Keys sorted recursively,
  whitespace dropped, so a reformat is not a mutation. Written by hand rather
  than relying on `serde_json::Map` being a `BTreeMap`, because that ordering is
  a feature flag any dependency could flip through feature unification, silently
  changing every hash.
* **Raw text, no normalisation**, as above.

Detection never writes. A plain scan reads the lock and never touches it, and
`--update-lock` is the only way to bless a change, after printing it. A scan
that refreshed the baseline as it went would erase the mutation it just found.

A server that failed to enumerate is skipped on both sides: not compared, since
an unreachable endpoint must not read as "every tool was removed", and not
written, since one network failure plus `--update-lock` would erase the
baseline.

## Shadowing

Two mechanisms. **Name collision**, where two servers expose the same tool name
or names that fold onto one another once invisibles, separators, case and
confusables are resolved. And **cross-server instruction**, where one server's
text names a tool belonging to another, which lets it change how a tool it does
not own gets called.

Three guards:

* Servers are compared by **transport identity**, not by their configuration
  key, so the same endpoint declared twice is one server rather than its own
  shadow.
* **References within one server are ordinary.** Context7's `query-docs` tells
  the model to call `resolve-library-id` first; flagging that would be wrong
  about a real, legitimate server.
* **Only distinctive names are hunted for in prose.** A tool called `search`
  would otherwise match every description using the word, and a name is matched
  at identifier boundaries, so `read_file` is not found inside
  `thread_read_filename`.

## Toxic flows

The first global check. No tool is dangerous alone; the risk is three roles
coexisting:

```
  ingest   untrusted content enters the context and can steer the model
     |
     v
  source   private state is read
     |
     v
  sink     it leaves
```

Roles are not decided by a flat keyword list, because the same verb means
opposite things depending on its object: `read_file` reads private local state,
`read_wiki_contents` pulls in a third party's text. The table in
[`roles.rs`](../src/analysis/roles.rs) is two-dimensional, a verb and an object,
and the role falls out of the pair.

The hard case is a URL parameter, which can mean a GET that pulls content in or
a POST that pushes data out. Resolution order is an explicit HTTP method in the
schema, then the verb in the name, then the description. **When none of them
settles it the tool is tagged as both, ambiguously**: a missed flow is a scanner
that failed, an over-reported one is a chain someone checks for a minute. The
guess is not hidden, it downgrades the finding from Critical to High.

**One finding, not N cubed.** Five tools per role is 125 triples all saying the
same thing. The risk is a property of the environment, so the check emits at
most one finding carrying a representative chain and listing every candidate per
role as evidence.

Missing any one role means no finding. Source and sink with **no ingest** is not
a flow: without untrusted content entering, nothing steers the agent into it.

## Reconnaissance

Six checks behind `--probe`, all read-only, none calling a tool. Two of them
test rules the specification states as MUSTs, which are the most useful findings
in the family: a server that skips them is telling you something about how
carefully the rest of it was written.

The probe sends two requests deliberately **without** credentials: the anonymous
check, whose point is to see what an unauthenticated party gets, and the
plaintext check, because sending a bearer token over `http://` to find out
whether `http://` works would leak it.

`MCPWN-NET-001` only fires when a credential **was** supplied. A server that is
simply public is not a finding, and reporting one would flag every public
documentation server in existence.

`--probe` is off by default. A plain scan sends one request per server; probing
touches paths you did not name.
