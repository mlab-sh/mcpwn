//! Discovery + loading, against real files in a temporary directory.
//!
//! The headline case is `vscode_servers_key_is_parsed`: every client but VS Code
//! and Zed uses `mcpServers`, and assuming that key everywhere makes a VS Code
//! config silently load as zero servers.

use std::fs;
use std::path::{Path, PathBuf};

use mcpwn::discovery::{self, Client, ConfigFormat, HomeLayout, Scope};
use mcpwn::loading::{self, LoadStatus};
use mcpwn::manifest::Transport;

// --- temp dir helper (no dev-dependency) -----------------------------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static COUNTER: AtomicUsize = AtomicUsize::new(0);

        let unique = format!(
            "mcpwn-test-{}-{}-{}",
            tag,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Write `contents` to `rel`, creating parent directories.
    fn write(&self, rel: &str, contents: &str) -> PathBuf {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().expect("has parent")).expect("create parents");
        fs::write(&path, contents).expect("write fixture");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// --- fixtures ---------------------------------------------------------------

/// Claude Desktop / Cursor / Windsurf: object under `mcpServers`.
const CURSOR_CONFIG: &str = r#"{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "env": { "TOKEN": "xyz" }
    },
    "remote-api": { "url": "https://mcp.example.com/sse" }
  }
}"#;

/// VS Code: object under `servers`. The root-key trap.
const VSCODE_CONFIG: &str = r#"{
  "servers": {
    "github": { "command": "docker", "args": ["run", "ghcr.io/example/mcp"] },
    "sqlite": { "command": "uvx", "args": ["mcp-server-sqlite"] },
    "http-thing": { "type": "http", "url": "https://tools.example.com/mcp" }
  },
  "inputs": []
}"#;

/// Zed: object under `context_servers`, command nested as an object.
const ZED_CONFIG: &str = r#"{
  "theme": "One Dark",
  "context_servers": {
    "my-server": { "command": { "path": "node", "args": ["server.js"] } }
  }
}"#;

/// Continue: an *array* under `mcpServers`, each entry carrying its own name.
const CONTINUE_CONFIG: &str = r#"{
  "mcpServers": [
    { "name": "notion", "command": "npx", "args": ["-y", "notion-mcp"] },
    { "name": "slack", "command": "npx", "args": ["-y", "slack-mcp"] }
  ]
}"#;

// --- discovery --------------------------------------------------------------

#[test]
fn project_discovery_finds_the_dotfolder_configs() {
    let tmp = TempDir::new("project");
    tmp.write(".cursor/mcp.json", CURSOR_CONFIG);
    tmp.write(".vscode/mcp.json", VSCODE_CONFIG);
    tmp.write(".windsurf/mcp.json", CURSOR_CONFIG);
    tmp.write(".continue/config.yaml", "mcpServers: []\n");
    // Not a config file: must be ignored.
    tmp.write(".continue/README.md", "hello");

    let found = discovery::discover_project(tmp.path());

    assert_eq!(found.len(), 4, "found: {found:#?}");
    assert!(found.iter().all(|c| c.scope == Scope::Project));

    let clients: Vec<Client> = found.iter().map(|c| c.client).collect();
    assert!(clients.contains(&Client::Cursor));
    assert!(clients.contains(&Client::VsCode));
    assert!(clients.contains(&Client::Windsurf));
    assert!(clients.contains(&Client::Continue));

    let yaml = found
        .iter()
        .find(|c| c.format == ConfigFormat::Yaml)
        .expect("the Continue yaml config");
    assert_eq!(yaml.client, Client::Continue);
}

#[test]
fn discovery_on_an_empty_directory_finds_nothing_and_does_not_fail() {
    let tmp = TempDir::new("empty");
    assert!(discovery::discover_project(tmp.path()).is_empty());
}

#[test]
fn discovery_on_a_missing_directory_finds_nothing_and_does_not_fail() {
    let missing = std::env::temp_dir().join("mcpwn-does-not-exist-at-all");
    assert!(discovery::discover_project(&missing).is_empty());
}

#[test]
fn a_config_file_can_be_named_directly() {
    let tmp = TempDir::new("direct");
    let path = tmp.write(".cursor/mcp.json", CURSOR_CONFIG);

    let found = discovery::discover_project(&path);

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].client, Client::Cursor);
    assert_eq!(found[0].path, path);
}

#[test]
fn global_discovery_uses_the_injected_home_layout() {
    let tmp = TempDir::new("global");
    let layout = HomeLayout::rooted_at(tmp.path());

    // Nothing exists yet.
    assert!(discovery::discover_global_in(&layout).is_empty());

    // Materialise the Claude Desktop candidate for this platform's layout, plus
    // the OS-independent Cursor one.
    let claude = discovery::global_candidates(&layout)
        .into_iter()
        .find(|c| c.client == Client::ClaudeDesktop)
        .expect("a Claude Desktop candidate exists");
    fs::create_dir_all(claude.path.parent().expect("has parent")).expect("create parents");
    fs::write(&claude.path, CURSOR_CONFIG).expect("write claude config");
    tmp.write(".cursor/mcp.json", CURSOR_CONFIG);

    let found = discovery::discover_global_in(&layout);

    assert_eq!(found.len(), 2, "found: {found:#?}");
    assert!(found.iter().all(|c| c.scope == Scope::Global));
    assert!(found.iter().any(|c| c.path == claude.path));
    assert!(found.iter().any(|c| c.client == Client::Cursor));
}

#[test]
fn global_candidates_cover_every_documented_client() {
    let layout = HomeLayout::rooted_at("/nowhere");
    let candidates = discovery::global_candidates(&layout);

    for client in [
        Client::ClaudeDesktop,
        Client::Cursor,
        Client::Windsurf,
        Client::Continue,
        Client::Zed,
        Client::Codex,
        Client::VsCode,
    ] {
        assert!(
            candidates.iter().any(|c| c.client == client),
            "no global candidate for {client}"
        );
    }
    assert!(candidates.iter().all(|c| c.path.starts_with("/nowhere")));
}

// --- loading ----------------------------------------------------------------

#[test]
fn cursor_mcpservers_object_is_parsed() {
    let tmp = TempDir::new("load-cursor");
    tmp.write(".cursor/mcp.json", CURSOR_CONFIG);

    let loaded = loading::load_all(&discovery::discover_project(tmp.path()));
    assert_eq!(loaded.len(), 1);
    let entry = &loaded[0];

    assert_eq!(entry.status, LoadStatus::Parsed);
    assert_eq!(entry.servers.len(), 2);

    let fs_server = entry
        .servers
        .iter()
        .find(|s| s.name == "filesystem")
        .expect("filesystem server");
    match fs_server.transport.as_ref().expect("transport") {
        Transport::Stdio { command, args, env } => {
            assert_eq!(command, "npx");
            assert_eq!(args.len(), 3);
            assert_eq!(env.get("TOKEN").map(String::as_str), Some("xyz"));
        }
        other => panic!("expected stdio, got {other:?}"),
    }

    let remote = entry
        .servers
        .iter()
        .find(|s| s.name == "remote-api")
        .expect("remote server");
    assert!(matches!(
        remote.transport.as_ref().expect("transport"),
        Transport::Http { url } if url == "https://mcp.example.com/sse"
    ));

    // Config files declare launch methods, never tools.
    assert!(entry.servers.iter().all(|s| s.tools.is_empty()));
    assert!(entry.servers.iter().all(|s| s.origin.is_some()));
}

#[test]
fn vscode_servers_key_is_parsed() {
    let tmp = TempDir::new("load-vscode");
    tmp.write(".vscode/mcp.json", VSCODE_CONFIG);

    let loaded = loading::load_all(&discovery::discover_project(tmp.path()));
    assert_eq!(loaded.len(), 1);
    let entry = &loaded[0];

    assert_eq!(entry.config.client, Client::VsCode);
    assert_eq!(entry.status, LoadStatus::Parsed);
    assert_eq!(
        entry.servers.len(),
        3,
        "VS Code uses `servers`, not `mcpServers`"
    );

    let mut names: Vec<&str> = entry.servers.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["github", "http-thing", "sqlite"]);
}

#[test]
fn the_wrong_root_key_yields_nothing() {
    // The regression this test guards: parsing a VS Code config as if it were a
    // Cursor one finds no servers at all, silently.
    let as_cursor = loading::parse_json(VSCODE_CONFIG, Client::Cursor, Path::new("mcp.json"))
        .expect("valid json");
    assert!(as_cursor.is_empty());

    let as_vscode = loading::parse_json(VSCODE_CONFIG, Client::VsCode, Path::new("mcp.json"))
        .expect("valid json");
    assert_eq!(as_vscode.len(), 3);
}

#[test]
fn vscode_settings_json_nested_mcp_block_is_parsed() {
    let raw = r#"{ "editor.fontSize": 12, "mcp": { "servers": { "a": { "command": "x" } } } }"#;
    let servers =
        loading::parse_json(raw, Client::VsCode, Path::new("settings.json")).expect("valid json");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "a");
}

#[test]
fn zed_context_servers_key_and_nested_command_are_parsed() {
    let servers = loading::parse_json(ZED_CONFIG, Client::Zed, Path::new("settings.json"))
        .expect("valid json");

    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "my-server");
    match servers[0].transport.as_ref().expect("transport") {
        Transport::Stdio { command, args, .. } => {
            assert_eq!(command, "node");
            assert_eq!(args, &["server.js"]);
        }
        other => panic!("expected stdio, got {other:?}"),
    }
}

#[test]
fn continue_mcpservers_array_is_parsed() {
    let servers = loading::parse_json(CONTINUE_CONFIG, Client::Continue, Path::new("config.json"))
        .expect("valid json");

    let mut names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["notion", "slack"],
        "Continue uses an array, not an object"
    );
}

#[test]
fn unknown_client_falls_back_to_trying_every_root_key() {
    for raw in [CURSOR_CONFIG, VSCODE_CONFIG, ZED_CONFIG] {
        let servers =
            loading::parse_json(raw, Client::Unknown, Path::new("mcp.json")).expect("valid json");
        assert!(!servers.is_empty());
    }
}

// --- error paths ------------------------------------------------------------

#[test]
fn toml_and_yaml_are_detected_but_reported_as_unsupported() {
    let tmp = TempDir::new("unsupported");
    tmp.write(".continue/config.yaml", "mcpServers:\n  - name: x\n");

    let loaded = loading::load_all(&discovery::discover_project(tmp.path()));
    assert_eq!(loaded.len(), 1);

    match &loaded[0].status {
        LoadStatus::Unsupported { reason } => assert!(reason.contains("yaml")),
        other => panic!("expected Unsupported, got {other:?}"),
    }
    assert!(loaded[0].servers.is_empty());
}

#[test]
fn invalid_json_is_skipped_with_a_reason_and_the_others_still_load() {
    let tmp = TempDir::new("invalid");
    tmp.write(".cursor/mcp.json", "{ this is not json");
    tmp.write(".vscode/mcp.json", VSCODE_CONFIG);

    let loaded = loading::load_all(&discovery::discover_project(tmp.path()));
    assert_eq!(loaded.len(), 2);

    let broken = loaded
        .iter()
        .find(|l| l.config.client == Client::Cursor)
        .expect("the cursor entry");
    assert!(
        matches!(&broken.status, LoadStatus::Skipped { reason } if !reason.is_empty()),
        "got {:?}",
        broken.status
    );

    let ok = loaded
        .iter()
        .find(|l| l.config.client == Client::VsCode)
        .expect("the vscode entry");
    assert_eq!(ok.status, LoadStatus::Parsed);
    assert_eq!(ok.servers.len(), 3);

    // Only the good servers reach the analyzer.
    assert_eq!(loading::servers_of(&loaded).len(), 3);
}

#[test]
fn an_empty_or_server_less_config_is_valid() {
    for raw in ["{}", r#"{"mcpServers": {}}"#] {
        let servers =
            loading::parse_json(raw, Client::Cursor, Path::new("mcp.json")).expect("valid json");
        assert!(servers.is_empty());
    }
}

#[test]
fn a_server_block_of_the_wrong_type_is_an_error_not_a_panic() {
    let err = loading::parse_json(
        r#"{"mcpServers": "oops"}"#,
        Client::Cursor,
        Path::new("mcp.json"),
    )
    .expect_err("a string server block is invalid");
    assert!(err.to_string().contains("string"), "got: {err}");
}
