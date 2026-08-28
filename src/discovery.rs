//! Step 1 of two: **find** MCP configuration files on disk.
//!
//! This module only locates and classifies files: it never opens them. Turning
//! a [`DiscoveredConfig`] into servers is [`crate::loading`]'s job.
//!
//! Two modes:
//!
//! * [`discover_global`]: the well-known per-user locations, per OS.
//! * [`discover_project`]: the project-level dotfolders under a repo root.
//!
//! A missing file is the normal case, not an error: candidates that do not
//! exist are simply dropped.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Which client owns a configuration file. Determines the root key used when
/// loading it, so misclassifying means parsing the wrong shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Client {
    ClaudeDesktop,
    Cursor,
    Windsurf,
    Continue,
    Zed,
    Codex,
    VsCode,
    /// Recognised as a config-shaped file, but the owner is unknown; loading
    /// falls back to trying every known root key.
    Unknown,
}

impl Client {
    pub fn label(self) -> &'static str {
        match self {
            Client::ClaudeDesktop => "Claude Desktop",
            Client::Cursor => "Cursor",
            Client::Windsurf => "Windsurf",
            Client::Continue => "Continue",
            Client::Zed => "Zed",
            Client::Codex => "Codex",
            Client::VsCode => "VS Code",
            Client::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Whether a config applies to the whole user account or to one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Global,
    Project,
}

impl Scope {
    pub fn label(self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::Project => "project",
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Serialisation format of a config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigFormat {
    Json,
    Toml,
    Yaml,
}

impl ConfigFormat {
    pub fn label(self) -> &'static str {
        match self {
            ConfigFormat::Json => "json",
            ConfigFormat::Toml => "toml",
            ConfigFormat::Yaml => "yaml",
        }
    }

    /// Whether [`crate::loading`] can parse this format yet.
    ///
    /// Only JSON in v1: see the module docs of [`crate::loading`].
    pub fn is_supported(self) -> bool {
        matches!(self, ConfigFormat::Json)
    }

    fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
            "json" | "jsonc" => Some(ConfigFormat::Json),
            "toml" => Some(ConfigFormat::Toml),
            "yaml" | "yml" => Some(ConfigFormat::Yaml),
            _ => None,
        }
    }
}

impl std::fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// One configuration file that exists on disk.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DiscoveredConfig {
    pub path: PathBuf,
    pub client: Client,
    pub scope: Scope,
    pub format: ConfigFormat,
}

impl DiscoveredConfig {
    pub fn new(path: PathBuf, client: Client, scope: Scope, format: ConfigFormat) -> Self {
        Self {
            path,
            client,
            scope,
            format,
        }
    }
}

/// The user-specific directories discovery resolves against.
///
/// Split out of the environment so tests can point discovery at a fake home
/// instead of the machine's real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeLayout {
    /// `$HOME` / `%USERPROFILE%`.
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`, else `~/.config`. Also used on macOS for the clients
    /// that ignore the platform convention (Zed).
    pub config: PathBuf,
    /// macOS `~/Library/Application Support`.
    pub app_support: Option<PathBuf>,
    /// Windows `%APPDATA%`.
    pub appdata: Option<PathBuf>,
}

impl HomeLayout {
    /// Resolve from the environment. `None` when the home directory cannot be
    /// determined, in which case global discovery finds nothing.
    pub fn from_env() -> Option<Self> {
        let home = home_from_env()?;
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        let app_support = if cfg!(target_os = "macos") {
            Some(home.join("Library").join("Application Support"))
        } else {
            None
        };
        let appdata = std::env::var_os("APPDATA").map(PathBuf::from);

        Some(Self {
            home,
            config,
            app_support,
            appdata,
        })
    }

    /// A layout rooted entirely at `home`, for tests.
    pub fn rooted_at(home: impl Into<PathBuf>) -> Self {
        let home: PathBuf = home.into();
        Self {
            config: home.join(".config"),
            app_support: Some(home.join("Library").join("Application Support")),
            appdata: Some(home.join("AppData").join("Roaming")),
            home,
        }
    }
}

fn home_from_env() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Every global path worth probing, whether or not it exists.
///
/// Exposed so `mcpwn discover --verbose` can show what was looked at, and so
/// tests can materialise a candidate before running discovery.
pub fn global_candidates(layout: &HomeLayout) -> Vec<DiscoveredConfig> {
    let mut out = Vec::new();
    let mut push = |path: PathBuf, client: Client, format: ConfigFormat| {
        out.push(DiscoveredConfig::new(path, client, Scope::Global, format));
    };

    // Claude Desktop: one location per OS.
    if let Some(app_support) = &layout.app_support {
        push(
            app_support
                .join("Claude")
                .join("claude_desktop_config.json"),
            Client::ClaudeDesktop,
            ConfigFormat::Json,
        );
    }
    if let Some(appdata) = &layout.appdata {
        push(
            appdata.join("Claude").join("claude_desktop_config.json"),
            Client::ClaudeDesktop,
            ConfigFormat::Json,
        );
    }
    push(
        layout
            .config
            .join("Claude")
            .join("claude_desktop_config.json"),
        Client::ClaudeDesktop,
        ConfigFormat::Json,
    );

    push(
        layout.home.join(".cursor").join("mcp.json"),
        Client::Cursor,
        ConfigFormat::Json,
    );
    push(
        layout
            .home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json"),
        Client::Windsurf,
        ConfigFormat::Json,
    );
    push(
        layout.home.join(".continue").join("config.json"),
        Client::Continue,
        ConfigFormat::Json,
    );
    push(
        layout.home.join(".continue").join("config.yaml"),
        Client::Continue,
        ConfigFormat::Yaml,
    );
    // Zed uses ~/.config/zed on every platform, macOS included.
    push(
        layout.config.join("zed").join("settings.json"),
        Client::Zed,
        ConfigFormat::Json,
    );
    push(
        layout.home.join(".codex").join("config.toml"),
        Client::Codex,
        ConfigFormat::Toml,
    );

    // VS Code: best effort. `mcp.json` in the user profile directory is the
    // location observed on current builds, and the directory itself follows the
    // usual per-OS settings path.
    //
    // TODO(vscode): unverified cases deliberately NOT guessed,
    //   * MCP servers declared inline in `settings.json` under `"mcp": {"servers": ...}`
    //     (the loader already accepts that shape, discovery just does not probe it);
    //   * Insiders / OSS / portable-mode installs (`Code - Insiders`, `VSCodium`,
    //     `data/user-data` next to the binary);
    //   * workspace-storage copies of the user config.
    // Confirm each against a real install before adding it here.
    for dir in vscode_user_dirs(layout) {
        push(dir.join("mcp.json"), Client::VsCode, ConfigFormat::Json);
    }

    out
}

fn vscode_user_dirs(layout: &HomeLayout) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(app_support) = &layout.app_support {
        dirs.push(app_support.join("Code").join("User"));
    }
    if let Some(appdata) = &layout.appdata {
        dirs.push(appdata.join("Code").join("User"));
    }
    dirs.push(layout.config.join("Code").join("User"));
    dirs
}

/// The project-level candidates under `root`.
pub fn project_candidates(root: &Path) -> Vec<DiscoveredConfig> {
    let mut out = vec![
        DiscoveredConfig::new(
            root.join(".cursor").join("mcp.json"),
            Client::Cursor,
            Scope::Project,
            ConfigFormat::Json,
        ),
        DiscoveredConfig::new(
            root.join(".vscode").join("mcp.json"),
            Client::VsCode,
            Scope::Project,
            ConfigFormat::Json,
        ),
        DiscoveredConfig::new(
            root.join(".windsurf").join("mcp.json"),
            Client::Windsurf,
            Scope::Project,
            ConfigFormat::Json,
        ),
    ];

    // `.continue/` holds imported configs rather than one fixed file: the
    // top-level config plus whatever lives in `mcpServers/`.
    let continue_dir = root.join(".continue");
    out.extend(continue_files(&continue_dir));

    out
}

/// Config-shaped files directly inside `.continue/` and `.continue/mcpServers/`.
fn continue_files(dir: &Path) -> Vec<DiscoveredConfig> {
    let mut out = Vec::new();
    for sub in [dir.to_path_buf(), dir.join("mcpServers")] {
        let Ok(entries) = std::fs::read_dir(&sub) else {
            // Missing or unreadable: nothing to collect, and not an error.
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(format) = ConfigFormat::from_path(&path) {
                out.push(DiscoveredConfig::new(
                    path,
                    Client::Continue,
                    Scope::Project,
                    format,
                ));
            }
        }
    }
    out
}

/// Global discovery against the real environment.
pub fn discover_global() -> Vec<DiscoveredConfig> {
    match HomeLayout::from_env() {
        Some(layout) => discover_global_in(&layout),
        None => Vec::new(),
    }
}

/// Global discovery against an explicit layout.
pub fn discover_global_in(layout: &HomeLayout) -> Vec<DiscoveredConfig> {
    finish(global_candidates(layout))
}

/// Project discovery under `root`.
///
/// If `root` is a file rather than a directory it is classified directly, so
/// `mcpwn discover ./some/mcp.json` works.
pub fn discover_project(root: &Path) -> Vec<DiscoveredConfig> {
    if root.is_file() {
        return match classify_file(root) {
            Some(config) => vec![config],
            None => Vec::new(),
        };
    }
    finish(project_candidates(root))
}

/// Classify an explicitly named file from its path.
pub fn classify_file(path: &Path) -> Option<DiscoveredConfig> {
    let format = ConfigFormat::from_path(path)?;
    let name = path.file_name()?.to_str()?;
    let parent = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let client = match (name, parent.as_str()) {
        ("claude_desktop_config.json", _) => Client::ClaudeDesktop,
        (_, ".cursor" | "cursor") => Client::Cursor,
        (_, ".vscode" | "user") => Client::VsCode,
        (_, ".windsurf" | "windsurf") => Client::Windsurf,
        (_, ".continue" | "continue" | "mcpservers") => Client::Continue,
        (_, "zed") => Client::Zed,
        (_, ".codex" | "codex") => Client::Codex,
        _ => Client::Unknown,
    };

    Some(DiscoveredConfig::new(
        path.to_path_buf(),
        client,
        Scope::Project,
        format,
    ))
}

/// Keep the candidates that exist, de-duplicate, and order deterministically.
///
/// A path whose existence cannot be determined (typically a permission error on
/// a parent directory) is kept: [`crate::loading`] will surface the real error
/// with its path instead of the file vanishing silently.
fn finish(candidates: Vec<DiscoveredConfig>) -> Vec<DiscoveredConfig> {
    let mut out: Vec<DiscoveredConfig> = candidates
        .into_iter()
        .filter(|c| c.path.try_exists().unwrap_or(true))
        .collect();
    out.sort();
    out.dedup_by(|a, b| a.path == b.path);
    out
}
