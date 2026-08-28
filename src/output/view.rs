//! `mcpwn view`: read what a server actually exposes.
//!
//! No analysis, no findings, no judgement. `scan` tells you what is wrong;
//! this tells you what is there. It is the command for answering "what can this
//! server do, exactly?" before deciding whether to connect it at all.

use std::io::{self, Write};

use owo_colors::{OwoColorize, Style};

use crate::analysis::schema::{self, Param};
use crate::enumerate::{EnumeratedServer, Enumeration};
use crate::manifest::ToolManifest;

/// Width the prose is wrapped to. Descriptions are the whole point of this
/// command, so they are wrapped rather than truncated.
const WIDTH: usize = 96;

/// Renders an inventory of servers, tools and parameters.
#[derive(Debug, Clone)]
pub struct ViewRenderer {
    color: bool,
    verbose: bool,
    /// Show only tools whose name contains this, case-insensitively.
    filter: Option<String>,
}

impl Default for ViewRenderer {
    fn default() -> Self {
        Self {
            color: true,
            verbose: false,
            filter: None,
        }
    }
}

impl ViewRenderer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn color(mut self, color: bool) -> Self {
        self.color = color;
        self
    }

    /// Also print the raw `inputSchema` of every tool.
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn filter(mut self, filter: Option<String>) -> Self {
        self.filter = filter.map(|f| f.to_lowercase());
        self
    }

    pub fn render<W: Write>(&self, servers: &[EnumeratedServer], out: &mut W) -> io::Result<()> {
        if servers.is_empty() {
            return writeln!(out, "no server to view");
        }

        let mut shown = 0usize;
        for (i, entry) in servers.iter().enumerate() {
            if i > 0 {
                writeln!(out)?;
            }
            shown += self.server(entry, out)?;
        }

        writeln!(out)?;
        if let Some(filter) = &self.filter {
            writeln!(out, "{shown} tool(s) matching `{filter}`")
        } else {
            writeln!(out, "{} server(s), {shown} tool(s)", servers.len())
        }
    }

    /// Returns how many tools were printed.
    fn server<W: Write>(&self, entry: &EnumeratedServer, out: &mut W) -> io::Result<usize> {
        writeln!(
            out,
            "{}",
            self.paint(&entry.server.name, Style::new().bold().cyan())
        )?;

        let transport = entry
            .server
            .transport
            .as_ref()
            .map(|t| t.summary())
            .unwrap_or_else(|| "(no launch method)".to_owned());
        writeln!(out, "  {}", self.paint(transport, Style::new().dimmed()))?;

        match &entry.outcome {
            Enumeration::Enumerated { protocol } => {
                writeln!(
                    out,
                    "  {}",
                    self.paint(
                        format!("{} tool(s) via MCP {protocol}", entry.server.tools.len()),
                        Style::new().dimmed()
                    )
                )?;
            }
            Enumeration::NotPossible { reason } => {
                writeln!(out, "  {}", self.paint(reason, Style::new().dimmed()))?;
                return Ok(0);
            }
            Enumeration::Failed { reason } => {
                writeln!(out, "  {}", self.paint(reason, Style::new().red()))?;
                return Ok(0);
            }
        }

        let tools: Vec<&ToolManifest> = entry
            .server
            .tools
            .iter()
            .filter(|tool| match &self.filter {
                Some(filter) => tool.name.to_lowercase().contains(filter),
                None => true,
            })
            .collect();

        for tool in &tools {
            writeln!(out)?;
            self.tool(tool, out)?;
        }
        Ok(tools.len())
    }

    fn tool<W: Write>(&self, tool: &ToolManifest, out: &mut W) -> io::Result<()> {
        writeln!(out, "  {}", self.paint(&tool.name, Style::new().bold()))?;

        let described = !tool.description.trim().is_empty();
        for line in wrap(&tool.description, WIDTH - 4) {
            // A blank line stays blank: trailing indent is invisible noise that
            // shows up in every diff and every copy-paste.
            if line.is_empty() {
                writeln!(out)?;
            } else {
                writeln!(out, "    {line}")?;
            }
        }

        let Some(input_schema) = tool.input_schema.as_ref() else {
            writeln!(
                out,
                "    {}",
                self.paint("(no input schema)", Style::new().dimmed())
            )?;
            return Ok(());
        };

        // Descriptions run to dozens of lines on real servers, so the
        // parameters need a boundary rather than following straight on.
        if described {
            writeln!(out)?;
        }

        let flattened = schema::flatten(input_schema);
        if flattened.is_empty() {
            writeln!(
                out,
                "    {}",
                self.paint("no parameters", Style::new().dimmed())
            )?;
        } else {
            writeln!(
                out,
                "    {}",
                self.paint("parameters", Style::new().dimmed())
            )?;
            self.params(flattened.params.as_slice(), out)?;
            if flattened.truncated {
                writeln!(
                    out,
                    "    {}",
                    self.paint(
                        "(schema truncated: too deep or too large)",
                        Style::new().yellow()
                    )
                )?;
            }
        }

        if self.verbose {
            writeln!(
                out,
                "    {}",
                self.paint("inputSchema", Style::new().dimmed())
            )?;
            let pretty = serde_json::to_string_pretty(input_schema)
                .unwrap_or_else(|_| input_schema.to_string());
            for line in pretty.lines() {
                writeln!(out, "      {line}")?;
            }
        }
        Ok(())
    }

    fn params<W: Write>(&self, params: &[Param], out: &mut W) -> io::Result<()> {
        let name_width = params
            .iter()
            .map(|p| p.path.len())
            .max()
            .unwrap_or(0)
            .min(32);
        let type_width = params
            .iter()
            .map(|p| type_label(p).len())
            .max()
            .unwrap_or(0)
            .min(16);

        for param in params {
            // An object with its own properties is a heading for the ones
            // below it, not a value the caller passes.
            let required = if param.required {
                self.paint("required", Style::new().yellow())
            } else {
                self.paint("optional", Style::new().dimmed())
            };

            writeln!(
                out,
                "    {:<name_width$}  {:<type_width$}  {}",
                self.paint(&param.path, Style::new().green()),
                self.paint(type_label(param), Style::new().dimmed()),
                required,
            )?;

            let indent = 6;
            if let Some(description) = &param.description {
                for line in wrap(description, WIDTH - indent) {
                    if line.is_empty() {
                        writeln!(out)?;
                    } else {
                        writeln!(out, "{:indent$}{line}", "")?;
                    }
                }
            }
            if !param.enum_values.is_empty() {
                for line in wrap(
                    &format!("one of: {}", param.enum_values.join(", ")),
                    WIDTH - indent,
                ) {
                    writeln!(
                        out,
                        "{:indent$}{}",
                        "",
                        self.paint(line, Style::new().dimmed())
                    )?;
                }
            }
            if let Some(header) = &param.header_name {
                writeln!(
                    out,
                    "{:indent$}{}",
                    "",
                    self.paint(
                        format!("sent as the HTTP header Mcp-Param-{header}"),
                        Style::new().yellow()
                    )
                )?;
            }
        }
        Ok(())
    }

    fn paint(&self, text: impl std::fmt::Display, style: Style) -> String {
        if self.color {
            format!("{}", text.style(style))
        } else {
            text.to_string()
        }
    }
}

/// `string`, `string[]`, `object`, or `?` when the schema does not say.
fn type_label(param: &Param) -> String {
    match (param.ty.as_deref(), param.item_ty.as_deref()) {
        (Some("array"), Some(item)) => format!("{item}[]"),
        (Some("array"), None) => "array".to_owned(),
        (Some(ty), _) => ty.to_owned(),
        (None, _) => "?".to_owned(),
    }
}

/// Word-wrap, preserving the paragraph breaks the server wrote.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for paragraph in text.lines() {
        if paragraph.trim().is_empty() {
            out.push(String::new());
            continue;
        }
        let mut line = String::new();
        for word in paragraph.split_whitespace() {
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        if !line.is_empty() {
            out.push(line);
        }
    }
    out
}
