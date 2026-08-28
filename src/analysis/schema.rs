//! Walking a tool's JSON Schema (`inputSchema`) into a flat list of parameters.
//!
//! This module only *flattens*; deciding what a parameter means is
//! [`super::capabilities`]' job. Two things matter here: what the schema
//! declares (names, types, constraints) and what its `description` fields say,
//! since those are read by the model exactly like the tool description is.
//!
//! The schema comes from an untrusted server, so the walk is bounded on every
//! axis: nesting depth, total parameters, and it never resolves `$ref`.

use serde_json::Value;

/// How deep into nested objects the walk goes.
///
/// Real tool schemas are one or two levels deep. Anything deeper is either
/// generated or deliberately hiding a parameter from a shallow reader, and the
/// truncation is reported via [`Flattened::truncated`] rather than hidden.
pub const MAX_DEPTH: usize = 8;

/// Upper bound on parameters collected from one schema, so a hostile server
/// cannot make a scan allocate without limit.
pub const MAX_PARAMS: usize = 512;

/// A flattened view of one parameter of an input schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// Dotted path from the schema root, e.g. `options.path`. Array element
    /// schemas appear as `args[]`.
    pub path: String,
    /// The leaf name only, e.g. `path`.
    pub name: String,
    /// JSON Schema `type`, when declared.
    pub ty: Option<String>,
    /// For arrays, the declared item type, e.g. `Some("string")` for `string[]`.
    pub item_ty: Option<String>,
    /// Whether the parent object lists it in `required`.
    pub required: bool,
    /// Per-parameter description: model-visible, therefore attacker-usable.
    pub description: Option<String>,
    /// Values from an `enum` constraint. A constrained parameter cannot carry
    /// arbitrary input, which lowers the severity of whatever it enables.
    pub enum_values: Vec<String>,
    /// JSON Schema `format`, e.g. `uri`, `hostname`.
    pub format: Option<String>,
    /// Value of the `x-mcp-header` annotation, if present. Per the MCP spec a
    /// property carrying it has its value mirrored into an HTTP request header.
    pub header_name: Option<String>,
    /// Nesting depth, 0 for a top-level property.
    pub depth: usize,
}

impl Param {
    /// Whether this parameter can carry free-form text.
    ///
    /// The capability patterns only apply to text-ish parameters: a boolean
    /// `dry_run` or an integer `run_id` cannot carry a command line, and
    /// excluding them removes a whole class of false positives for free.
    pub fn is_texty(&self) -> bool {
        match self.ty.as_deref() {
            Some("string") => true,
            Some("array") => matches!(self.item_ty.as_deref(), None | Some("string")),
            // An undeclared type is permissive: JSON Schema allows anything.
            None => true,
            Some("object") => false,
            _ => false,
        }
    }

    /// Whether an `enum` restricts the value to a known set.
    pub fn is_constrained(&self) -> bool {
        !self.enum_values.is_empty()
    }
}

/// The result of flattening one schema.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flattened {
    pub params: Vec<Param>,
    /// True when a bound was hit and part of the schema was not walked.
    pub truncated: bool,
}

impl Flattened {
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Param> {
        self.params.iter()
    }
}

/// Walk an input schema and flatten it into [`Param`]s.
pub fn flatten(schema: &Value) -> Flattened {
    let mut out = Flattened::default();
    walk(schema, "", 0, &mut out);
    out
}

fn walk(schema: &Value, prefix: &str, depth: usize, out: &mut Flattened) {
    if depth > MAX_DEPTH {
        out.truncated = true;
        return;
    }
    let Some(object) = schema.as_object() else {
        return;
    };

    let required: Vec<&str> = object
        .get("required")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();

    let Some(properties) = object.get("properties").and_then(Value::as_object) else {
        return;
    };

    for (name, node) in properties {
        if out.params.len() >= MAX_PARAMS {
            out.truncated = true;
            return;
        }

        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };
        let param = param_from(name, &path, node, required.contains(&name.as_str()), depth);
        let ty = param.ty.clone();
        out.params.push(param);

        match ty.as_deref() {
            // A nested object carries its own properties.
            Some("object") | None => walk(node, &path, depth + 1, out),
            // An array of objects hides its properties one level further down.
            Some("array") => {
                if let Some(items) = node.get("items") {
                    walk(items, &format!("{path}[]"), depth + 1, out);
                }
            }
            _ => {}
        }
    }
}

fn param_from(name: &str, path: &str, node: &Value, required: bool, depth: usize) -> Param {
    Param {
        path: path.to_owned(),
        name: name.to_owned(),
        ty: node.get("type").and_then(Value::as_str).map(str::to_owned),
        item_ty: node
            .get("items")
            .and_then(|items| items.get("type"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        required,
        description: node
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned),
        enum_values: node
            .get("enum")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        format: node
            .get("format")
            .and_then(Value::as_str)
            .map(str::to_owned),
        header_name: node
            .get("x-mcp-header")
            .and_then(Value::as_str)
            .map(str::to_owned),
        depth,
    }
}
