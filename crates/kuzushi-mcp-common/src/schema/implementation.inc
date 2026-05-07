use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Position {
    pub file: PathBuf,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl Position {
    pub fn new(file: impl Into<PathBuf>, line: u32) -> Self {
        Self {
            file: file.into(),
            line,
            column: None,
        }
    }

    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

impl Range {
    pub fn single_line(file: impl Into<PathBuf>, line: u32) -> Self {
        let pos = Position::new(file, line);
        Self {
            start: pos.clone(),
            end: pos,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    Function,
    Method,
    Macro,
    Variable,
    Field,
    Class,
    Struct,
    Enum,
    Interface,
    TypeAlias,
    Module,
    Namespace,
    Constant,
    Parameter,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub location: Range,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Method {
    pub symbol: Symbol,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<MethodParameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MethodParameter {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// A short snippet of source attached to a symbol or location — useful for
/// caller/callee result presentation without forcing the consumer to re-read
/// the file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FileSpan {
    pub range: Range,
    pub snippet: String,
}

/// Kind of edge connecting two positions in a `Path`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Call,
    ReachingDef,
    DataDependence,
    ControlFlow,
    Includes,
    References,
}

/// A taint / dataflow path returned by joern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Path {
    pub steps: Vec<Position>,
    pub edges: Vec<EdgeKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn position_serializes_with_camel_case() {
        let p = Position::new("/tmp/foo.rs", 12).with_column(5);
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["file"], json!("/tmp/foo.rs"));
        assert_eq!(v["line"], json!(12));
        assert_eq!(v["column"], json!(5));
    }

    #[test]
    fn position_round_trips_without_column() {
        let p = Position::new("/x.rs", 1);
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("column").is_none());
        let back: Position = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn symbol_kind_serializes_lowercase() {
        let v = serde_json::to_value(SymbolKind::Function).unwrap();
        assert_eq!(v, json!("function"));
        let v = serde_json::to_value(SymbolKind::TypeAlias).unwrap();
        assert_eq!(v, json!("type_alias"));
    }

    #[test]
    fn method_round_trips() {
        let m = Method {
            symbol: Symbol {
                name: "recv_msg".to_string(),
                kind: SymbolKind::Function,
                location: Range::single_line("/src/net.c", 42),
                qualifier: None,
                language: Some("c".to_string()),
            },
            signature: "int recv_msg(int fd, struct msg *m)".to_string(),
            return_type: Some("int".to_string()),
            parameters: vec![],
        };
        let v = serde_json::to_value(&m).unwrap();
        let back: Method = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn path_includes_edges_in_order() {
        let path = Path {
            steps: vec![
                Position::new("/a.c", 1),
                Position::new("/a.c", 2),
                Position::new("/b.c", 3),
            ],
            edges: vec![EdgeKind::DataDependence, EdgeKind::Call],
            source: Some("argv".to_string()),
            sink: Some("system".to_string()),
        };
        let v = serde_json::to_value(&path).unwrap();
        let back: Path = serde_json::from_value(v).unwrap();
        assert_eq!(back, path);
    }
}
