#[cfg(test)]
mod tests {
    use super::super::*;
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
