#[cfg(test)]
mod tests {
    use super::super::*;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn list_c_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.c",
            "static int foo(int x) {\n  return x;\n}\n\n#define BAR 1\n\nvoid baz()\n{\n}\n",
        );
        let out = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.c".to_string(),
            },
        )
        .unwrap();
        let names: Vec<&str> = out.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"baz"));
    }

    #[test]
    fn list_rust_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.rs",
            "pub fn foo() {}\nfn private_fn(x: u32) -> u32 { x }\npub struct Bar;\nenum Baz { A, B }\n",
        );
        let out = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.rs".to_string(),
            },
        )
        .unwrap();
        let kinds: Vec<&str> = out.definitions.iter().map(|d| d.kind.as_str()).collect();
        let names: Vec<&str> = out.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"private_fn"));
        assert!(names.contains(&"Bar"));
        assert!(names.contains(&"Baz"));
        assert!(kinds.contains(&"struct"));
        assert!(kinds.contains(&"enum"));
    }

    #[test]
    fn list_python_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.py",
            "class Foo:\n    def bar(self): pass\n    async def baz(self): pass\n\ndef top_level():\n    pass\n",
        );
        let out = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.py".to_string(),
            },
        )
        .unwrap();
        let names: Vec<&str> = out.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"bar"));
        assert!(names.contains(&"baz"));
        assert!(names.contains(&"top_level"));
    }

    #[test]
    fn list_go_and_java_definitions() {
        let tmp = tempdir().unwrap();
        write(
            tmp.path(),
            "a.go",
            "type Server struct{}\nfunc NewServer() *Server { return nil }\nfunc (s *Server) Serve() {}\n",
        );
        write(
            tmp.path(),
            "A.java",
            "public class A {\n  public void run() {}\n}\ninterface Worker {}\n",
        );

        let go = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "a.go".to_string(),
            },
        )
        .unwrap();
        let go_names: Vec<&str> = go.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(go_names.contains(&"Server"));
        assert!(go_names.contains(&"NewServer"));
        assert!(go_names.contains(&"Serve"));

        let java = list_definitions(
            tmp.path(),
            &ListDefinitionsInput {
                file: "A.java".to_string(),
            },
        )
        .unwrap();
        let java_names: Vec<&str> = java.definitions.iter().map(|d| d.name.as_str()).collect();
        assert!(java_names.contains(&"A"));
        assert!(java_names.contains(&"Worker"));
    }

    #[test]
    fn classify_hit_accepts_definitions_and_rejects_call_sites() {
        assert_eq!(
            classify_hit("pub async fn target() {}", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("async def target():", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("func target() {}", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("int target(int x)", "target").as_deref(),
            Some("function")
        );
        assert_eq!(
            classify_hit("struct target {", "target").as_deref(),
            Some("struct")
        );
        assert_eq!(classify_hit("let x = target();", "target"), None);
        assert_eq!(classify_hit("fn other() {}", "target"), None);
    }
}
