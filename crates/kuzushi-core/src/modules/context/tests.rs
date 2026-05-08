#[cfg(test)]
mod tests {
    use super::super::*;
    use std::fs;

    #[test]
    fn infer_repo_context_collects_languages_entrypoints_and_manifest_signals() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{
              "dependencies": {
                "express": "^4",
                "passport": "^1",
                "jsonwebtoken": "^9",
                "prisma": "^5",
                "zod": "^3"
              },
              "devDependencies": {"react": "^18"}
            }"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "axum = \"0.7\"\nsqlx = \"0.8\"",
        )
        .unwrap();

        let context = infer_repo_context(
            temp.path(),
            &[
                "server.ts".to_string(),
                "src/main.rs".to_string(),
                "cmd/api/main.go".to_string(),
                "native/parser.cpp".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(
            context["languages"],
            json!(["C++", "Go", "Rust", "TypeScript"])
        );
        assert_eq!(
            context["entryPoints"],
            json!(["cmd/api/main.go", "server.ts", "src/main.rs"])
        );
        assert!(context["frameworks"]
            .as_array()
            .unwrap()
            .contains(&json!("express")));
        assert!(context["frameworks"]
            .as_array()
            .unwrap()
            .contains(&json!("axum")));
        assert!(context["authPatterns"]
            .as_array()
            .unwrap()
            .contains(&json!("jwt")));
        assert!(context["ormOrDb"]
            .as_array()
            .unwrap()
            .contains(&json!("prisma")));
        assert!(context["sanitizationLibs"]
            .as_array()
            .unwrap()
            .contains(&json!("zod")));
    }
}
