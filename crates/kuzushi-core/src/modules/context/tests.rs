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

    #[test]
    fn infer_repo_context_collects_backend_framework_manifest_signals() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "dependencies { implementation 'org.springframework.boot:spring-boot-starter-web' }\n",
        )
        .unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();

        let context = infer_repo_context(
            temp.path(),
            &[
                "src/main/java/app/UserController.java".to_string(),
                "app/controllers/users_controller.rb".to_string(),
                "app/Http/Controllers/UserController.php".to_string(),
                "Controllers/AdminController.cs".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(context["languages"], json!(["C#", "Java", "PHP", "Ruby"]));
        for framework in ["aspnet-core", "laravel", "rails", "spring"] {
            assert!(context["frameworks"]
                .as_array()
                .unwrap()
                .contains(&json!(framework)));
        }
    }
}
