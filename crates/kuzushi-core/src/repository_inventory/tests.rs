#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::*;

    #[test]
    fn repository_inventory_detects_node_express_routes_and_manifests() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("node_modules/express")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"scripts":{"start":"node src/server.js"},"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(temp.path().join("package-lock.json"), "{}\n").unwrap();
        fs::write(temp.path().join("tsconfig.json"), "{}\n").unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import express from 'express';\nconst app = express();\napp.get('/users', handler);\napp.listen(3000);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/controllers/userController.ts"),
            "export function handler() {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("node_modules/express/index.js"),
            "module.exports = {}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "TypeScript", 2);
        assert_has_file(&inventory.manifests, "package.json", "node-package");
        assert_has_file(
            &inventory.dependency_manifests,
            "package-lock.json",
            "npm-lockfile",
        );
        assert_has_file(
            &inventory.config_files,
            "tsconfig.json",
            "typescript-config",
        );
        assert_framework(&inventory, "Express", "JavaScript");
        assert!(inventory.entrypoints.iter().any(|entrypoint| {
            entrypoint.kind == "node-start-script" && entrypoint.path == "package.json"
        }));
        assert!(inventory.entrypoints.iter().any(|entrypoint| {
            entrypoint.kind == "node-server" && entrypoint.path == "src/server.ts"
        }));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("GET")
                && item.route.as_deref() == Some("/users")
        }));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "controller" && item.path == "src/controllers/userController.ts"
        }));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "node_modules" && item.kind == "vendor"));
        assert!(!inventory
            .source_files
            .iter()
            .any(|file| file.path.starts_with("node_modules/")));
    }

    #[test]
    fn repository_inventory_detects_python_frameworks_and_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "fastapi\nflask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/items')\ndef create_item(): pass\nif __name__ == '__main__':\n    pass\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Python", 1);
        assert_has_file(
            &inventory.manifests,
            "requirements.txt",
            "python-requirements",
        );
        assert_framework(&inventory, "FastAPI", "Python");
        assert_framework(&inventory, "Flask", "Python");
        assert!(inventory
            .entrypoints
            .iter()
            .any(|entrypoint| entrypoint.kind == "python-app" && entrypoint.path == "app.py"));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("POST")
                && item.route.as_deref() == Some("/items")
        }));
    }

    #[test]
    fn python_route_methods_extracts_declared_method_lists() {
        assert_eq!(
            python_route_methods("@app.route('/items', methods=['GET', 'POST'])").as_deref(),
            Some("GET,POST")
        );
        assert_eq!(
            python_route_methods("@bp.route('/item', methods=['delete', 'PATCH'])").as_deref(),
            Some("PATCH,DELETE")
        );
        assert_eq!(python_route_methods("@app.get('/items')"), None);
        assert_eq!(
            python_route_methods("@app.route('/items', methods=[])"),
            None
        );
    }

    #[test]
    fn repository_inventory_detects_go_entrypoints_routes_and_vendor_paths() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("vendor/example")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module demo\nrequire github.com/gin-gonic/gin v1.9.0\n",
        )
        .unwrap();
        fs::write(temp.path().join("go.sum"), "example h1:abc\n").unwrap();
        fs::write(
            temp.path().join("main.go"),
            "package main\nimport \"net/http\"\nfunc main() { http.HandleFunc(\"/health\", health) }\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Go", 1);
        assert_has_file(&inventory.manifests, "go.mod", "go-module");
        assert_has_file(&inventory.dependency_manifests, "go.sum", "go-checksums");
        assert_framework(&inventory, "Gin", "Go");
        assert_framework(&inventory, "net/http", "Go");
        assert!(inventory
            .entrypoints
            .iter()
            .any(|entrypoint| entrypoint.kind == "go-main" && entrypoint.path == "main.go"));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.route.as_deref() == Some("/health")
                && item.framework.as_deref() == Some("net/http")
        }));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "vendor" && item.kind == "vendor"));
    }

    #[test]
    fn repository_inventory_detects_rust_entrypoints_and_config() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("target/debug")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n[dependencies]\naxum = \"0.7\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("Cargo.lock"), "# lock\n").unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use axum::{routing::get, Router};\n#[tokio::main]\nasync fn main() { let app = Router::new().route(\"/ready\", get(ready)); }\n",
        )
        .unwrap();
        fs::write(temp.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Rust", 1);
        assert_has_file(&inventory.manifests, "Cargo.toml", "rust-cargo");
        assert_has_file(
            &inventory.dependency_manifests,
            "Cargo.lock",
            "rust-cargo-lockfile",
        );
        assert_has_file(&inventory.config_files, "Dockerfile", "dockerfile");
        assert_framework(&inventory, "Axum", "Rust");
        assert!(
            inventory
                .entrypoints
                .iter()
                .any(|entrypoint| entrypoint.kind == "rust-binary"
                    && entrypoint.path == "src/main.rs")
        );
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.route.as_deref() == Some("/ready") && item.framework.as_deref() == Some("Axum")
        }));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "target" && item.kind == "generated"));
    }

    #[test]
    fn repository_inventory_is_deterministic_for_mixed_fixtures_and_skips_generated_sources() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/generated")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("pyproject.toml"),
            "[project]\ndependencies = ['django']\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"mixed\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/api.ts"), "export const ok = true;\n").unwrap();
        fs::write(temp.path().join("worker.py"), "print('ok')\n").unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        fs::write(
            temp.path().join("src/generated/client.generated.ts"),
            "export const generated = true;\n",
        )
        .unwrap();

        let first = build_repository_inventory(temp.path()).unwrap();
        let second = build_repository_inventory(temp.path()).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first
                .languages
                .iter()
                .map(|language| language.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Python", "Rust", "TypeScript"]
        );
        assert_framework(&first, "Next.js", "JavaScript");
        assert_framework(&first, "Django", "Python");
        assert!(first
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "src/generated" && item.kind == "generated"));
        assert!(!first
            .source_files
            .iter()
            .any(|file| file.path == "src/generated/client.generated.ts"));
    }

    fn assert_language(inventory: &RepositoryInventory, name: &str, files: usize) {
        let language = inventory
            .languages
            .iter()
            .find(|language| language.name == name)
            .unwrap_or_else(|| panic!("missing language {name}: {:?}", inventory.languages));
        assert_eq!(language.files, files);
    }

    fn assert_has_file(files: &[InventoryFile], path: &str, kind: &str) {
        assert!(
            files
                .iter()
                .any(|file| file.path == path && file.kind == kind),
            "missing {path} {kind}: {files:?}"
        );
    }

    fn assert_framework(inventory: &RepositoryInventory, name: &str, language: &str) {
        assert!(
            inventory
                .frameworks
                .iter()
                .any(|framework| framework.name == name && framework.language == language),
            "missing framework {name}/{language}: {:?}",
            inventory.frameworks
        );
    }
}
