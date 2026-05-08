use super::prelude::*;
use super::*;

impl RepoContextSignals {
    pub(in crate::modules) fn ingest_file(&mut self, file: &str) {
        if let Some(language) = language_for_context_file(file) {
            self.languages.insert(language);
        }
        if is_context_entry_point(file) {
            self.entry_points.insert(file.to_string());
        }
    }

    pub(in crate::modules) fn inspect_manifests(&mut self, root: &Path) -> Result<()> {
        inspect_manifest_dependencies(
            &root.join("package.json"),
            &mut self.frameworks,
            &mut self.auth_patterns,
            &mut self.orm_or_db,
            &mut self.sanitization_libs,
        )?;
        inspect_manifest_text(
            &root.join("Cargo.toml"),
            &["actix-web", "axum", "rocket"],
            &mut self.frameworks,
        )?;
        inspect_manifest_text(
            &root.join("Cargo.toml"),
            &["sqlx", "diesel"],
            &mut self.orm_or_db,
        )?;
        inspect_manifest_text(
            &root.join("pyproject.toml"),
            &["django", "fastapi", "flask"],
            &mut self.frameworks,
        )?;
        inspect_manifest_text(
            &root.join("pyproject.toml"),
            &["sqlalchemy"],
            &mut self.orm_or_db,
        )?;
        inspect_manifest_text(
            &root.join("go.mod"),
            &["gin-gonic/gin", "gorilla/mux"],
            &mut self.frameworks,
        )?;
        inspect_manifest_text(&root.join("go.mod"), &["gorm.io/gorm"], &mut self.orm_or_db)
    }

    pub(in crate::modules) fn into_json(self) -> Value {
        json!({
            "languages": self.languages.into_iter().collect::<Vec<_>>(),
            "frameworks": self.frameworks.into_iter().collect::<Vec<_>>(),
            "authPatterns": self.auth_patterns.into_iter().collect::<Vec<_>>(),
            "ormOrDb": self.orm_or_db.into_iter().collect::<Vec<_>>(),
            "entryPoints": self.entry_points.into_iter().collect::<Vec<_>>(),
            "sanitizationLibs": self.sanitization_libs.into_iter().collect::<Vec<_>>(),
        })
    }
}

pub(in crate::modules) fn language_for_context_file(file: &str) -> Option<&'static str> {
    match Path::new(file).extension().and_then(|ext| ext.to_str())? {
        "js" | "jsx" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "rs" => Some("Rust"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        "c" | "h" => Some("C"),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => Some("C++"),
        _ => None,
    }
}

pub(in crate::modules) fn is_context_entry_point(file: &str) -> bool {
    let lower = file.to_lowercase();
    matches!(
        lower.as_str(),
        "package.json" | "server.js" | "server.ts" | "src/main.rs" | "main.go" | "app.py"
    ) || [
        "/server.js",
        "/server.ts",
        "/src/main.rs",
        "/main.go",
        "/app.py",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

pub(in crate::modules) fn inspect_manifest_dependencies(
    path: &Path,
    frameworks: &mut BTreeSet<&'static str>,
    auth_patterns: &mut BTreeSet<&'static str>,
    orm_or_db: &mut BTreeSet<&'static str>,
    sanitization_libs: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Ok(());
    };
    let parsed = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    let deps = package_json_dependency_names(&parsed);
    insert_package_json_context_signals(
        &deps,
        frameworks,
        auth_patterns,
        orm_or_db,
        sanitization_libs,
    );

    Ok(())
}
