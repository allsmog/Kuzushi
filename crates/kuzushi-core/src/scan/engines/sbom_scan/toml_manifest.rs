pub(super) fn toml_dependency_scopes(ecosystem: &str) -> &'static [&'static str] {
    if ecosystem == "cargo" {
        return &[
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "workspace.dependencies",
        ];
    }
    &[
        "project.dependencies",
        "project.optional-dependencies",
        "dependency-groups",
    ]
}

pub(super) fn toml_value_at<'a>(
    value: &'a toml::Value,
    dotted_path: &str,
) -> Option<&'a toml::Value> {
    dotted_path
        .split('.')
        .try_fold(value, |current, key| current.get(key))
}

pub(super) fn toml_version(value: &toml::Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_table()?.get("version")?.as_str())
}
