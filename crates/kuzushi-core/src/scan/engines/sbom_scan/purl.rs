pub(super) fn package_url(ecosystem: &str, name: &str, version: Option<&str>) -> Option<String> {
    let package_type = package_type(ecosystem)?;
    let version = version.and_then(exact_version);
    Some(match version {
        Some(version) => format!("pkg:{package_type}/{}@{version}", encode_name(ecosystem, name)),
        None => format!("pkg:{package_type}/{}", encode_name(ecosystem, name)),
    })
}

fn package_type(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "bower" => Some("generic"),
        "carthage" => Some("generic"),
        "composer" => Some("composer"),
        "conda" => Some("conda"),
        "conan" => Some("conan"),
        "cargo" => Some("cargo"),
        "cpan" => Some("cpan"),
        "crystal" => Some("generic"),
        "dart" => Some("pub"),
        "elm" => Some("elm"),
        "gem" => Some("gem"),
        "go" => Some("golang"),
        "hackage" => Some("hackage"),
        "haxelib" => Some("generic"),
        "hex" => Some("hex"),
        "helm" => Some("helm"),
        "julia" => Some("julia"),
        "jsr" => Some("generic"),
        "maven" => Some("maven"),
        "nimble" => Some("generic"),
        "nuget" => Some("nuget"),
        "npm" => Some("npm"),
        "opam" => Some("generic"),
        "cocoapods" => Some("generic"),
        "python" => Some("pypi"),
        "r" => Some("cran"),
        "swift" => Some("generic"),
        "vcpkg" => Some("generic"),
        _ => None,
    }
}

fn exact_version(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed.eq_ignore_ascii_case("latest") {
        return None;
    }
    if trimmed.contains(['^', '~', '<', '>', '=', '!', ',', '|', ' ', '$', '{', '}']) {
        return None;
    }
    Some(trimmed)
}

fn encode_name(ecosystem: &str, name: &str) -> String {
    if ecosystem == "npm" {
        return name.replace('@', "%40");
    }
    name.to_string()
}
