pub(crate) fn prompt_brand() -> &'static str {
    prompt_brand_from_sources(
        std::env::var("KUZUSHI_CLI_NAME").ok().as_deref(),
        std::env::args().next().as_deref(),
    )
}

fn prompt_brand_from_sources(cli_name: Option<&str>, argv0: Option<&str>) -> &'static str {
    if cli_name == Some("kz") {
        return "kz";
    }
    match argv0.and_then(binary_stem) {
        Some("kz") => "kz",
        _ => "kuzushi",
    }
}

fn binary_stem(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .next()
        .map(|name| name.strip_suffix(".exe").unwrap_or(name))
}

#[cfg(test)]
mod tests;
