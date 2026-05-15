use super::*;

#[test]
fn prompt_brand_uses_kz_when_cli_name_requests_alias() {
    assert_eq!(prompt_brand_from_sources(Some("kz"), Some("kuzushi")), "kz");
}

#[test]
fn prompt_brand_uses_kz_binary_stem_for_unix_or_windows_paths() {
    assert_eq!(
        prompt_brand_from_sources(None, Some("/usr/local/bin/kz")),
        "kz"
    );
    assert_eq!(
        prompt_brand_from_sources(None, Some(r"C:\tools\kz.exe")),
        "kz"
    );
}

#[test]
fn prompt_brand_defaults_to_kuzushi() {
    assert_eq!(
        prompt_brand_from_sources(Some("kuzushi"), Some("/usr/local/bin/kuzushi")),
        "kuzushi"
    );
    assert_eq!(prompt_brand_from_sources(None, None), "kuzushi");
}
