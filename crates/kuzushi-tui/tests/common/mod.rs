//! Shared HOME isolation for the integration-test binaries. Mirrors
//! `src/test_support.rs::isolate_operator_home_from_tests` for the lib tests:
//! tests must never observe the operator's real `$HOME/.kuzushi` state,
//! because a globally configured model or runtime silently flips "no model
//! configured" expectations. Runs before `main`, while the process is still
//! single-threaded; scoped overrides like `ScopedHome` still apply on top.

#[ctor::ctor]
fn isolate_operator_home_from_tests() {
    let home = std::env::temp_dir().join(format!("kuzushi-tui-test-home-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("create isolated test HOME");
    std::env::set_var("HOME", &home);
}
