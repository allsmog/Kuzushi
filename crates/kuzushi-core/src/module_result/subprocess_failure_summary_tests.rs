use super::subprocess_failure_summary;

#[test]
fn prefers_the_line_that_names_the_failure_over_stack_frames() {
    let stderr = b"WARNING: deprecated method called\n\
        ERROR AstGenRunner Local astgen binary not found at '/x/astgen'!\n\
        java.lang.RuntimeException: Could not generate CPG\n\
        at io.joern.joerncli.JoernParse$.run(JoernParse.scala:87)\n\
        ... 12 more\n";

    let summary = subprocess_failure_summary(stderr, "fallback");

    assert!(
        summary.contains("astgen binary not found"),
        "got: {summary}"
    );
    assert!(!summary.contains("at io.joern"));
    assert!(!summary.contains("12 more"));
}

#[test]
fn falls_back_when_no_failure_line_present() {
    let stderr = b"   \n\n";
    assert_eq!(
        subprocess_failure_summary(stderr, "use a real target"),
        "use a real target"
    );
}

#[test]
fn uses_last_meaningful_line_when_nothing_names_a_failure() {
    let stderr = b"step one done\nstep two done\n";
    assert_eq!(
        subprocess_failure_summary(stderr, "fallback"),
        "step two done"
    );
}

#[test]
fn skips_generic_exit_wrapper_in_favor_of_real_cause() {
    // joern emits the generic ExternalCommand wrapper first; the actionable
    // cause (missing astgen) comes later and should win.
    let stderr = b"2026-05-28 13:48:03.597 ERROR ExternalCommand$          Process exited with code 1.\n\
        2026-05-28 13:48:03.500 ERROR AstGenRunner              Local astgen binary not found at '/x/astgen'!\n";

    let summary = subprocess_failure_summary(stderr, "fallback");

    assert!(
        summary.contains("astgen binary not found"),
        "got: {summary}"
    );
    assert!(!summary.contains("Process exited with code"));
    assert!(
        !summary.contains("ERROR AstGenRunner"),
        "log prefix stripped: {summary}"
    );
}
