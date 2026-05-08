#[cfg(test)]
mod tests {
    use super::super::*;

    fn opts(cmd: &[&str]) -> SandboxExecOptions {
        SandboxExecOptions::new(cmd.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn bwrap_argv_contains_unshare_all_and_cap_drop() {
        let argv = build_argv(SandboxBackend::Bwrap, &opts(&["echo", "hi"]));
        assert_eq!(argv[0], "bwrap");
        assert!(argv.iter().any(|a| a == "--unshare-all"));
        assert!(argv.iter().any(|a| a == "--cap-drop"));
        assert!(argv.iter().any(|a| a == "ALL"));
        // Ensures the cmd is at the tail past `--`.
        let dashdash = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(&argv[dashdash + 1..], &["echo", "hi"]);
    }

    #[test]
    fn bwrap_share_net_only_when_network_requested() {
        let mut o = opts(&["true"]);
        o.network = false;
        let no_net = build_argv(SandboxBackend::Bwrap, &o);
        assert!(!no_net.iter().any(|a| a == "--share-net"));
        o.network = true;
        let with_net = build_argv(SandboxBackend::Bwrap, &o);
        assert!(with_net.iter().any(|a| a == "--share-net"));
    }

    #[test]
    fn bwrap_includes_tmpfs_for_tmp_and_work() {
        let argv = build_argv(SandboxBackend::Bwrap, &opts(&["true"]));
        let mut tmpfs_targets = Vec::new();
        let mut iter = argv.iter().peekable();
        while let Some(a) = iter.next() {
            if a == "--tmpfs" {
                if let Some(target) = iter.next() {
                    tmpfs_targets.push(target.clone());
                }
            }
        }
        assert!(tmpfs_targets.iter().any(|t| t == "/tmp"));
        assert!(tmpfs_targets.iter().any(|t| t == "/work"));
    }

    #[test]
    fn podman_argv_includes_read_only_and_no_new_privileges() {
        let argv = build_argv(SandboxBackend::Podman, &opts(&["alpine", "echo"]));
        assert_eq!(argv[0], "podman");
        assert_eq!(argv[1], "run");
        assert!(argv.iter().any(|a| a == "--read-only"));
        assert!(argv.iter().any(|a| a == "--cap-drop=ALL"));
        let mut found_no_new = false;
        let mut iter = argv.iter().peekable();
        while let Some(a) = iter.next() {
            if a == "--security-opt" && iter.peek().map(|s| s.as_str()) == Some("no-new-privileges")
            {
                found_no_new = true;
            }
        }
        assert!(found_no_new);
    }

    #[test]
    fn podman_argv_omits_network_none_when_network_requested() {
        let mut o = opts(&["alpine", "true"]);
        o.network = true;
        let argv = build_argv(SandboxBackend::Podman, &o);
        assert!(!argv.iter().any(|a| a == "--network=none"));
    }

    #[test]
    fn read_only_mounts_appear_in_argv() {
        let mut o = opts(&["true"]);
        o.read_only_mounts = vec![MountSpec {
            host_path: PathBuf::from("/host/ro"),
            guest_path: PathBuf::from("/guest/ro"),
        }];
        let argv = build_argv(SandboxBackend::Bwrap, &o);
        let pairs = argv
            .windows(3)
            .find(|w| w[0] == "--ro-bind" && w[1] == "/host/ro" && w[2] == "/guest/ro");
        assert!(pairs.is_some());
    }

    #[test]
    fn cap_output_truncates_at_1mib_with_marker() {
        let big = vec![b'A'; MAX_OUTPUT_BYTES + 100];
        let (capped, truncated) = cap_output(big);
        assert!(truncated);
        assert!(capped.ends_with(TRUNCATION_MARKER));
        assert!(capped.len() <= MAX_OUTPUT_BYTES + TRUNCATION_MARKER.len());
    }

    #[test]
    fn cap_output_passes_short_payloads_through_unchanged() {
        let small = b"hello".to_vec();
        let (out, truncated) = cap_output(small);
        assert!(!truncated);
        assert_eq!(out, "hello");
    }

    #[tokio::test]
    async fn plain_backend_runs_echo_end_to_end() {
        let result = sandbox_exec(SandboxBackend::Plain, opts(&["echo", "kuzushi"]))
            .await
            .unwrap();
        assert_eq!(result.outcome, ExitOutcome::Exited);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.starts_with("kuzushi"));
        assert!(!result.stdout_truncated);
    }

    #[tokio::test]
    async fn plain_backend_exit_code_propagates() {
        // `false` exits non-zero on every Unix.
        let result = sandbox_exec(SandboxBackend::Plain, opts(&["false"]))
            .await
            .unwrap();
        assert_eq!(result.outcome, ExitOutcome::Exited);
        assert_eq!(result.exit_code, Some(1));
    }

    #[tokio::test]
    async fn timeout_kills_long_running_child() {
        let mut o = opts(&["sleep", "5"]);
        o.timeout_ms = 200;
        let result = sandbox_exec(SandboxBackend::Plain, o).await.unwrap();
        assert_eq!(result.outcome, ExitOutcome::TimedOut);
        assert!(result.stderr.contains("timeout after 200 ms"));
    }

    #[tokio::test]
    async fn requesting_isolating_backend_when_missing_returns_unavailable() {
        // bwrap and podman are absent in the test sandbox; this exercises
        // the BackendUnavailable error path. On hosts that *do* have
        // them the test exits early.
        if crate::backend::which("bwrap").is_some() {
            return;
        }
        let err = sandbox_exec(SandboxBackend::Bwrap, opts(&["true"]))
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::BackendUnavailable(_)));
    }

    #[tokio::test]
    async fn stdin_is_piped_through_to_child() {
        let mut o = opts(&["cat"]);
        o.stdin = Some("inbound\n".to_string());
        let result = sandbox_exec(SandboxBackend::Plain, o).await.unwrap();
        assert_eq!(result.outcome, ExitOutcome::Exited);
        assert!(result.stdout.contains("inbound"));
    }
}
