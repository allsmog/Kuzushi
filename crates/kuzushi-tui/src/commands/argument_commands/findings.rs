use super::*;

pub(crate) fn parse_findings_command(args: &[&str], original: &str) -> ShellCommand {
    match args.first().copied() {
        Some("filter") => parse_findings_filter(original),
        Some(action) => parse_findings_action(action, args),
        None => ShellCommand::Findings,
    }
}

fn parse_findings_action(action: &str, args: &[&str]) -> ShellCommand {
    match action {
        "refresh" if args.len() == 1 => ShellCommand::FindingsRefresh,
        "since" => args
            .get(1)
            .map(|reference| ShellCommand::Since((*reference).to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown("findings since <ref>".to_string())),
        "export" => parse_workspace_findings_export_args(args.get(1..).unwrap_or_default()),
        other => ShellCommand::Unknown(format!("findings {other}")),
    }
}

fn parse_findings_filter(original: &str) -> ShellCommand {
    let expression = command_tail(command_tail(original.trim_start()));
    match expression.trim() {
        "" => ShellCommand::Unknown("findings filter".into()),
        "clear" => ShellCommand::Findings,
        _ => ShellCommand::FindingsFilter(expression.into()),
    }
}

fn command_tail(input: &str) -> &str {
    input
        .split_once(char::is_whitespace)
        .map_or("", |(_, rest)| rest.trim_start())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_is_a_distinct_read_action_with_no_ignored_arguments() {
        for input in ["findings refresh", "/findings refresh", "/f refresh"] {
            assert_eq!(
                crate::commands::parse_command(input),
                ShellCommand::FindingsRefresh
            );
        }
        assert!(matches!(
            crate::commands::parse_command("findings refresh extra"),
            ShellCommand::Unknown(_)
        ));
    }

    #[test]
    fn exact_paths_keep_repeated_spaces_tabs_commas_and_json_escapes() {
        let expression =
            r#"files:["app/a  b.rs","app/a\tb.rs","app/a,b.rs","app/é.rs"] severity:high"#;
        for prefix in ["findings filter ", "/findings  filter\t", "/f\tfilter\n"] {
            assert_eq!(
                crate::commands::parse_command(&format!("{prefix}{expression}")),
                ShellCommand::FindingsFilter(expression.into())
            );
        }
        let filter = kuzushi_core::FindingListFilter::from_filter_expression(expression).unwrap();
        assert_eq!(
            filter.file_paths,
            ["app/a  b.rs", "app/a\tb.rs", "app/a,b.rs", "app/é.rs"]
        );
    }

    #[test]
    fn text_filters_keep_their_original_expression() {
        assert_eq!(
            crate::commands::parse_command("findings filter name:two  words  severity:high"),
            ShellCommand::FindingsFilter("name:two  words  severity:high".into())
        );
    }

    #[test]
    fn empty_clear_and_since_keep_existing_behavior() {
        for input in ["findings filter", "/f\tfilter  "] {
            assert_eq!(
                crate::commands::parse_command(input),
                ShellCommand::Unknown("findings filter".into())
            );
        }
        assert_eq!(
            crate::commands::parse_command("/findings  filter  clear"),
            ShellCommand::Findings
        );
        assert_eq!(
            crate::commands::parse_command("findings since HEAD~1"),
            ShellCommand::Since("HEAD~1".into())
        );
    }
}
