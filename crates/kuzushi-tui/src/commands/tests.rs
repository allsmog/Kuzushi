#[cfg(test)]
mod tests {
    use super::super::*;
    use std::path::PathBuf;

    #[test]
    fn parses_kept_commands() {
        assert_eq!(parse_command("/"), ShellCommand::Home);
        assert_eq!(parse_command("home"), ShellCommand::Home);
        assert_eq!(parse_command("/help"), ShellCommand::Help(None));
        assert_eq!(parse_command("/h"), ShellCommand::Help(None));
        assert_eq!(parse_command("?"), ShellCommand::Help(None));
        assert_eq!(parse_command("/modules"), ShellCommand::Modules);
        assert_eq!(parse_command("/show modules"), ShellCommand::Modules);
        assert_eq!(parse_command("/recommend"), ShellCommand::Recommend);
        assert_eq!(parse_command("rec"), ShellCommand::Recommend);
        assert_eq!(parse_command("aim"), ShellCommand::Aim(None));
        assert_eq!(
            parse_command("aim sql injection"),
            ShellCommand::Aim(Some("sql injection".to_string()))
        );
        assert_eq!(parse_command("doctor"), ShellCommand::Health);
        assert_eq!(parse_command("/health"), ShellCommand::Health);
        assert_eq!(parse_command("/tools"), ShellCommand::Tools(None));
        assert_eq!(parse_command("/show tools"), ShellCommand::Tools(None));
        assert_eq!(
            parse_command("tools semgrep scan"),
            ShellCommand::Tools(Some("semgrep scan".to_string()))
        );
        assert_eq!(
            parse_command("show tools codeql"),
            ShellCommand::Tools(Some("codeql".to_string()))
        );
        assert_eq!(
            parse_command("find phase:hunt taint"),
            ShellCommand::Tools(Some("phase:hunt taint".to_string()))
        );
        assert_eq!(
            parse_command("tools --fav"),
            ShellCommand::Tools(Some("fav:yes".to_string()))
        );
        assert_eq!(
            parse_command("tools --fav phase:hunt"),
            ShellCommand::Tools(Some("fav:yes phase:hunt".to_string()))
        );
        assert_eq!(
            parse_command("find --fav"),
            ShellCommand::Tools(Some("fav:yes".to_string()))
        );
        assert_eq!(
            parse_command("find --fav phase:hunt"),
            ShellCommand::Tools(Some("fav:yes phase:hunt".to_string()))
        );
        assert_eq!(
            parse_command("favorite semgrep:scan"),
            ShellCommand::FavoriteTool("semgrep:scan".to_string())
        );
        assert_eq!(
            parse_command("fav semgrep:scan"),
            ShellCommand::FavoriteTool("semgrep:scan".to_string())
        );
        assert_eq!(parse_command("/findings"), ShellCommand::Findings);
        assert_eq!(parse_command("/f"), ShellCommand::Findings);
        assert_eq!(
            parse_command(
                "suppress F-0002 --reason documentation-example --author alice --days 30"
            ),
            ShellCommand::ReviewDecision(ReviewDecisionCommand::Suppress {
                reference: "F-0002".to_string(),
                reason: "documentation-example".to_string(),
                author: "alice".to_string(),
                days: 30,
            })
        );
        assert_eq!(
            parse_command("findings filter state:new rank:high run:scan-1"),
            ShellCommand::FindingsFilter("state:new rank:high run:scan-1".to_string())
        );
        assert_eq!(
            parse_command("findings filter clear"),
            ShellCommand::Findings
        );
        assert_eq!(
            parse_command("decision suppressed reviewed under policy"),
            ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
                verdict: "suppressed".to_string(),
                reason: "reviewed under policy".to_string(),
            })
        );
        assert_eq!(
            parse_command("review confirmed source-linked evidence reviewed"),
            ShellCommand::ReviewDecision(ReviewDecisionCommand::Record {
                verdict: "confirmed".to_string(),
                reason: "source-linked evidence reviewed".to_string(),
            })
        );
        assert_eq!(
            parse_command("decision suppressed"),
            ShellCommand::ReviewDecision(ReviewDecisionCommand::Unsupported(
                "decision suppressed".to_string(),
            ))
        );
        assert_eq!(
            parse_command("proof defer F-01 --reason production harness is unavailable"),
            ShellCommand::ProofDeferral {
                reference: "F-01".to_string(),
                reason: "production harness is unavailable".to_string(),
            }
        );
        assert_eq!(
            parse_command("dismiss used_in_tests only exercised in fixtures"),
            ShellCommand::ReviewDecision(ReviewDecisionCommand::Dismiss {
                reason: "used_in_tests".to_string(),
                note: "only exercised in fixtures".to_string(),
            })
        );
        assert_eq!(
            parse_command("dismiss false_positive"),
            ShellCommand::ReviewDecision(ReviewDecisionCommand::Unsupported(
                "dismiss false_positive".to_string(),
            ))
        );
        assert_eq!(
            parse_command("findings export /tmp/findings.json"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("/tmp/findings.json"),
                format: None,
                completeness: None,
                allow_empty: false,
            })
        );
        assert_eq!(
            parse_command("findings export /tmp/findings-bundle format=markdown-bundle"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("/tmp/findings-bundle"),
                format: Some("markdown-bundle".to_string()),
                completeness: None,
                allow_empty: false,
            })
        );
        assert_eq!(
            parse_command("findings export /tmp/empty.json --allow-empty"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("/tmp/empty.json"),
                format: None,
                completeness: None,
                allow_empty: true,
            })
        );
        assert_eq!(
            parse_command("findings export /tmp/open.json --completeness open"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("/tmp/open.json"),
                format: None,
                completeness: Some("open".to_string()),
                allow_empty: false,
            })
        );
        assert_eq!(parse_command("runs"), ShellCommand::ShowRuns);
        assert_eq!(
            parse_command("runs diff run-left run-right"),
            ShellCommand::RunDiff {
                left: "run-left".to_string(),
                right: "run-right".to_string()
            }
        );
        assert_eq!(parse_command("/back"), ShellCommand::Back);
        assert_eq!(
            parse_command("/threats stride"),
            ShellCommand::Threat(ThreatView::Stride)
        );
        assert_eq!(
            parse_command("/threats 4"),
            ShellCommand::Threat(ThreatView::Summary)
        );
        assert_eq!(parse_command("/threats regen"), ShellCommand::ThreatRegen);
        assert_eq!(
            parse_command("/threats versions"),
            ShellCommand::ThreatVersions
        );
        assert_eq!(
            parse_command("/threats use 3"),
            ShellCommand::ThreatVersionUse(3)
        );
        assert_eq!(
            parse_command("/threats use"),
            ShellCommand::Unknown("/threats use <version-id>".to_string())
        );
        assert_eq!(
            parse_command("/threats ask what changed?"),
            ShellCommand::ThreatAsk("what changed?".to_string())
        );
        assert_eq!(parse_command("/threats apply"), ShellCommand::ThreatApply);
        assert_eq!(parse_command("/threats reject"), ShellCommand::ThreatReject);
        assert_eq!(parse_command("/prompts"), ShellCommand::Prompts);
        assert_eq!(
            parse_command("/prompt show run"),
            ShellCommand::Prompt("show run".to_string())
        );
        assert_eq!(
            parse_command("/prompt mutate triage \"focus authz\""),
            ShellCommand::Prompt("mutate triage \"focus authz\"".to_string())
        );
        assert_eq!(
            parse_command("/open abc123"),
            ShellCommand::Open("abc123".to_string())
        );
        assert_eq!(
            parse_command("/scan ./repo"),
            ShellCommand::Scan(Some(PathBuf::from("./repo")))
        );
        assert_eq!(parse_command("/demo"), ShellCommand::Demo);
        assert_eq!(
            parse_command("/target rev abcdef1"),
            ShellCommand::TargetRevision("abcdef1".to_string())
        );
        assert_eq!(parse_command("/pwn"), ShellCommand::Pwn(PwnCommand::Show));
        assert_eq!(
            parse_command("/pwn target ./challenge/bin"),
            ShellCommand::Pwn(PwnCommand::Target(PathBuf::from("./challenge/bin")))
        );
        assert_eq!(
            parse_command("/pwn profile"),
            ShellCommand::Pwn(PwnCommand::Profile)
        );
        assert_eq!(
            parse_command("/pwn reverse main"),
            ShellCommand::Pwn(PwnCommand::Reverse(Some("main".to_string())))
        );
        assert_eq!(
            parse_command("/pwn auto"),
            ShellCommand::Pwn(PwnCommand::Auto)
        );
        assert_eq!(
            parse_command("/pwn state"),
            ShellCommand::Pwn(PwnCommand::State)
        );
        assert_eq!(
            parse_command("/pwn candidates 127.0.0.1:31337"),
            ShellCommand::Pwn(PwnCommand::Candidates("127.0.0.1:31337".to_string()))
        );
        assert_eq!(
            parse_command("/model openai:gpt-5.5 xtrahigh"),
            ShellCommand::Model(Some("openai:gpt-5.5 xtrahigh".to_string()))
        );
        assert_eq!(parse_command("/auth"), ShellCommand::Auth);
        assert_eq!(
            parse_command("/auth login anthropic"),
            ShellCommand::AuthLogin(Some("anthropic".to_string()))
        );
        assert_eq!(
            parse_command("auth openai"),
            ShellCommand::AuthLogin(Some("openai".to_string()))
        );
        assert_eq!(
            parse_command("/auth login openai headless"),
            ShellCommand::AuthLogin(Some("openai headless".to_string()))
        );
        assert_eq!(
            parse_command("/auth login github-copilot"),
            ShellCommand::AuthLogin(Some("github-copilot".to_string()))
        );
        for command in [
            format!("auth {}", "codex"),
            format!("auth {}", "openai-codex"),
            "auth login codex".to_string(),
            format!("/auth login {}", "openai-codex"),
        ] {
            let parsed = parse_command(&command);
            let ShellCommand::Unknown(raw) = parsed else {
                panic!("expected unknown legacy auth selector for {command}");
            };
            assert_eq!(raw, "auth legacy-openai-oauth");
        }
        assert_eq!(
            parse_command("/provider openai"),
            ShellCommand::Provider(Some("openai".to_string()))
        );
        assert_eq!(
            parse_command("/backend LangGraph"),
            ShellCommand::Backend(Some("LangGraph".to_string()))
        );
        assert_eq!(parse_command("/cost"), ShellCommand::Cost);
        assert_eq!(parse_command("/config"), ShellCommand::Config);
        assert_eq!(parse_command("/permissions"), ShellCommand::Permissions);
        assert_eq!(parse_command("show permissions"), ShellCommand::Permissions);
        assert_eq!(parse_command("/boot"), ShellCommand::BootSplash);
        assert_eq!(parse_command("/theme"), ShellCommand::ThemePicker);
        assert_eq!(parse_command("/keys"), ShellCommand::Keymap);
        assert_eq!(parse_command("/update"), ShellCommand::UpdateAvailable);
        assert_eq!(parse_command("/quit-confirm"), ShellCommand::QuitConfirm);
        assert_eq!(
            parse_command("/use semgrep"),
            ShellCommand::Use("semgrep".to_string())
        );
        assert_eq!(parse_command("/tune"), ShellCommand::Tune);
        assert_eq!(parse_command("/t"), ShellCommand::Tune);
        assert_eq!(parse_command("/actor 1"), ShellCommand::Actor(1));
        assert_eq!(parse_command("/show runs"), ShellCommand::ShowRuns);
        assert_eq!(
            parse_command("/show aliases F-00"),
            ShellCommand::ShowAliases(Some("F-00".to_string()))
        );
        assert_eq!(parse_command("/show prompts"), ShellCommand::Prompts);
        assert_eq!(
            parse_command("/options semgrep:scan"),
            ShellCommand::Options {
                tool: Some("semgrep:scan".to_string()),
                filter: OptionsFilter::Standard
            }
        );
        assert_eq!(
            parse_command("show options sast:scan"),
            ShellCommand::Options {
                tool: Some("sast:scan".to_string()),
                filter: OptionsFilter::Standard
            }
        );
        assert_eq!(
            parse_command("show advanced"),
            ShellCommand::Options {
                tool: None,
                filter: OptionsFilter::Advanced
            }
        );
        assert_eq!(
            parse_command("show missing"),
            ShellCommand::Options {
                tool: None,
                filter: OptionsFilter::Missing
            }
        );
        assert_eq!(
            parse_command("/set sampleLimit 2"),
            ShellCommand::SetOption {
                global: false,
                name: "sampleLimit".to_string(),
                value: "2".to_string()
            }
        );
        assert_eq!(
            parse_command("setg triage=false"),
            ShellCommand::SetOption {
                global: true,
                name: "triage".to_string(),
                value: "false".to_string()
            }
        );
        assert_eq!(
            parse_command("/unset sampleLimit"),
            ShellCommand::UnsetOption {
                global: false,
                name: "sampleLimit".to_string()
            }
        );
        assert_eq!(
            parse_command("unsetg triage"),
            ShellCommand::UnsetOption {
                global: true,
                name: "triage".to_string()
            }
        );
        assert_eq!(parse_command("/tasks"), ShellCommand::Tasks);
        assert_eq!(
            parse_command("/kb threat-model"),
            ShellCommand::KnowledgeBase(Some("threat-model".to_string()))
        );
        assert_eq!(
            parse_command("attachments"),
            ShellCommand::KnowledgeBase(None)
        );
        assert_eq!(
            parse_command("attach docs/design.md"),
            ShellCommand::Attach("docs/design.md".to_string())
        );
        assert_eq!(parse_command("attach"), ShellCommand::FilePicker);
        assert_eq!(parse_command("files"), ShellCommand::FilePicker);
        assert_eq!(
            parse_command("component web/app"),
            ShellCommand::Component(Some("web/app".to_string()))
        );
        assert_eq!(
            parse_command("component all"),
            ShellCommand::Component(Some("all".to_string()))
        );
        assert_eq!(
            parse_command("detach A-123"),
            ShellCommand::Detach("A-123".to_string())
        );
        assert_eq!(
            parse_command("reparse A-123"),
            ShellCommand::Reparse("A-123".to_string())
        );
        assert_eq!(parse_command("/session"), ShellCommand::SessionInfo);
        assert_eq!(parse_command("/history"), ShellCommand::History);
        assert_eq!(parse_command("/clear"), ShellCommand::Clear);
        assert_eq!(
            parse_command("/load builtin:sast"),
            ShellCommand::Load(Some("builtin:sast".to_string()))
        );
        assert_eq!(parse_command("/load"), ShellCommand::Load(None));
        assert_eq!(parse_command("/pause"), ShellCommand::Pause);
        assert_eq!(parse_command("/cancel"), ShellCommand::Cancel);
        assert_eq!(parse_command("c"), ShellCommand::Cancel);
        assert_eq!(parse_command("/c"), ShellCommand::Cancel);
        assert_eq!(parse_command("stop"), ShellCommand::Cancel);
        assert_eq!(parse_command("/resume"), ShellCommand::Resume(None));
        assert_eq!(
            parse_command("/resume run-123"),
            ShellCommand::Resume(Some("run-123".to_string()))
        );
        assert_eq!(parse_command("/story"), ShellCommand::Story);
        assert_eq!(
            parse_command("task block semgrep"),
            ShellCommand::Task(SastTaskCommand::Block("semgrep".to_string()))
        );
        assert_eq!(
            parse_command("/task allow codeql"),
            ShellCommand::Task(SastTaskCommand::Allow("codeql".to_string()))
        );
        assert_eq!(
            parse_command("/task toggle"),
            ShellCommand::Task(SastTaskCommand::Toggle(None))
        );
        assert_eq!(
            parse_command("/task toggle secret-scan"),
            ShellCommand::Task(SastTaskCommand::Toggle(Some("secret-scan".to_string())))
        );
        assert_eq!(
            parse_command("/task mode auto"),
            ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Auto))
        );
        assert_eq!(
            parse_command("/task mode manual"),
            ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Manual))
        );
        assert_eq!(
            parse_command("/task mode toggle"),
            ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Toggle))
        );
        assert_eq!(
            parse_command("/task reset"),
            ShellCommand::Task(SastTaskCommand::Reset)
        );
        assert_eq!(
            parse_command("/context"),
            ShellCommand::Context(ContextCommand::Show)
        );
        assert_eq!(
            parse_command("context build"),
            ShellCommand::Context(ContextCommand::Build)
        );
        assert_eq!(
            parse_command("/context status"),
            ShellCommand::Context(ContextCommand::Status)
        );
        assert_eq!(
            parse_command("/context regen repo"),
            ShellCommand::Context(ContextCommand::Regen("repo".to_string()))
        );
        assert_eq!(parse_command("project model"), ShellCommand::ProjectModel);
        assert_eq!(parse_command("queue"), ShellCommand::ShowJobs);
        assert_eq!(
            parse_command("queue run secret-scan:scan {}"),
            ShellCommand::QueueCommand("run secret-scan:scan {}".to_string())
        );
        assert_eq!(
            parse_command("strategy"),
            ShellCommand::Strategy(StrategyCommand::Show)
        );
        assert_eq!(
            parse_command("strategies"),
            ShellCommand::Strategy(StrategyCommand::Show)
        );
        assert_eq!(
            parse_command("strategy queue"),
            ShellCommand::Strategy(StrategyCommand::Show)
        );
        assert_eq!(
            parse_command("strategy approve review-codeql-scan"),
            ShellCommand::Strategy(StrategyCommand::Approve("review-codeql-scan".to_string()))
        );
        assert_eq!(
            parse_command("strategy keep review-codeql-scan"),
            ShellCommand::Strategy(StrategyCommand::Approve("review-codeql-scan".to_string()))
        );
        assert_eq!(
            parse_command("strategy reject review-codeql-scan"),
            ShellCommand::Strategy(StrategyCommand::Reject("review-codeql-scan".to_string()))
        );
        assert_eq!(
            parse_command("strategy skip review-codeql-scan"),
            ShellCommand::Strategy(StrategyCommand::Reject("review-codeql-scan".to_string()))
        );
        assert_eq!(
            parse_command("strategy fire"),
            ShellCommand::Strategy(StrategyCommand::Fire)
        );
        assert_eq!(
            parse_command(
                "strategy correct review-codeql-scan run codeql:scan with authz focus --workspace --reason tighten authz paths"
            ),
            ShellCommand::Strategy(StrategyCommand::Correct {
                id: "review-codeql-scan".to_string(),
                to_strategy: "run codeql:scan with authz focus".to_string(),
                reason: Some("tighten authz paths".to_string()),
                scope: StrategyCorrectionCommandScope::Workspace,
            })
        );
        assert_eq!(
            parse_command("patch apply"),
            ShellCommand::Patch(PatchCommand::Apply)
        );
        assert_eq!(
            parse_command("/patch reject"),
            ShellCommand::Patch(PatchCommand::Reject)
        );
        assert_eq!(
            parse_command("patch discard"),
            ShellCommand::Patch(PatchCommand::Reject)
        );
        assert_eq!(
            parse_command("patch regen --style defensive"),
            ShellCommand::Patch(PatchCommand::Regen {
                style: Some("defensive".to_string())
            })
        );
        assert_eq!(
            parse_command("patch regenerate --style=minimal"),
            ShellCommand::Patch(PatchCommand::Regen {
                style: Some("minimal".to_string())
            })
        );
        assert_eq!(
            parse_command("/workspace"),
            ShellCommand::Workspace(WorkspaceCommand::Status)
        );
        assert_eq!(
            parse_command("workspace status"),
            ShellCommand::Workspace(WorkspaceCommand::Status)
        );
        assert_eq!(
            parse_command("workspace reindex"),
            ShellCommand::Workspace(WorkspaceCommand::Reindex)
        );
        assert_eq!(
            parse_command("workspace index"),
            ShellCommand::Workspace(WorkspaceCommand::Reindex)
        );
        assert_eq!(
            parse_command("workspace export findings out.json"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("out.json"),
                format: None,
                completeness: None,
                allow_empty: false,
            })
        );
        assert_eq!(
            parse_command("workspace export findings markdown-bundle bundle-dir"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("bundle-dir"),
                format: Some("markdown-bundle".to_string()),
                completeness: None,
                allow_empty: false,
            })
        );
        assert_eq!(
            parse_command("workspace export findings out.csv scope=complete"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("out.csv"),
                format: None,
                completeness: Some("complete".to_string()),
                allow_empty: false,
            })
        );
        assert_eq!(
            parse_command("workspace scope init"),
            ShellCommand::Workspace(WorkspaceCommand::ScopeInit)
        );
        assert_eq!(
            parse_command("workspace import burp report.xml"),
            ShellCommand::Workspace(WorkspaceCommand::Unsupported(
                "workspace import".to_string()
            ))
        );
        assert_eq!(
            parse_command("/since main"),
            ShellCommand::Since("main".to_string())
        );
        assert_eq!(
            parse_command("/replay run-123"),
            ShellCommand::Replay("run-123".to_string())
        );
        assert_eq!(
            parse_command("/trace run-123"),
            ShellCommand::Trace("run-123".to_string())
        );
        assert_eq!(parse_command("/activity"), ShellCommand::Activity);
        assert_eq!(parse_command("activity"), ShellCommand::Activity);
        assert_eq!(parse_command("/progress"), ShellCommand::Activity);
        assert_eq!(parse_command("/a"), ShellCommand::Activity);
        assert_eq!(parse_command("/handoff"), ShellCommand::FailureHandoff);
        assert_eq!(parse_command("failure"), ShellCommand::FailureHandoff);
        assert_eq!(
            parse_command("/plan only admin routes"),
            ShellCommand::Plan("only admin routes".to_string())
        );
        assert_eq!(
            parse_command("/ask what changed?"),
            ShellCommand::Ask("what changed?".to_string())
        );
        assert_eq!(
            parse_command("ask what changed?"),
            ShellCommand::Ask("what changed?".to_string())
        );
        assert_eq!(
            parse_command("?what changed?"),
            ShellCommand::Ask("what changed?".to_string())
        );
        assert_eq!(parse_command("?"), ShellCommand::Help(None));
        assert_eq!(
            parse_command("phase confirm"),
            ShellCommand::Phase(WorkflowPhase::Prove)
        );
        assert_eq!(
            parse_command("/phase fix"),
            ShellCommand::Phase(WorkflowPhase::Fix)
        );
        assert_eq!(
            parse_command("help scan"),
            ShellCommand::Help(Some("scan".to_string()))
        );
        assert_eq!(
            parse_command("/run dep-hygiene:check {\"target\":\".\"}"),
            ShellCommand::RunTool {
                tool: Some("dep-hygiene:check".to_string()),
                input: Some("{\"target\":\".\"}".to_string())
            }
        );
        assert_eq!(
            parse_command("/run ."),
            ShellCommand::RunTool {
                tool: None,
                input: None
            }
        );
        assert_eq!(
            parse_command("run . {\"sampleLimit\":10}"),
            ShellCommand::RunTool {
                tool: None,
                input: Some("{\"sampleLimit\":10}".to_string())
            }
        );
        assert_eq!(parse_command("/exit"), ShellCommand::Quit);
        assert_eq!(parse_command("/quit"), ShellCommand::Quit);
    }

    #[test]
    fn recon_import_compiles_native_syntax_into_descriptor_input() {
        let ShellCommand::RunTool {
            tool: Some(tool),
            input: Some(input),
        } = parse_command("recon:import httpx ./recon/httpx.json")
        else {
            panic!("expected native recon import route");
        };
        let input: serde_json::Value = serde_json::from_str(&input).unwrap();
        assert_eq!(tool, "recon:import");
        assert_eq!(input["tool"], "httpx");
        assert_eq!(input["path"], "./recon/httpx.json");

        assert!(matches!(
            parse_command("recon:import"),
            ShellCommand::RunTool {
                tool: Some(tool),
                input: None,
            } if tool == "recon:import"
        ));
    }

    #[test]
    fn export_aliases_report_the_complete_friendly_usage() {
        for command in [
            "export",
            "findings export",
            "workspace export",
            "workspace export findings",
        ] {
            let ShellCommand::Workspace(WorkspaceCommand::Unsupported(message)) =
                parse_command(command)
            else {
                panic!("expected usage for {command}");
            };
            assert!(
                message.contains("usage: findings export <path> [format]"),
                "unexpected usage for {command}: {message}"
            );
            assert!(
                message.contains("alias: workspace export findings"),
                "unexpected usage for {command}: {message}"
            );
        }
    }

    #[test]
    fn accepts_commands_without_slash_for_log_prompt() {
        assert_eq!(parse_command("help"), ShellCommand::Help(None));
        assert_eq!(parse_command("modules"), ShellCommand::Modules);
        assert_eq!(parse_command("m"), ShellCommand::Modules);
        assert_eq!(parse_command("tools"), ShellCommand::Tools(None));
        assert_eq!(parse_command("findings"), ShellCommand::Findings);
        assert_eq!(parse_command("back"), ShellCommand::Back);
        assert_eq!(parse_command("b"), ShellCommand::Back);
        assert_eq!(parse_command("runs"), ShellCommand::ShowRuns);
        assert_eq!(
            parse_command("context status"),
            ShellCommand::Context(ContextCommand::Status)
        );
        assert_eq!(
            parse_command("scan ./repo"),
            ShellCommand::Scan(Some(PathBuf::from("./repo")))
        );
        assert_eq!(parse_command("q"), ShellCommand::Quit);
        assert_eq!(
            parse_command("exitj"),
            ShellCommand::Unknown("exitj".into())
        );
        assert_eq!(
            parse_command("/exitj"),
            ShellCommand::Unknown("/exitj".into())
        );
    }

    #[test]
    fn unknown_prose_does_not_route_to_agent_chat() {
        assert_eq!(
            parse_command("summarize this repo"),
            ShellCommand::Unknown("summarize this repo".to_string())
        );
        assert_eq!(
            parse_command("ask"),
            ShellCommand::Unknown("ask".to_string())
        );
        assert_eq!(
            parse_command("/ask"),
            ShellCommand::Unknown("/ask".to_string())
        );
    }

    #[test]
    fn retired_navigation_aliases_do_not_route() {
        for input in ["studio", "cc", "plan-stage", "diagram", "3d", "threats dfd"] {
            assert!(
                matches!(parse_command(input), ShellCommand::Unknown(_)),
                "retired alias {input:?} still routes"
            );
        }
    }

    #[test]
    fn command_catalog_advertises_only_routed_commands() {
        for spec in shell_command_specs() {
            let mut forms = vec![spec.command];
            forms.extend(spec.aliases.iter().copied());
            for form in forms {
                let sample = sample_help_form(form);
                let parsed = parse_command(&sample);
                assert!(
                    !matches!(parsed, ShellCommand::Unknown(_)),
                    "catalog form {form:?} materialized as {sample:?} did not route"
                );
            }
        }
    }

    #[test]
    fn command_catalog_covers_every_public_route_kind() {
        let mut routed = std::collections::BTreeSet::new();
        for spec in shell_command_specs() {
            let mut forms = vec![spec.command];
            forms.extend(spec.aliases.iter().copied());
            for form in forms {
                routed.insert(route_kind(&parse_command(&sample_help_form(form))));
            }
        }

        let expected = std::collections::BTreeSet::from([
            "activity",
            "actor",
            "aim",
            "attach",
            "ask",
            "auth",
            "auth-login",
            "autonomy",
            "back",
            "backend",
            "background",
            "boot-splash",
            "cancel",
            "cancel-job",
            "campaigns",
            "clear",
            "component",
            "config",
            "context",
            "cost",
            "coverage",
            "demo",
            "detach",
            "failure-handoff",
            "favorite-tool",
            "file-picker",
            "findings",
            "findings-filter",
            "health",
            "help",
            "home",
            "history",
            "kb",
            "load",
            "logs",
            "model",
            "modules",
            "next",
            "onboarding",
            "open",
            "options",
            "pause",
            "patch",
            "permissions",
            "phase",
            "plan",
            "plan-apply",
            "plan-discard",
            "prompts",
            "prompt",
            "proof-deferral",
            "provider",
            "project-model",
            "queue-command",
            "quickstart",
            "keymap",
            "recommend",
            "report",
            "quit",
            "quit-confirm",
            "reparse",
            "replay",
            "resume",
            "review-decision",
            "run-diff",
            "run-tool",
            "scan",
            "scene",
            "session-info",
            "set-option",
            "show-aliases",
            "show-jobs",
            "show-runs",
            "since",
            "story",
            "strategy",
            "target",
            "target-revision",
            "task",
            "tasks",
            "threat",
            "threat-ask",
            "threat-apply",
            "threat-editor",
            "threat-regen",
            "threat-reject",
            "threat-versions",
            "threat-version-use",
            "theme-picker",
            "tools",
            "trace",
            "tune",
            "unset-option",
            "update-available",
            "use",
            "workbench",
            "workspace",
        ]);

        assert_eq!(routed, expected);
    }

    /// U5 keypath registry: every command a "Next:" hint, empty-state CTA,
    /// or NEXT strip advertises must actually route when typed verbatim
    /// (placeholders substituted with realistic values). A renamed verb must
    /// fail here, not in an operator's session after they typed what the
    /// banner told them to.
    #[test]
    fn advertised_next_hint_commands_all_route() {
        let advertised = [
            // review queue empty CTA (renderer/views/workbench/panes/review_queue.rs)
            "findings",
            "findings filter completeness:open",
            // finding detail next actions (ui_view_models/findings.rs)
            "verify F-0001",
            "patch F-0001",
            // findings empty-state CTA + context snapshot hints
            "context build",
            "context status",
            "context regen repo",
            // workspace hints (ui_view_models/workspace.rs)
            "workspace status",
            "workspace scope init",
            "workspace export findings out.json json",
            // options hints (ui_view_models/options.rs)
            "set MODEL_TRIAGE anthropic:claude-sonnet-4-6",
            "setg ui.auto_open_viz false",
            "show advanced",
            "show missing",
            "tools",
            // sast task hints (ui_view_models/sast_tasks.rs)
            "task block t1",
            "task allow t1",
            "task toggle",
            "task mode auto",
            // project model hints (ui_view_models/project_model.rs)
            "threats summary",
            "scan",
            "project model",
            // config hints (ui_view_models/config.rs)
            "model 1",
            "auth login openai",
            "auth login anthropic",
            "cost",
            // knowledge base hints (ui_view_models/knowledge_base.rs)
            "attach README.md",
            // journey / cockpit verbs the NEXT banner and phase strip name
            "next",
            "workbench",
            "report",
            "setup",
            "open F-0001",
            "jobs",
            "replay run-123",
            "trace run-123",
            "run patch:finding",
        ];
        for command in advertised {
            assert!(
                !matches!(parse_command(command), ShellCommand::Unknown(_)),
                "advertised keypath {command:?} does not route; fix the hint or the parser"
            );
        }
    }

    #[test]
    fn featured_help_examples_are_alias_backed_and_routed() {
        let examples = shell_help_examples();
        assert_eq!(
            examples,
            vec![
                "demo",
                "next",
                "use semgrep",
                "run .",
                "findings",
                "open F-0001",
                "findings export report.sarif sarif"
            ]
        );

        for example in examples {
            assert!(
                shell_command_specs().any(|spec| spec.aliases.contains(&example)),
                "featured help example {example:?} is not backed by ShellCommandSpec.aliases"
            );
            assert!(
                !matches!(parse_command(example), ShellCommand::Unknown(_)),
                "featured help example {example:?} did not route"
            );
        }
    }

    fn route_kind(command: &ShellCommand) -> &'static str {
        match command {
            ShellCommand::Help(_) => "help",
            ShellCommand::Home => "home",
            ShellCommand::Report => "report",
            ShellCommand::Back => "back",
            ShellCommand::Modules => "modules",
            ShellCommand::Recommend => "recommend",
            ShellCommand::Tools(_) => "tools",
            ShellCommand::FavoriteTool(_) => "favorite-tool",
            ShellCommand::Workbench => "workbench",
            ShellCommand::Aim(_) => "aim",
            ShellCommand::Findings => "findings",
            ShellCommand::FindingsFilter(_) => "findings-filter",
            ShellCommand::Component(_) => "component",
            ShellCommand::Open(_) => "open",
            ShellCommand::Scan(_) => "scan",
            ShellCommand::LaunchStartView => "launch-start-view",
            ShellCommand::LaunchTargetPicker => "launch-target-picker",
            ShellCommand::ScriptedScan(_) => "scripted-scan",
            ShellCommand::Demo => "demo",
            ShellCommand::Model(_) => "model",
            ShellCommand::Auth => "auth",
            ShellCommand::AuthLogin(_) => "auth-login",
            ShellCommand::Provider(_) => "provider",
            ShellCommand::Backend(_) => "backend",
            ShellCommand::Cost => "cost",
            ShellCommand::Config => "config",
            ShellCommand::Health => "health",
            ShellCommand::Permissions => "permissions",
            ShellCommand::BootSplash => "boot-splash",
            ShellCommand::QuitConfirm => "quit-confirm",
            ShellCommand::ThemePicker => "theme-picker",
            ShellCommand::Keymap => "keymap",
            ShellCommand::UpdateAvailable => "update-available",
            ShellCommand::ProjectModel => "project-model",
            ShellCommand::Use(_) => "use",
            ShellCommand::Tune => "tune",
            ShellCommand::Threat(_) => "threat",
            ShellCommand::ThreatEditor => "threat-editor",
            ShellCommand::ThreatRegen => "threat-regen",
            ShellCommand::ThreatAsk(_) => "threat-ask",
            ShellCommand::ThreatApply => "threat-apply",
            ShellCommand::ThreatReject => "threat-reject",
            ShellCommand::ThreatVersions => "threat-versions",
            ShellCommand::ThreatVersionUse(_) => "threat-version-use",
            ShellCommand::Prompts => "prompts",
            ShellCommand::Prompt(_) => "prompt",
            ShellCommand::Actor(_) => "actor",
            ShellCommand::ShowRuns => "show-runs",
            ShellCommand::ShowJobs => "show-jobs",
            ShellCommand::CancelJob(_) => "cancel-job",
            ShellCommand::ShowCampaigns(_) => "campaigns",
            ShellCommand::ShowCoverage => "coverage",
            ShellCommand::QueueCommand(_) => "queue-command",
            ShellCommand::Background => "background",
            ShellCommand::RunDiff { .. } => "run-diff",
            ShellCommand::ShowAliases(_) => "show-aliases",
            ShellCommand::Since(_) => "since",
            ShellCommand::Replay(_) => "replay",
            ShellCommand::Trace(_) => "trace",
            ShellCommand::Activity => "activity",
            ShellCommand::FailureHandoff => "failure-handoff",
            ShellCommand::Plan(_) => "plan",
            ShellCommand::PhaseIntent { .. } => "phase-intent",
            ShellCommand::PlanApply => "plan-apply",
            ShellCommand::PlanDiscard => "plan-discard",
            ShellCommand::Quickstart => "quickstart",
            ShellCommand::Onboarding => "onboarding",
            ShellCommand::Next => "next",
            ShellCommand::NextFresh => "next-fresh",
            ShellCommand::Phase(_) => "phase",
            ShellCommand::Autonomy(_) => "autonomy",
            ShellCommand::Logs => "logs",
            ShellCommand::Target(_) => "target",
            ShellCommand::TargetRevision(_) => "target-revision",
            ShellCommand::Ask(_) => "ask",
            ShellCommand::Options { .. } => "options",
            ShellCommand::SetOption { .. } => "set-option",
            ShellCommand::UnsetOption { .. } => "unset-option",
            ShellCommand::Tasks => "tasks",
            ShellCommand::Task(_) => "task",
            ShellCommand::Context(_) => "context",
            ShellCommand::Workspace(_) => "workspace",
            ShellCommand::Strategy(_) => "strategy",
            ShellCommand::ReviewDecision(_) => "review-decision",
            ShellCommand::ProofDeferral { .. } => "proof-deferral",
            ShellCommand::Patch(_) => "patch",
            ShellCommand::Pwn(_) => "pwn",
            ShellCommand::KnowledgeBase(_) => "kb",
            ShellCommand::FilePicker => "file-picker",
            ShellCommand::Attach(_) => "attach",
            ShellCommand::Detach(_) => "detach",
            ShellCommand::Reparse(_) => "reparse",
            ShellCommand::SessionInfo => "session-info",
            ShellCommand::History => "history",
            ShellCommand::Clear => "clear",
            ShellCommand::Load(_) => "load",
            ShellCommand::Resume(_) => "resume",
            ShellCommand::Pause => "pause",
            ShellCommand::Cancel => "cancel",
            ShellCommand::Story => "story",
            ShellCommand::Scene => "scene",
            ShellCommand::RunTool { .. } => "run-tool",
            ShellCommand::Quit => "quit",
            ShellCommand::Empty => "empty",
            ShellCommand::Unknown(_) => "unknown",
        }
    }

    fn sample_help_form(form: &str) -> String {
        form.split_whitespace()
            .map(|part| match part {
                "<module>" => "sast".to_string(),
                "<tool>" => "sast:scan".to_string(),
                "<key>" => "severity".to_string(),
                "<value>" => "high".to_string(),
                "<id>" => "semgrep".to_string(),
                "<slice>" => "repo".to_string(),
                "<path>" => "findings.json".to_string(),
                "<path-or-url>" => "README.md".to_string(),
                "<run>" | "<runId>" => "run-123".to_string(),
                "<ref>" => "main".to_string(),
                "<provider>" => "openai".to_string(),
                "<map|scan|review|prove|fix>" => "prove".to_string(),
                "[recon|scan|review|prove|fix]" => "scan".to_string(),
                "<choice>" => "1".to_string(),
                "<question>" => "what now".to_string(),
                "<specifier>" => "builtin:sast".to_string(),
                "<verb>" => "show run".to_string(),
                "<n>" => "1".to_string(),
                "[json]" => String::new(),
                "[format]" => String::new(),
                "[tool]" => "sast:scan".to_string(),
                "[target]" => "./repo".to_string(),
                "[module]" => "context".to_string(),
                "[prefix]" => "F-00".to_string(),
                "[id]" => "semgrep".to_string(),
                "[1-4]" => "4".to_string(),
                "[choice]" => "1".to_string(),
                "[runId]" => "run-123".to_string(),
                "[--completeness" => "--completeness".to_string(),
                "open|complete]" => "open".to_string(),
                "[--allow-empty]" => "--allow-empty".to_string(),
                "auto|manual|toggle" => "auto".to_string(),
                other => other.to_string(),
            })
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}
