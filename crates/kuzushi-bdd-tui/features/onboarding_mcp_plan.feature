Feature: Conditional MCP attachment plan
  When the operator launches the shell, Kuzushi inspects which
  foundational artifacts exist under .kuzushi/ and logs a one-line MCP
  attachment summary. The plan is refreshed every time a planning task
  completes, so building a CPG or running context:build surfaces a new
  attachment without restarting the shell.

  Background:
    Given a fresh kuzushi workspace
    And a model and auth are configured
    And the env var "KUZUSHI_AUTO_OPEN_ACTIVITY" is set to "false"
    # Skip Target/Setup; the reality-derived Map page owns the first frame, so
    # scenarios open Logs before asserting startup MCP-plan transcript lines.
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"

  Scenario: Empty target shows only the constant MCPs
    When I launch the shell
    Then the status segment shows "workbench"
    When I type command "logs"
    Then the log contains "MCP plan: treesitter"
    And I do not see "cpg,"
    And I do not see "codeql,"

  Scenario: Pre-seeded context snapshot attaches the context MCP
    Given the artifact ".kuzushi/context-snapshot.json" is seeded with "{\"target\":\"x\"}"
    When I launch the shell
    Then the status segment shows "workbench"
    When I type command "logs"
    Then the log contains "MCP plan: treesitter, context"

  Scenario: Pre-seeded CPG graphs and CodeQL DB attach the cpg + codeql MCPs
    # The cpg server only attaches for current-shape-version graphs
    # (<lang>.v<GRAPH_SHAPE_VERSION>.cpg) under .kuzushi/cpg-rs/.
    Given the artifact ".kuzushi/cpg-rs/rust.v11.cpg" is seeded with "CPGSTUB"
    And the artifact ".kuzushi/codeql-db/codeql-database.yml" is seeded with "primaryLanguage: rust"
    When I launch the shell
    Then the status segment shows "workbench"
    When I type command "logs"
    Then the log contains "cpg"
    And the log contains "codeql"
