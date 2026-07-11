Feature: Conditional MCP attachment plan
  When the operator launches the shell, kuzushi inspects which
  foundational artifacts exist under .kuzushi/ and logs a one-line MCP
  attachment summary. The plan is refreshed every time a planning task
  completes, so building a CPG or running context:build surfaces a new
  attachment without restarting the shell.

  Background:
    Given a fresh kuzushi workspace
    And a model and auth are configured
    And the env var "KUZUSHI_AUTO_OPEN_ACTIVITY" is set to "false"
    # Skip the phase picker; Workbench owns the first frame, so scenarios open
    # the full Logs surface before asserting startup MCP-plan transcript lines.
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"

  Scenario: Empty target shows only the constant MCPs
    When I launch the shell
    And I type command "logs"
    Then the log contains "MCP plan: treesitter"
    And I do not see "joern,"
    And I do not see "codeql,"

  Scenario: Pre-seeded context snapshot attaches the context MCP
    Given the artifact ".kuzushi/context-snapshot.json" is seeded with "{\"target\":\"x\"}"
    When I launch the shell
    And I type command "logs"
    Then the log contains "MCP plan: treesitter, context"

  Scenario: Pre-seeded CPG and CodeQL DB attach the joern + codeql MCPs
    Given the artifact ".kuzushi/cpg.bin" is seeded with "CPGSTUB"
    And the artifact ".kuzushi/codeql-db/codeql-database.yml" is seeded with "primaryLanguage: rust"
    When I launch the shell
    And I type command "logs"
    Then the log contains "joern"
    And the log contains "codeql"
