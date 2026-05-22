Feature: Skip paths
  Esc out of every picker should fall through cleanly, and the
  documented `KUZUSHI_SKIP_ONBOARDING` env should bypass the flow.

  Scenario: KUZUSHI_SKIP_ONBOARDING short-circuits to Catalog
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell
    Then the status segment shows "modules"
    And I do not see "CHOOSE A MODEL"

  Scenario: Esc from planning picker falls through
    Given a fresh kuzushi workspace
    And a model and auth are configured
    When I launch the shell
    And I press "Esc"
    Then the log contains "planning skipped"
    And the status segment shows "modules"
