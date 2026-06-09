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

  Scenario: Esc skips every phase and finishes the engagement
    Given a fresh kuzushi workspace
    And a model and auth are configured
    When I launch the shell
    And I press "Esc"
    Then I see "phase 2 of 4"
    When I press "Esc"
    And I press "Esc"
    And I press "Esc"
    Then the status segment shows "recommend"
