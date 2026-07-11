Feature: Skip paths
  Esc on a phase picker hands off to the Workbench cockpit.
  The documented `KUZUSHI_SKIP_ONBOARDING` env bypasses the flow.

  Scenario: KUZUSHI_SKIP_ONBOARDING short-circuits to Workbench
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell
    Then the status segment shows "workbench"
    And I see "AIM - ATTACK SURFACE"
    And I do not see "CHOOSE A MODEL"

  Scenario: Esc leaves the phase picker for Workbench
    Given a fresh kuzushi workspace
    And a model and auth are configured
    When I launch the shell
    And I press "Esc"
    Then I see "AIM - ATTACK SURFACE"
    And the status segment shows "workbench"

  Scenario: Repeated Esc stays on Workbench
    Given a fresh kuzushi workspace
    And a model and auth are configured
    When I launch the shell
    And I press "Esc"
    And I press "Esc"
    And I press "Esc"
    And I press "Esc"
    Then I see "AIM - ATTACK SURFACE"
