Feature: Setup remains explicitly reachable
  Esc leaves aggregate Setup for the reality-derived workflow page. The
  documented onboarding bypass remains available for controlled environments,
  and /setup returns to readiness without forging phase progress.

  Scenario: Skip-onboarding opens the workflow page
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell
    Then I see "Viewing Map"
    And I see "PROJECT CONTEXT"
    And I do not see "SETUP · READY THE MAP RUN"

  Scenario: Esc leaves Setup for the reality-derived Map page
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Esc"
    Then I see "PROJECT CONTEXT"
    And I see "Viewing Map"

  Scenario: Setup can be reopened explicitly
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Esc"
    And I type command "setup"
    Then I see "SETUP · READY THE MAP RUN"
    And the status segment shows "Setup"
