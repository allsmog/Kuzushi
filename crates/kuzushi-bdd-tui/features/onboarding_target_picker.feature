Feature: Explicit target consent enters aggregate Setup
  A bare interactive launch presents Target before any engagement chrome.
  Highlighting shows facts; Enter activates the target. Esc explicitly chooses
  targetless capability browsing, and cwd is never silently substituted.

  Scenario: Bare launch opens Target before Setup
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell without a target
    Then I see "CHOOSE A TARGET"
    And the selected target consent is visible
    And the status segment shows "target-picker"
    And I do not see "SETUP · READY THE MAP RUN"

  Scenario: Explicit activation enters one readiness screen
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell without a target
    And I press "Enter"
    Then I see "SETUP · READY THE MAP RUN"
    And I see "Map plan"
    And I see "Credentials"
    And I see "Budget"
    And I see "Start Map"
    And the status segment shows "setup"

  Scenario: Esc browses without a target
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell without a target
    And I press "Esc"
    Then I see "CAPABILITIES"
    And the status segment shows "capabilities"

  Scenario: Skip-onboarding suppresses Target
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell without a target
    Then I do not see "CHOOSE A TARGET"
    And I see "no target"
