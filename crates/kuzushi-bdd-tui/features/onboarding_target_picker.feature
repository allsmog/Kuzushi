Feature: Launch-time target picker
  A bare interactive `kuzushi` with no `--target` opens the target picker as
  the first stage of the ordered onboarding gate. Nothing silently falls back
  to cwd — the operator picks a target, browses without one via Esc, or takes
  the offline demo escape hatch. `KUZUSHI_SKIP_ONBOARDING` suppresses the gate.

  Scenario: Bare launch opens the target picker first
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell without a target
    Then I see "CHOOSE A TARGET"
    And I see "offline fixture"
    And the selected target consent is visible
    And the status segment shows "target-picker"

  Scenario: Esc browses without a target
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell without a target
    And I press "Esc"
    Then the status segment shows "workbench"

  Scenario: Skip-onboarding suppresses the target picker
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell without a target
    Then I do not see "CHOOSE A TARGET"
    And the status segment shows "workbench"

  Scenario: Narrow full chain preserves target consent and plan confirmation
    Given a fresh kuzushi workspace
    And a 60 by 20 terminal
    And no model is configured
    When I launch the shell without a target
    Then the selected target consent is visible
    When I press "Enter"
    Then I see "CHOOSE A MODEL"
    And the confirmed target is visible
    When I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Enter"
    Then I see "CHOOSE AUTH METHOD"
    And the confirmed target is visible
    When I type text "bdd-anthropic-key"
    And I press "Enter"
    Then I see "KUMI-KATA"
    And the confirmed target is visible
    And I see "Inline action"
    And the Enter plan summary and controls are visible
    And I do not see "tool descriptor missing"
