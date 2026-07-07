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
    And the status segment shows "target-picker"

  Scenario: Esc browses without a target
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell without a target
    And I see "CHOOSE A TARGET"
    And I press "Esc"
    Then I see "AIM - ATTACK SURFACE"
    And the log contains "browsing without a target"

  Scenario: Skip-onboarding suppresses the target picker
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell without a target
    Then I do not see "CHOOSE A TARGET"
    And the status segment shows "modules"
