Feature: Foreground Map work owns Run Focus and restores its origin
  Start Map commits the selected plan into one Run Focus screen. Completion
  of preparation-only Map work restores Setup without claiming a phase result;
  background keeps work alive and restores Setup immediately.

  Scenario: Keyless deterministic Map opens one Steps and Output presentation
    Given a fresh kuzushi workspace
    And a 96 by 89 terminal
    And no model is configured
    When I launch the shell
    Then the live terminal is 96 by 89
    And I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Start Map"
    And I press "Enter"
    Then one Run Focus capture shows "TASKS" and "OUTPUT"

  Scenario: Preparation completion restores Setup without forging a Map result
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Start Map"
    And I press "Enter"
    Then the file ".kuzushi/context-snapshot.json" eventually exists
    And the file ".kuzushi/entry-points.json" eventually exists
    And I see "SETUP · READY THE MAP RUN"
    And I see "NOTHING TO RUN"
    And I see "run receipt · completed"
    And I do not see "RESULT READY"
    And the status segment shows "Setup"

  Scenario: Background restores captured Setup without canceling the plan
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Start Map"
    And I press "Enter" then immediately "b"
    Then I see "SETUP · READY THE MAP RUN"
    And the status segment shows "Setup"
    And the file ".kuzushi/context-snapshot.json" eventually exists
