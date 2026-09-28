Feature: Foreground Map work owns Run Focus and restores its origin
  Start Map commits the selected plan into one Run Focus screen. Completion
  of a Map launched from Setup presents the durable Map result for explicit
  acceptance; background keeps work alive and restores Setup immediately.

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

  Scenario: Final completion presents the Map result for explicit acceptance
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Start Map"
    And I press "Enter"
    Then the file ".kuzushi/context-snapshot.json" eventually exists
    And the file ".kuzushi/entry-points.json" eventually exists
    And I see "RESULT READY Map ready"
    And I see "accept, continue with, or discard the completed Map result"
    And the status segment shows "workbench"

  Scenario: Background restores captured Setup without canceling the plan
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Start Map"
    And I press "Enter" then immediately "b"
    Then I see "SETUP · READY THE MAP RUN"
    And the status segment shows "setup"
    And the file ".kuzushi/context-snapshot.json" eventually exists
