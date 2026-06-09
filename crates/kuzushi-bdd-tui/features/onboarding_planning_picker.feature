Feature: Planning-stage multi-select
  Once model + auth are configured, the phase walker opens at
  組 KUMI-KATA · map with that phase's tasks and respects
  dependency-aware toggling.

  Background:
    Given a fresh kuzushi workspace
    And a model and auth are configured

  Scenario: Default selection covers the model-cheap prereqs plus STRIDE
    When I launch the shell
    Then I see "KUMI-KATA"
    And the status segment shows "planning"
    And "Gather repo context" is checked
    And "Map entry points" is checked
    And "Build STRIDE threat model" is checked
    And "Build PASTA threat model" is unchecked

  Scenario: Space toggles a row and auto-selects its dependencies
    When I launch the shell
    And I move the cursor to "Build PASTA threat model"
    And I press "Space"
    Then "Build PASTA threat model" is checked
    And "Gather repo context" is checked

  Scenario: Refuses to uncheck a dependency that others still need
    When I launch the shell
    And I move the cursor to "Gather repo context"
    And I press "Space"
    Then "Gather repo context" is checked
    And the log contains "cannot uncheck Gather repo context"

  Scenario: Enter runs the selected set and produces context-snapshot.json
    When I launch the shell
    And I press "Enter"
    Then the file ".kuzushi/context-snapshot.json" eventually exists
    And the file ".kuzushi/entry-points.json" eventually exists
