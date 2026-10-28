Feature: Map-plan editing returns to aggregate Setup
  Setup owns one Map plan row. Its editor preserves dependency-aware selection,
  and Enter saves the plan without starting work. Start Map is the only commit.

  Background:
    Given a fresh kuzushi workspace
    And a model and auth are configured

  Scenario: Map plan starts with deterministic quick-value tasks
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Down"
    And I press "Enter"
    Then I see "SETUP · MAP PLAN"
    And the status segment shows "Setup"
    And "Gather repo context" is checked
    And "Map entry points" is checked
    And "Attach reference files" is unchecked
    And "Build threat model" is unchecked

  Scenario: Space keeps dependency-aware selection
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Down"
    And I press "Enter"
    And I move the cursor to "Build threat model"
    And I press "Space"
    Then "Build threat model" is checked
    And "Gather repo context" is checked

  Scenario: Enter saves the plan and returns without launching
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Down"
    And I press "Enter"
    And I press "Enter"
    Then I see "SETUP · READY THE MAP RUN"
    And the status segment shows "Setup"
    And I do not see "TASKS"
