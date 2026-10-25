Feature: Slash commands open the requested phase planner
  The five phase shortcuts open that phase's planning surface without starting
  work. The full command, and its pipeline alias, enter bounded Setup. A phase
  shortcut without a target asks for explicit consent and resumes the requested
  planner after the target is selected.

  Background:
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured

  Scenario Outline: A phase shortcut opens only that phase's planner
    When I launch the shell
    And I type command "<command>"
    Then I see "<task>"
    And I do not see "SETUP · MAP PLAN"
    And I do not see "MAP · ROUTE"
    And I do not see "RUN FOCUS"

    Examples:
      | command | task                |
      | /map    | Gather repo context |
      | /scan   | PLAN A STUDY        |
      | /review | Triage findings     |
      | /prove  | Verify findings     |
      | /fix    | Patch findings      |

  Scenario: Scan rejects the former target argument with migration guidance
    When I launch the shell
    And I type command "/scan ."
    Then I see "scan opens the Scan phase planner and no longer accepts a target."
    And I see "full <path>"
    And I see "Viewing Map"
    And I do not see "MAP · ROUTE"
    And I do not see "RUN FOCUS"

  Scenario: A targetless phase shortcut resumes after explicit target consent
    When I launch the shell without a target
    And I type command "/map"
    Then I see "CHOOSE A TARGET"
    And the selected target consent is visible
    And the status segment shows "target-picker"
    And I do not see "Gather repo context"
    When I press "Enter"
    Then I see "Gather repo context"
    And the confirmed target is visible
    And the status segment shows "planning"
    And I do not see "SETUP · MAP PLAN"
    And I do not see "MAP · ROUTE"

  Scenario Outline: Full and pipeline enter bounded Setup
    When I launch the shell
    And I type command "<command>"
    Then I see "SETUP · READY THE MAP RUN"
    And I see "Map plan"
    And I see "Start Map"
    And the status segment shows "setup"
    And I do not see "MAP · ROUTE"
    And I do not see "Scan for secrets"
    And I do not see "RUN FOCUS"

    Examples:
      | command   |
      | /full     |
      | /pipeline |

  Scenario: Full accepts an explicit target from targetless browsing
    When I launch the shell without a target
    And I type command "/full ."
    Then I see "SETUP · READY THE MAP RUN"
    And I see "Map plan"
    And I see "Start Map"
    And the status segment shows "setup"
    And I do not see "MAP · ROUTE"
    And I do not see "CHOOSE A TARGET"
    And I do not see "RUN FOCUS"
