Feature: First-run model picker
  When no model is configured, launching the shell should drop the
  operator on the model picker with the cursor on the first row.

  Scenario: No model configured opens the picker
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "CHOOSE A MODEL"
    And the status segment shows "model-picker"

  Scenario: Arrow keys move the cursor
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I press "Down"
    And I press "Down"
    Then I see "> Claude Sonnet 4.6"

  Scenario: Esc on the model picker falls through to Catalog
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I press "Esc"
    Then the log contains "model selection deferred"
    And the status segment shows "modules"
