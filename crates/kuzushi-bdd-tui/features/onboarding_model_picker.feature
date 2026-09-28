Feature: Model selection is an editor inside aggregate Setup
  Setup explains whether the selected Map plan needs a model. Enter on Model
  opens the catalog; leaving or selecting returns to the same Setup draft.

  Scenario: A keyless deterministic plan does not force a model picker
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    And I see "Model"
    And I see "NOT NEEDED"
    And the status segment shows "setup"

  Scenario: Enter on Model opens the model editor and Esc restores Setup
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I move the cursor to "Model"
    And I press "Enter"
    Then I see "CHOOSE A MODEL"
    And the status segment shows "setup:model"
    When I press "Esc"
    Then I see "SETUP · READY THE MAP RUN"
    And the status segment shows "setup"

  Scenario: The highlighted model identity is the selected identity
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I move the cursor to "Model"
    And I press "Enter"
    Then I see "CHOOSE A MODEL"
    When I move the cursor to "OpenAI OAuth GPT-5.6 Terra"
    When I press "Enter"
    Then I see "SETUP · READY THE MAP RUN"
    And the config file contains "openai-codex"
