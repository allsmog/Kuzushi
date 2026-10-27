Feature: Session credential entry returns a readiness receipt
  A provider key can be pasted in-session without becoming product state or
  leaking its value. The credential editor then returns to aggregate Setup.

  Scenario: Pasted API key marks the selected provider ready for this session
    Given a fresh kuzushi workspace
    And the model is set to "anthropic:claude-sonnet-4-6"
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Credentials"
    And I press "Enter"
    And I type text "bdd-anthropic-key"
    And I press "Enter"
    Then I see "SETUP · READY THE MAP RUN"
    And I see "Credentials"
    And the status segment shows "Setup"
    And I do not see "bdd-anthropic-key"

  Scenario: The credential surface keeps a keyless escape hatch visible
    Given a fresh kuzushi workspace
    And the model is set to "anthropic:claude-sonnet-4-6"
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Credentials"
    And I press "Enter"
    Then I see "No key yet?"
    And I see "Offline demo"
    And I see "offline fixture"
