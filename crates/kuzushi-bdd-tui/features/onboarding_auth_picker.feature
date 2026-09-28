Feature: Credential readiness is an editor inside aggregate Setup
  Credentials block only selected model-backed Map tasks. Setup routes the
  explicit provider to API-key, stored-OAuth, session, or offline choices and
  returns without discarding the Map plan.

  Scenario: Enter on missing Anthropic credentials opens its auth methods
    Given a fresh kuzushi workspace
    And the model is set to "anthropic:claude-sonnet-4-6"
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Credentials"
    And I press "Enter"
    Then I see "CHOOSE AUTH METHOD"
    And I see "API key (ANTHROPIC_API_KEY)"
    And I see "Claude.ai OAuth login"
    And I see "Offline demo"
    And the status segment shows "setup:credentials:anthropic"

  Scenario: Esc returns from credentials to the same Setup screen
    Given a fresh kuzushi workspace
    And the model is set to "anthropic:claude-sonnet-4-6"
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I move the cursor to "Credentials"
    And I press "Enter"
    And I press "Esc"
    Then I see "SETUP · READY THE MAP RUN"
    And I see "Map plan"
    And the status segment shows "setup"
