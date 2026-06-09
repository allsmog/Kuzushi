Feature: Auth-method picker
  After the model picker resolves to a provider with multiple auth
  methods, the auth-method picker should open and label both rows.

  Scenario: Selecting Anthropic opens the auth picker
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I press "Down"
    And I press "Down"
    And I press "Enter"
    Then I see "CHOOSE AUTH METHOD"
    And I see "API key (ANTHROPIC_API_KEY)"
    And I see "Claude.ai OAuth login"
    And the status segment shows "auth-picker:anthropic"

  Scenario: Esc on the auth picker defers and goes to Catalog
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I press "Down"
    And I press "Down"
    And I press "Enter"
    And I press "Esc"
    Then the log contains "auth deferred"
    And the status segment shows "modules"
