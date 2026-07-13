Feature: Auth-method picker
  After the model picker resolves to a provider with multiple auth
  methods, the auth-method picker should open and label both rows.

  Scenario: Selecting Anthropic opens the auth picker
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Enter"
    Then I see "CHOOSE AUTH METHOD"
    And I see "API key (ANTHROPIC_API_KEY)"
    And I see "Claude.ai OAuth login"
    And I see "Offline demo"
    And the status segment shows "auth-picker:anthropic"

  Scenario: q on the auth picker leaves setup for Workbench
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Enter"
    And I press "q"
    Then I see "AIM - ATTACK SURFACE"
    And the status segment shows "workbench"
