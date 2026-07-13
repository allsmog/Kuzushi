Feature: Inline credential entry
  A credentialed provider with no wired credentials opens an inline
  credential-entry step instead of dumping the operator on the Workbench.
  The offline demo is promoted as a first-class keyless escape hatch on the
  surface. Esc returns to model choice; q leaves setup for browsing.

  Scenario: Keyless model selection opens credential entry with the demo escape hatch
    Given a fresh kuzushi workspace
    And no model is configured
    When I launch the shell
    And I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Enter"
    Then I see "CHOOSE AUTH METHOD"
    And I see "No key yet?"
    And I see "Offline demo"
    And I see "offline fixture"

  Scenario: q on the credential step leaves setup for the Workbench
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
