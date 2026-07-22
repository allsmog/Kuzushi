Feature: Compact Run Focus remains operable in a real terminal
  At 60 columns, Run Focus stacks its authoritative task checklist above live
  output without dropping either pane or reviving the generic shell prompt.

  Scenario: Keyless deterministic Map stacks Tasks above Output at 60 by 20
    Given a fresh kuzushi workspace
    And a 60 by 20 terminal
    And no model is configured
    When I launch the shell
    Then the live terminal is 60 by 20
    And I see "SETUP · READY THE MAP RUN"
    When I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Down"
    And I press "Enter"
    Then one compact Run Focus capture shows plan "context:build" then "entry-points:extract" with "STEPS" above "OUTPUT" without a shell prompt
