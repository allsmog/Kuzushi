Feature: Contextual surfaces restore the workflow origin
  Help and Capabilities are modal context. Jobs and visualization pages are
  full-frame decks. Esc restores the workflow page instead of replacing it.

  Background:
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured

  Scenario: Help restores the Map origin
    When I launch the shell
    Then I see "PROJECT CONTEXT"
    When I type text "help"
    And I press "Enter"
    Then I see "HELP"
    And the status segment shows "help"
    When I press "Esc"
    Then I see "PROJECT CONTEXT"
    And the status segment shows "workbench"

  Scenario: Jobs restores the Map origin
    When I launch the shell
    And I type text "jobs"
    And I press "Enter"
    Then I see "JOBS"
    And the status segment shows "jobs"
    When I press "Esc"
    Then I see "PROJECT CONTEXT"
    And the status segment shows "workbench"

  Scenario: The DFD remains available as a contextual visualization deck
    Given the artifact ".kuzushi/threat-model.json" is seeded with "{\"version\":\"2.0\",\"dfd\":{\"nodes\":[{\"id\":\"client\",\"type\":\"external-entity\",\"name\":\"Client\",\"trustZone\":\"external\"},{\"id\":\"api\",\"type\":\"process\",\"name\":\"API\",\"trustZone\":\"application\"},{\"id\":\"db\",\"type\":\"data-store\",\"name\":\"Orders DB\",\"trustZone\":\"data\"}],\"flows\":[{\"id\":\"f1\",\"sourceId\":\"client\",\"targetId\":\"api\",\"description\":\"HTTPS request\",\"trustBoundaryIds\":[\"edge\"]},{\"id\":\"f2\",\"sourceId\":\"api\",\"targetId\":\"db\",\"description\":\"SQL query\",\"trustBoundaryIds\":[\"data-boundary\"]}],\"trustBoundaries\":[]},\"threats\":[]}"
    When I launch the shell
    Then I see "Viewing Scan"
    When I type command "scene"
    Then I see "DATA-FLOW DIAGRAM"
    And I see "Client"
    And I see "Orders DB"
    And the status segment shows "viz:dfd"
    When I press "Esc"
    Then I see "Viewing Scan"
    And the status segment shows "workbench"
