Feature: Durable phase pages survive in-place terminal resizing
  One live shell process keeps its selected canonical phase while tmux resizes
  through the supported cockpit matrix. Every assertion captures only the
  active alternate screen.

  Background:
    Given a fresh kuzushi workspace
    And a 160 by 48 terminal
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured

  Scenario Outline: A canonical phase survives the complete resize sequence
    When I launch the shell
    And I press "F2"
    And I press "<key>"
    Then an alternate-screen capture shows "Viewing <title>"
    When I resize the live terminal to 120 by 36
    Then the same shell process is still running
    And the resized live frame shows "<phase>"
    When I resize the live terminal to 80 by 24
    Then the same shell process is still running
    And the resized live frame shows "<phase>"
    When I resize the live terminal to 60 by 20
    Then the same shell process is still running
    And the resized live frame shows "<phase>"
    When I resize the live terminal to 40 by 12
    Then the same shell process is still running
    And the resized live frame shows "<phase>"
    When I resize the live terminal to 160 by 48
    Then the same shell process is still running
    And the resized live frame shows "Viewing <title>"

    Examples:
      | key | phase  | title  |
      | 1   | MAP    | Map    |
      | 2   | SCAN   | Scan   |
      | 3   | REVIEW | Review |
      | 4   | PROVE  | Prove  |
      | 5   | FIX    | Fix    |

  Scenario: A hidden compact fallback restores semantic focus when space returns
    Given the artifact ".kuzushi/context-snapshot.json" is seeded with "{\"target\":\"bdd\"}"
    And the artifact ".kuzushi/threat-model.json" is seeded with "{\"version\":\"2.0\",\"dfd\":{\"nodes\":[{\"id\":\"client\",\"type\":\"external-entity\",\"name\":\"Client\",\"trustZone\":\"external\"},{\"id\":\"api\",\"type\":\"process\",\"name\":\"API\",\"trustZone\":\"application\"}],\"flows\":[{\"id\":\"f1\",\"sourceId\":\"client\",\"targetId\":\"api\",\"description\":\"request\",\"trustBoundaryIds\":[]}],\"trustBoundaries\":[]},\"threats\":[]}"
    When I launch the shell
    And I press "F2"
    And I press "1"
    And I press "Tab"
    Then an alternate-screen capture shows "THREAT MODEL / DFD"
    When I resize the live terminal to 40 by 12
    Then the resized live frame shows "MAP"
    When I resize the live terminal to 160 by 48
    And I press "Z"
    Then an alternate-screen capture shows "ZOOM DFD"
    When I press "Z"
    Then an alternate-screen capture shows "Viewing Map"
