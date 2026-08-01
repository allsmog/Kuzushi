Feature: Durable phase pages survive in-place terminal resizing
  One live shell process keeps an available canonical phase while tmux resizes
  through the supported cockpit matrix. Locked phases remain visibly locked
  instead of becoming selectable through a resize. Every assertion captures
  only the active alternate screen.

  Background:
    Given a fresh kuzushi workspace
    And a 160 by 48 terminal
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured

  Scenario: The available Map phase survives the complete resize sequence
    When I launch the shell
    And I press "Esc"
    And I press "1"
    Then an alternate-screen capture shows "Viewing Map"
    When I resize the live terminal to 120 by 36
    Then the same shell process is still running
    And the resized live frame shows "MAP"
    When I resize the live terminal to 80 by 24
    Then the same shell process is still running
    And the resized live frame shows "MAP"
    When I resize the live terminal to 60 by 20
    Then the same shell process is still running
    And the resized live frame shows "MAP"
    When I resize the live terminal to 40 by 12
    Then the same shell process is still running
    And the resized live frame shows "MAP"
    When I resize the live terminal to 160 by 48
    Then the same shell process is still running
    And the resized live frame shows "Viewing Map"

  Scenario Outline: Locked phases remain locked through a resize
    When I launch the shell
    And I press "Esc"
    And I press "<key>"
    Then an alternate-screen capture shows "<title> is locked"
    And an alternate-screen capture shows "Viewing Map"
    When I resize the live terminal to 40 by 12
    Then the same shell process is still running
    And the resized live frame shows "MAP"
    When I resize the live terminal to 160 by 48
    Then the same shell process is still running
    And the resized live frame shows "Viewing Map"

    Examples:
      | key | title  |
      | 2   | Scan   |
      | 3   | Review |
      | 4   | Prove  |
      | 5   | Fix    |

  Scenario: A contextual DFD survives compact fallback and restores its origin
    Given the artifact ".kuzushi/context-snapshot.json" is seeded with "{\"target\":\"bdd\"}"
    And the artifact ".kuzushi/threat-model.json" is seeded with "{\"version\":\"2.0\",\"dfd\":{\"nodes\":[{\"id\":\"client\",\"type\":\"external-entity\",\"name\":\"Client\",\"trustZone\":\"external\"},{\"id\":\"api\",\"type\":\"process\",\"name\":\"API\",\"trustZone\":\"application\"}],\"flows\":[{\"id\":\"f1\",\"sourceId\":\"client\",\"targetId\":\"api\",\"description\":\"request\",\"trustBoundaryIds\":[]}],\"trustBoundaries\":[]},\"threats\":[]}"
    When I launch the shell
    And I press "Esc"
    And I press "1"
    And I press "z"
    And I press "Tab"
    Then an alternate-screen capture shows "DATA-FLOW DIAGRAM"
    When I resize the live terminal to 40 by 12
    Then the resized live frame shows "DATA-FLOW DIAGRAM"
    When I resize the live terminal to 160 by 48
    Then an alternate-screen capture shows "DATA-FLOW DIAGRAM"
    And an alternate-screen capture shows "Client"
    When I press "Esc"
    Then an alternate-screen capture shows "Viewing Map"
