Feature: Five phase modes are real interactive Workbench states
  Shift+Tab uses the literal xterm BackTab sequence and cycles available phase
  pages without replacing durable workspace reality or the shared composer.
  Navigate mode exposes direct positional access through 1..5 and explains
  why a requested page is locked.

  Background:
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured

  Scenario: Literal xterm BackTab skips locked modes and preserves the draft cursor
    When I launch the shell
    Then an alternate-screen capture shows "Viewing Map"
    When I type text "alphaomega"
    And I press "Left"
    And I press "Left"
    And I press "Left"
    And I press "Left"
    And I press "Left"
    And I send literal xterm BackTab
    Then an alternate-screen capture shows "Viewing Map"
    And an alternate-screen capture shows "◇ MAP VIEW › alphaomega"
    When I type text "-"
    Then an alternate-screen capture shows "◇ MAP VIEW › alpha-omega"
    When I send literal xterm BackTab
    Then an alternate-screen capture shows "Viewing Map"
    And an alternate-screen capture shows "◇ MAP VIEW › alpha-omega"

  Scenario: Navigate numbers select available modes and disclose locked modes
    Given the artifact ".kuzushi/context-snapshot.json" is seeded with "{\"target\":\"bdd\",\"filesIndexed\":1}"
    When I launch the shell
    Then an alternate-screen capture shows "Viewing Scan"
    When I press "Esc"
    And I press "1"
    Then one alternate-screen row shows "Viewing Map" and "next required Scan"
    And an alternate-screen capture shows "◇ MAP VIEW › NAVIGATE"
    When I press "2"
    Then an alternate-screen capture shows "Viewing Scan"
    And an alternate-screen capture shows "▦ SCAN VIEW › NAVIGATE"
    When I press "3"
    Then an alternate-screen capture shows "Review is locked"
    And an alternate-screen capture shows "Viewing Scan"
