Feature: Five phase modes are real interactive Workbench states
  Shift+Tab uses the literal xterm BackTab sequence and cycles the five phase
  modes without replacing durable workspace reality or the shared composer.
  Navigate mode also exposes direct positional access through 1..5.

  Background:
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured

  Scenario: Literal xterm BackTab wraps all five modes and preserves the draft cursor
    When I launch the shell
    Then an alternate-screen capture shows "VIEW MAP"
    When I type text "alphaomega"
    And I press "Left"
    And I press "Left"
    And I press "Left"
    And I press "Left"
    And I press "Left"
    And I send literal xterm BackTab
    Then one alternate-screen row shows "VIEW SCAN" and "REALITY MAP"
    And an alternate-screen capture shows "▦ SCAN › alphaomega"
    When I type text "-"
    Then an alternate-screen capture shows "▦ SCAN › alpha-omega"
    When I send literal xterm BackTab
    Then an alternate-screen capture shows "VIEW REVIEW"
    And an alternate-screen capture shows "▣ REVIEW › alpha-omega"
    When I send literal xterm BackTab
    Then an alternate-screen capture shows "VIEW PROVE"
    And an alternate-screen capture shows "◎ PROVE › alpha-omega"
    When I send literal xterm BackTab
    Then an alternate-screen capture shows "VIEW FIX"
    And an alternate-screen capture shows "◆ FIX › alpha-omega"
    When I send literal xterm BackTab
    Then an alternate-screen capture shows "VIEW MAP"
    And an alternate-screen capture shows "◇ MAP › alpha-omega"

  Scenario: Navigate numbers select all modes while durable Map evidence keeps reality at Scan
    Given the artifact ".kuzushi/context-snapshot.json" is seeded with "{\"target\":\"bdd\",\"filesIndexed\":1}"
    When I launch the shell
    Then an alternate-screen capture shows "VIEW SCAN"
    When I press "F2"
    And I press "1"
    Then one alternate-screen row shows "VIEW MAP" and "REALITY SCAN"
    And an alternate-screen capture shows "◇ MAP › NAVIGATE"
    When I press "2"
    Then an alternate-screen capture shows "VIEW SCAN"
    And an alternate-screen capture shows "▦ SCAN › NAVIGATE"
    When I press "3"
    Then one alternate-screen row shows "VIEW REVIEW" and "REALITY SCAN"
    And an alternate-screen capture shows "▣ REVIEW › NAVIGATE"
    When I press "4"
    Then an alternate-screen capture shows "VIEW PROVE"
    And an alternate-screen capture shows "◎ PROVE › NAVIGATE"
    When I press "5"
    Then an alternate-screen capture shows "VIEW FIX"
    And an alternate-screen capture shows "◆ FIX › NAVIGATE"
