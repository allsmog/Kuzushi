Feature: Report is a durable exit surface
  Report exposes all six formats, defaults to All completeness, and remains on
  the route for both export receipts and errors.

  Background:
    Given a fresh kuzushi workspace
    And no model is configured

  Scenario: Report exposes every format in locked order
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Esc"
    And I type command "report"
    Then I see "── REPORT ──"
    And I see "sarif · markdown-bundle · jsonl · json · csv · vuln-findings"
    And I see "format sarif (1/6)"
    And I see "all"
    And the status segment shows "report"

  Scenario: Completeness cycles without leaving Report
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Esc"
    And I type command "report"
    And I press "c"
    Then I see "open"
    And the status segment shows "report"

  Scenario: Empty-workspace export returns a durable receipt on Report
    When I launch the shell
    Then I see "SETUP · READY THE MAP RUN"
    When I press "Esc"
    And I type command "report"
    And I press "Enter"
    Then I see "── EXPORTED ──"
    And I see "timestamp"
    And I see "reports/report.sarif"
    And the status segment shows "report"
    When I press "Esc"
    Then I see "PROJECT CONTEXT"
    And the status segment shows "workbench"
