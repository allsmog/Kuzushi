Feature: Root-shell operator questions pause and resume deterministic work
  A root-shell agent may pause for an operator decision without blocking the
  TUI. Backgrounding preserves the question as live job state, and reopening
  Run Focus resumes the exact tool loop after an explicit answer.

  Scenario: A backgrounded operator question remains in Jobs and resumes from Activity
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And a model and auth are configured
    And a deterministic operator-question bridge is configured
    When I launch the shell
    And I submit shell command "/ask decide the scan scope"
    Then the deterministic operator question card appears
    And I see "WAITING INPUT"
    And I see "Choose the scan scope."
    And I see "Changed files"
    And I see "Repository"
    When I press "b"
    Then I see "PROJECT CONTEXT"
    And I do not see "Choose the scan scope."
    When I submit shell command "jobs"
    Then I see "JOBS"
    And I see "WAITING INPUT"
    When I submit shell command "activity"
    Then I see "WAITING INPUT"
    And I see "Choose the scan scope."
    When I press "2"
    Then I do not see "Choose the scan scope."
    When I press "b"
    Then I see "PROJECT CONTEXT"
    When I submit shell command "logs"
    Then I see "Operator chose repository scope; deterministic answer complete."
