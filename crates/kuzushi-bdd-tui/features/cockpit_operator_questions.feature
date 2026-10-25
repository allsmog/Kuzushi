Feature: Root-shell questions require reviewed Map context
  A root-shell question cannot bypass the current target and Map review gate.
  Kuzushi keeps the operator's question and names the exact recovery path.

  Scenario: A question before Map review is retained with recovery guidance
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And a model and auth are configured
    When I launch the shell
    And I submit shell command "/ask decide the scan scope"
    Then I see "Question needs a reviewed plan"
    And I see "Accept a current Map context before asking"
    And I see "your question is kept"
    And I do not see "WAITING INPUT"
