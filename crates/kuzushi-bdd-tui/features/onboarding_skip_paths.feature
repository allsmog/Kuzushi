Feature: Skip paths
  Esc on a phase picker skips that phase and advances to the next one;
  past the last phase the shell hands off to next-step recommendations.
  The documented `KUZUSHI_SKIP_ONBOARDING` env bypasses the flow.

  Scenario: KUZUSHI_SKIP_ONBOARDING short-circuits to Catalog
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell
    Then the status segment shows "modules"
    And I do not see "CHOOSE A MODEL"

  Scenario: Esc skips the phase and advances to the next
    Given a fresh kuzushi workspace
    And a model and auth are configured
    When I launch the shell
    And I press "Esc"
    Then I see "KUZUSHI · hunt"
    And the status segment shows "planning"

  Scenario: Esc through every phase hands off to recommendations
    Given a fresh kuzushi workspace
    And a model and auth are configured
    When I launch the shell
    And I press "Esc"
    And I press "Esc"
    And I press "Esc"
    And I press "Esc"
    # Assert the stable handoff (the Recommend view header), not the transient
    # "ranking modules" transcript line — the 2-row strip scrolls it away as
    # soon as the background recommender logs again, which races the poller
    # on slow CI runners.
    Then I see "RECOMMEND"
