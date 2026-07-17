Feature: Patch re-verification requires an attributable application
  Re-verification is descriptor-backed and cannot invent application state or
  silently choose another detector. An operator must supply an application id
  created by a persisted apply receipt.

  Scenario: Re-verification without an application id is rejected explicitly
    Given a fresh kuzushi workspace
    And the env var "KUZUSHI_SKIP_ONBOARDING" is set to "1"
    And no model is configured
    When I launch the shell
    Then I see "PROJECT CONTEXT"
    When I type command "run patch:reverify"
    Then I see "applicationId"
    And I do not see "Verified"
