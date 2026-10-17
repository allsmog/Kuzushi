import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { threatLeadsPublicationChecks } from "./artifact-manifest-contract.mjs";

const root = new URL("../crates/kuzushi-core/src/capabilities/threat_leads/", import.meta.url);
const source = readFileSync(new URL("mod.rs", root), "utf8");
const publication = readFileSync(new URL("publication.rs", root), "utf8");

test("lead artifact contract follows the extracted publisher and explicit repair", () => {
  assert.deepEqual(threatLeadsPublicationChecks(source, publication), []);
});

test("lead artifact contract rejects detached publisher, JSON, summary and repair paths", () => {
  for (const [index, token, expected] of [
    [0, "publication::publish(&target, &report)", "build must use its publisher"],
    [
      1,
      "let artifact_path = threat_leads_artifact_path(target)",
      "write must use threat_leads_artifact_path",
    ],
    [
      1,
      "let summary_path = threat_leads_summary_path(target)",
      "write must use threat_leads_summary_path",
    ],
    [
      1,
      "let path = threat_leads_summary_path(target)",
      "repair must use threat_leads_summary_path",
    ],
  ]) {
    const changed = [source, publication];
    changed[index] = changed[index].replaceAll(token, "detached_output()");
    assert.ok(
      threatLeadsPublicationChecks(...changed).some((failure) => failure.includes(expected)),
    );
  }
});
