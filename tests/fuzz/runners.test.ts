import { describe, expect, it } from "vitest";
import {
  ALL_RUNNERS,
  aflRunner,
  atherisRunner,
  cargoFuzzRunner,
  findRunnerById,
  findRunnersForLanguage,
  goFuzzRunner,
  honggfuzzRunner,
  jazzerJsRunner,
  libfuzzerRunner,
  surveyRunners,
} from "../../src/fuzz/runners.js";

function alwaysAvailable(): boolean {
  return true;
}

function neverAvailable(): boolean {
  return false;
}

describe("fuzz/runners registry", () => {
  it("includes all 7 built-in runners", () => {
    expect(ALL_RUNNERS.map((r) => r.id).sort()).toEqual([
      "afl",
      "atheris",
      "cargo-fuzz",
      "go-fuzz",
      "honggfuzz",
      "jazzer.js",
      "libfuzzer",
    ]);
  });

  it("findRunnersForLanguage filters by language", () => {
    expect(findRunnersForLanguage("c").map((r) => r.id)).toEqual(["libfuzzer", "afl", "honggfuzz"]);
    expect(findRunnersForLanguage("go").map((r) => r.id)).toEqual(["go-fuzz"]);
    expect(findRunnersForLanguage("rust").map((r) => r.id)).toEqual(["cargo-fuzz"]);
    expect(findRunnersForLanguage("python").map((r) => r.id)).toEqual(["atheris"]);
    expect(findRunnersForLanguage("js").map((r) => r.id)).toEqual(["jazzer.js"]);
  });

  it("findRunnerById returns the matching runner", () => {
    expect(findRunnerById("libfuzzer")?.id).toBe("libfuzzer");
    expect(findRunnerById("nonexistent")).toBeUndefined();
  });

  it("surveyRunners reports availability using the injected which()", () => {
    const all = surveyRunners(alwaysAvailable);
    expect(all).toHaveLength(ALL_RUNNERS.length);
    for (const { availability } of all) expect(availability.available).toBe(true);

    const none = surveyRunners(neverAvailable);
    for (const { availability } of none) {
      expect(availability.available).toBe(false);
      expect(availability.missingBins.length).toBeGreaterThan(0);
    }
  });
});

describe("fuzz/runners run plans", () => {
  const baseInput = {
    harnessPath: "/w/fuzz_target.c",
    workdir: "/w",
    durationSec: 60,
  };

  it("libFuzzer plan: uses artifact_prefix and time cap", () => {
    const plan = libfuzzerRunner.buildRunPlan(baseInput);
    expect(plan.cmd[0]).toBe("/w/harness");
    expect(plan.cmd).toContain("-max_total_time=60");
    expect(plan.cmd.join(" ")).toContain("-artifact_prefix=/w/crashes/");
    expect(plan.crashDir).toBe("/w/crashes");
  });

  it("libFuzzer plan: includes dictionary when provided", () => {
    const plan = libfuzzerRunner.buildRunPlan({
      ...baseInput,
      dictionary: "/w/dict.txt",
    });
    expect(plan.cmd).toContain("-dict=/w/dict.txt");
  });

  it("AFL plan: honors duration and dictionary", () => {
    const plan = aflRunner.buildRunPlan({
      ...baseInput,
      dictionary: "/w/dict.txt",
    });
    expect(plan.cmd[0]).toBe("afl-fuzz");
    expect(plan.cmd).toContain("-V");
    expect(plan.cmd).toContain("60");
    expect(plan.cmd).toContain("-x");
    expect(plan.cmd).toContain("/w/dict.txt");
    expect(plan.crashDir).toBe("/w/afl-out/default/crashes");
  });

  it("honggfuzz plan: uses --run_time + ___FILE___ placeholder", () => {
    const plan = honggfuzzRunner.buildRunPlan(baseInput);
    expect(plan.cmd[0]).toBe("honggfuzz");
    expect(plan.cmd).toContain("--run_time");
    expect(plan.cmd).toContain("60");
    expect(plan.cmd).toContain("___FILE___");
  });

  it("cargo-fuzz plan: derives target from harness basename", () => {
    const plan = cargoFuzzRunner.buildRunPlan({
      ...baseInput,
      harnessPath: "/r/fuzz/fuzz_targets/parse.rs",
      workdir: "/r",
    });
    expect(plan.cmd.slice(0, 4)).toEqual(["cargo", "fuzz", "run", "parse"]);
    expect(plan.cmd).toContain("-max_total_time=60");
    expect(plan.crashDir.endsWith("artifacts/parse")).toBe(true);
  });

  it("go-fuzz plan: passes -fuzztime and runs in the package dir", () => {
    const plan = goFuzzRunner.buildRunPlan({
      ...baseInput,
      harnessPath: "/g/pkg/parser_fuzz_test.go",
      extraArgs: ["FuzzParse"],
    });
    expect(plan.cmd.slice(0, 2)).toEqual(["go", "test"]);
    expect(plan.cmd.some((a) => a === "-fuzz=FuzzParse")).toBe(true);
    expect(plan.cmd).toContain("-fuzztime=60s");
    expect(plan.workdir).toBe("/g/pkg");
  });

  it("jazzer.js plan: runs npx jazzer against the harness", () => {
    const plan = jazzerJsRunner.buildRunPlan({
      ...baseInput,
      harnessPath: "/w/fuzz/harness.js",
    });
    expect(plan.cmd.slice(0, 3)).toEqual(["npx", "jazzer", "/w/fuzz/harness.js"]);
    expect(plan.cmd).toContain("-max_total_time=60");
  });

  it("atheris plan: launches python3 against the harness", () => {
    const plan = atherisRunner.buildRunPlan({
      ...baseInput,
      harnessPath: "/w/fuzz/harness.py",
    });
    expect(plan.cmd[0]).toBe("python3");
    expect(plan.cmd).toContain("-max_total_time=60");
  });
});
