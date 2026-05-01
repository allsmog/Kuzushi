/**
 * Per-language fuzz runner adapters.
 *
 * Each adapter declares how to:
 * - Detect whether the required toolchain is available on the host.
 * - Turn a harness file + corpus dir + duration into a concrete command line.
 * - Normalize a crash artifact path.
 *
 * The actual execution happens via `sandboxExec` in `sandbox.ts`; runners
 * only produce the command and interpret results. This keeps the fuzz-forge
 * module backend-agnostic and testable.
 */

import { existsSync } from "node:fs";
import path from "node:path";

export type FuzzLanguage = "c" | "cpp" | "rust" | "go" | "js" | "ts" | "python";

export interface RunnerAvailability {
  available: boolean;
  missingBins: string[];
  notes: string;
}

export interface FuzzRunPlan {
  /** argv array ready to hand to sandboxExec. */
  cmd: string[];
  /** Working directory the harness + corpus + crashes live in. */
  workdir: string;
  /** Relative path (from workdir) where crashes will be written. */
  crashDir: string;
  /** Relative path (from workdir) where the corpus lives. */
  corpusDir: string;
  /** Human-readable notes about the invocation (e.g. flags used). */
  notes: string;
}

export interface BuildRunPlanInput {
  /** Absolute path to the harness source file. */
  harnessPath: string;
  /** Working directory the run should use (writable). */
  workdir: string;
  /** Seconds of wall-clock fuzzing. */
  durationSec: number;
  /** Optional existing corpus directory. */
  corpusDir?: string;
  /** Optional dictionary file (libFuzzer -dict=...). */
  dictionary?: string;
  /** Extra fuzzer flags. */
  extraArgs?: string[];
  /** Sanitizers (informational — adapters include in build flags). */
  sanitizers?: Array<"asan" | "ubsan" | "msan" | "tsan">;
}

export interface FuzzRunner {
  id: string;
  language: FuzzLanguage[];
  /** Binaries required on PATH. */
  requiredBins: string[];
  /** Which sanitizers this runner typically supports. */
  supportedSanitizers: Array<"asan" | "ubsan" | "msan" | "tsan">;
  checkAvailability(which: (bin: string) => boolean): RunnerAvailability;
  buildRunPlan(input: BuildRunPlanInput): FuzzRunPlan;
}

// libFuzzer (C / C++)

export const libfuzzerRunner: FuzzRunner = {
  id: "libfuzzer",
  language: ["c", "cpp"],
  requiredBins: ["clang"],
  supportedSanitizers: ["asan", "ubsan", "msan"],
  checkAvailability(which) {
    const clang = which("clang");
    return {
      available: clang,
      missingBins: clang ? [] : ["clang"],
      notes: clang
        ? "clang + libFuzzer detected"
        : "install clang with -fsanitize=fuzzer to enable libFuzzer",
    };
  },
  buildRunPlan(input) {
    const corpusDir = input.corpusDir ?? path.join(input.workdir, "corpus");
    const crashDir = path.join(input.workdir, "crashes");
    const harnessBinary = path.join(input.workdir, "harness");
    const sanitizers = (input.sanitizers ?? ["asan", "ubsan"]).join(",");
    // Build command assumes `clang -fsanitize=fuzzer,<sanitizers>` with the
    // caller responsible for running it before invoking the fuzzer. The
    // run plan here covers only the execution phase.
    const cmd = [
      harnessBinary,
      `-max_total_time=${input.durationSec}`,
      `-artifact_prefix=${crashDir}/`,
      "-print_final_stats=1",
      ...(input.dictionary ? [`-dict=${input.dictionary}`] : []),
      ...(input.extraArgs ?? []),
      corpusDir,
    ];
    return {
      cmd,
      workdir: input.workdir,
      crashDir,
      corpusDir,
      notes: `libFuzzer ${sanitizers} — ${input.durationSec}s budget`,
    };
  },
};

// AFL++ (C / C++)

export const aflRunner: FuzzRunner = {
  id: "afl",
  language: ["c", "cpp"],
  requiredBins: ["afl-fuzz"],
  supportedSanitizers: ["asan", "ubsan"],
  checkAvailability(which) {
    const ok = which("afl-fuzz");
    return {
      available: ok,
      missingBins: ok ? [] : ["afl-fuzz"],
      notes: ok ? "AFL++ detected" : "install AFL++ to enable this runner",
    };
  },
  buildRunPlan(input) {
    const corpusDir = input.corpusDir ?? path.join(input.workdir, "corpus");
    const crashDir = path.join(input.workdir, "afl-out");
    const harnessBinary = path.join(input.workdir, "harness");
    const cmd = [
      "afl-fuzz",
      "-i",
      corpusDir,
      "-o",
      crashDir,
      "-V",
      String(input.durationSec),
      ...(input.dictionary ? ["-x", input.dictionary] : []),
      ...(input.extraArgs ?? []),
      "--",
      harnessBinary,
    ];
    return {
      cmd,
      workdir: input.workdir,
      crashDir: path.join(crashDir, "default", "crashes"),
      corpusDir,
      notes: `AFL++ — ${input.durationSec}s budget`,
    };
  },
};

// honggfuzz (C / C++)

export const honggfuzzRunner: FuzzRunner = {
  id: "honggfuzz",
  language: ["c", "cpp"],
  requiredBins: ["honggfuzz"],
  supportedSanitizers: ["asan", "ubsan", "msan"],
  checkAvailability(which) {
    const ok = which("honggfuzz");
    return {
      available: ok,
      missingBins: ok ? [] : ["honggfuzz"],
      notes: ok ? "honggfuzz detected" : "install honggfuzz to enable this runner",
    };
  },
  buildRunPlan(input) {
    const corpusDir = input.corpusDir ?? path.join(input.workdir, "corpus");
    const crashDir = path.join(input.workdir, "hf-crashes");
    const harnessBinary = path.join(input.workdir, "harness");
    const cmd = [
      "honggfuzz",
      "-i",
      corpusDir,
      "--crashdir",
      crashDir,
      "--run_time",
      String(input.durationSec),
      ...(input.dictionary ? ["--dict", input.dictionary] : []),
      ...(input.extraArgs ?? []),
      "--",
      harnessBinary,
      "___FILE___",
    ];
    return {
      cmd,
      workdir: input.workdir,
      crashDir,
      corpusDir,
      notes: `honggfuzz — ${input.durationSec}s budget`,
    };
  },
};

// cargo-fuzz (Rust)

export const cargoFuzzRunner: FuzzRunner = {
  id: "cargo-fuzz",
  language: ["rust"],
  requiredBins: ["cargo"],
  supportedSanitizers: ["asan"],
  checkAvailability(which) {
    const ok = which("cargo");
    return {
      available: ok,
      missingBins: ok ? [] : ["cargo"],
      notes: ok
        ? "cargo detected — ensure `cargo fuzz` subcommand is installed"
        : "install cargo + cargo-fuzz to enable this runner",
    };
  },
  buildRunPlan(input) {
    const workdir = input.workdir;
    const target = path.basename(input.harnessPath, path.extname(input.harnessPath));
    const crashDir = path.join(workdir, "fuzz", "artifacts", target);
    const corpusDir = input.corpusDir ?? path.join(workdir, "fuzz", "corpus", target);
    const cmd = [
      "cargo",
      "fuzz",
      "run",
      target,
      "--",
      `-max_total_time=${input.durationSec}`,
      ...(input.dictionary ? [`-dict=${input.dictionary}`] : []),
      ...(input.extraArgs ?? []),
    ];
    return {
      cmd,
      workdir,
      crashDir,
      corpusDir,
      notes: `cargo fuzz run ${target} — ${input.durationSec}s budget`,
    };
  },
};

// Go native fuzzing (`go test -fuzz`)

export const goFuzzRunner: FuzzRunner = {
  id: "go-fuzz",
  language: ["go"],
  requiredBins: ["go"],
  supportedSanitizers: [],
  checkAvailability(which) {
    const ok = which("go");
    return {
      available: ok,
      missingBins: ok ? [] : ["go"],
      notes: ok ? "go toolchain detected" : "install go >= 1.18 for native fuzzing",
    };
  },
  buildRunPlan(input) {
    const workdir = path.dirname(input.harnessPath);
    // Go fuzz target name is the Fuzz* function; assume caller passes
    // harnessPath pointing into the package dir. extraArgs can include
    // `-run=^$` and `-fuzz=FuzzName`.
    const cmd = [
      "go",
      "test",
      `-fuzz=${input.extraArgs?.find((a) => a.startsWith("Fuzz")) ?? "Fuzz"}`,
      `-fuzztime=${input.durationSec}s`,
      "-run=^$",
      ".",
    ];
    return {
      cmd,
      workdir,
      crashDir: path.join(workdir, "testdata", "fuzz"),
      corpusDir: input.corpusDir ?? path.join(workdir, "testdata", "corpus"),
      notes: `go test -fuzz — ${input.durationSec}s budget`,
    };
  },
};

// jazzer.js (JS / TS)

export const jazzerJsRunner: FuzzRunner = {
  id: "jazzer.js",
  language: ["js", "ts"],
  requiredBins: ["npx"],
  supportedSanitizers: [],
  checkAvailability(which) {
    const ok = which("npx");
    return {
      available: ok,
      missingBins: ok ? [] : ["npx"],
      notes: ok
        ? "npx detected — ensure @jazzer.js/core is installed in the target"
        : "install Node.js (npx) and @jazzer.js/core to enable this runner",
    };
  },
  buildRunPlan(input) {
    const workdir = input.workdir;
    const corpusDir = input.corpusDir ?? path.join(workdir, "corpus");
    const crashDir = path.join(workdir, "crashes");
    const cmd = [
      "npx",
      "jazzer",
      input.harnessPath,
      corpusDir,
      `-max_total_time=${input.durationSec}`,
      `-artifact_prefix=${crashDir}/`,
      ...(input.dictionary ? [`-dict=${input.dictionary}`] : []),
      ...(input.extraArgs ?? []),
    ];
    return {
      cmd,
      workdir,
      crashDir,
      corpusDir,
      notes: `jazzer.js — ${input.durationSec}s budget`,
    };
  },
};

// atheris (Python)

export const atherisRunner: FuzzRunner = {
  id: "atheris",
  language: ["python"],
  requiredBins: ["python3"],
  supportedSanitizers: ["asan", "ubsan"],
  checkAvailability(which) {
    const ok = which("python3");
    return {
      available: ok,
      missingBins: ok ? [] : ["python3"],
      notes: ok
        ? "python3 detected — ensure the `atheris` package is installed"
        : "install python3 and atheris to enable this runner",
    };
  },
  buildRunPlan(input) {
    const workdir = input.workdir;
    const corpusDir = input.corpusDir ?? path.join(workdir, "corpus");
    const crashDir = path.join(workdir, "crashes");
    const cmd = [
      "python3",
      input.harnessPath,
      corpusDir,
      `-max_total_time=${input.durationSec}`,
      `-artifact_prefix=${crashDir}/`,
      ...(input.dictionary ? [`-dict=${input.dictionary}`] : []),
      ...(input.extraArgs ?? []),
    ];
    return {
      cmd,
      workdir,
      crashDir,
      corpusDir,
      notes: `atheris — ${input.durationSec}s budget`,
    };
  },
};

// Registry

export const ALL_RUNNERS: FuzzRunner[] = [
  libfuzzerRunner,
  aflRunner,
  honggfuzzRunner,
  cargoFuzzRunner,
  goFuzzRunner,
  jazzerJsRunner,
  atherisRunner,
];

export function findRunnersForLanguage(language: FuzzLanguage): FuzzRunner[] {
  return ALL_RUNNERS.filter((r) => r.language.includes(language));
}

export function findRunnerById(id: string): FuzzRunner | undefined {
  return ALL_RUNNERS.find((r) => r.id === id);
}

/** A which() implementation that does filesystem lookup via PATH. */
export function realWhich(binary: string): boolean {
  const pathEnv = process.env.PATH ?? "";
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    if (existsSync(path.join(dir, binary))) return true;
  }
  return false;
}

/**
 * Return a report of all runner availability on this host. Useful for
 * module init diagnostics.
 */
export function surveyRunners(which: (bin: string) => boolean = realWhich): Array<{
  runner: FuzzRunner;
  availability: RunnerAvailability;
}> {
  return ALL_RUNNERS.map((runner) => ({
    runner,
    availability: runner.checkAvailability(which),
  }));
}
