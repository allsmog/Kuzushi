import { describe, expect, it } from "vitest";
import {
  __appModelBuildInternals,
  appModelBuildTask,
} from "../../../src/agents/tasks/app-model-build.js";
import type { RepoContext } from "../../../src/types.js";

const { collectRoutes } = __appModelBuildInternals;

function makeRepoContext(overrides: Partial<RepoContext> = {}): RepoContext {
  return {
    languages: ["Go"],
    frameworks: [],
    authPatterns: [],
    sanitizationLibs: [],
    ormOrDb: [],
    entryPoints: ["main.go"],
    ...overrides,
  };
}

describe("app-model-build task", () => {
  it("has correct task contract", () => {
    expect(appModelBuildTask.id).toBe("app-model-build");
    expect(appModelBuildTask.outputKind).toBe("custom");
    expect(appModelBuildTask.dependsOn).toContain("context-gatherer");
    expect(appModelBuildTask.dependsOn).toContain("context-enricher");
  });

  it("detects Go CLI, init, listener, and gRPC entrypoints", () => {
    const routes = collectRoutes(
      [
        {
          filePath: "main.go",
          content: `
package main

func init() {}

func runCLI() {
  flag.Parse()
}

func main() {
  lis, _ := net.Listen("tcp", ":50051")
  _ = lis
  srv := grpc.NewServer()
  _ = srv
}
        `.trim(),
        },
      ],
      makeRepoContext(),
      undefined,
    );

    expect(routes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ method: "INIT", path: "go://init", handlerSymbol: "init" }),
        expect.objectContaining({ method: "CLI", path: "cli://runCLI", handlerSymbol: "runCLI" }),
        expect.objectContaining({ method: "CLI", path: "cli://main", handlerSymbol: "main" }),
        expect.objectContaining({ method: "TCP", path: "tcp://:50051", handlerSymbol: "main" }),
        expect.objectContaining({ method: "GRPC", path: "grpc://main", handlerSymbol: "main" }),
      ]),
    );
  });
});
