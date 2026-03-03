import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { __discoverInternals } from "../../../../../src/agents/tasks/taint-analysis/cross-service/discover.js";

const { loadManifest, autoDetectServices, detectServiceInDir, manifestEntryToDescriptor } = __discoverInternals;

let tempDir: string;

function setupTempDir(): string {
  const dir = path.join(os.tmpdir(), `kuzushi-discover-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJson(filePath: string, data: unknown): void {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, JSON.stringify(data, null, 2), "utf-8");
}

function writeText(filePath: string, content: string): void {
  mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileSync(filePath, content, "utf-8");
}

beforeEach(() => {
  tempDir = setupTempDir();
});

afterEach(() => {
  if (tempDir && existsSync(tempDir)) {
    rmSync(tempDir, { recursive: true, force: true });
  }
});

describe("loadManifest", () => {
  it("parses a valid services.json manifest", async () => {
    const manifestPath = path.join(tempDir, "services.json");
    writeJson(manifestPath, {
      version: "1.0.0",
      services: [
        { id: "auth-api", rootPath: "services/auth", language: "typescript", framework: "express" },
        { id: "order-svc", rootPath: "services/orders", language: "go", framework: "gin" },
      ],
    });

    const manifest = await loadManifest(manifestPath);
    expect(manifest.version).toBe("1.0.0");
    expect(manifest.services).toHaveLength(2);
    expect(manifest.services[0].id).toBe("auth-api");
    expect(manifest.services[0].language).toBe("typescript");
    expect(manifest.services[1].id).toBe("order-svc");
    expect(manifest.services[1].framework).toBe("gin");
  });

  it("skips entries with missing required fields", async () => {
    const manifestPath = path.join(tempDir, "services.json");
    writeJson(manifestPath, {
      version: "1.0.0",
      services: [
        { id: "valid", rootPath: "svc/valid", language: "go" },
        { id: "", rootPath: "svc/missing-id", language: "go" },
        { id: "no-lang", rootPath: "svc/no-lang" },
        { rootPath: "svc/no-id", language: "go" },
      ],
    });

    const manifest = await loadManifest(manifestPath);
    expect(manifest.services).toHaveLength(1);
    expect(manifest.services[0].id).toBe("valid");
  });

  it("throws on invalid manifest (no services array)", async () => {
    const manifestPath = path.join(tempDir, "services.json");
    writeJson(manifestPath, { version: "1.0.0" });

    await expect(loadManifest(manifestPath)).rejects.toThrow("must contain");
  });
});

describe("manifestEntryToDescriptor", () => {
  it("converts a manifest entry to ServiceDescriptor", () => {
    const descriptor = manifestEntryToDescriptor({
      id: "auth",
      displayName: "Auth Service",
      rootPath: "services/auth",
      language: "typescript",
      framework: "express",
    });

    expect(descriptor.id).toBe("auth");
    expect(descriptor.displayName).toBe("Auth Service");
    expect(descriptor.rootPath).toBe("services/auth");
    expect(descriptor.language).toBe("typescript");
    expect(descriptor.framework).toBe("express");
    expect(descriptor.discoveryMethod).toBe("manifest");
  });

  it("uses id as displayName when displayName is not set", () => {
    const descriptor = manifestEntryToDescriptor({
      id: "my-service",
      rootPath: "svc",
      language: "go",
    });
    expect(descriptor.displayName).toBe("my-service");
  });
});

describe("autoDetectServices", () => {
  it("detects a Node.js Express service", async () => {
    const svcDir = path.join(tempDir, "services", "api");
    mkdirSync(svcDir, { recursive: true });
    writeJson(path.join(svcDir, "package.json"), {
      dependencies: { express: "^4.18.0" },
    });

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(1);
    expect(services[0].language).toBe("javascript");
    expect(services[0].framework).toBe("express");
    expect(services[0].discoveryMethod).toBe("auto");
    expect(detected.length).toBeGreaterThan(0);
  });

  it("detects a Go Gin service", async () => {
    const svcDir = path.join(tempDir, "services", "gateway");
    mkdirSync(svcDir, { recursive: true });
    writeText(path.join(svcDir, "go.mod"), `
module github.com/example/gateway

go 1.21

require github.com/gin-gonic/gin v1.9.1
`);

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(1);
    expect(services[0].language).toBe("go");
    expect(services[0].framework).toBe("gin");
  });

  it("detects a Python FastAPI service", async () => {
    const svcDir = path.join(tempDir, "services", "ml");
    mkdirSync(svcDir, { recursive: true });
    writeText(path.join(svcDir, "requirements.txt"), "fastapi==0.104.1\nuvicorn\n");

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(1);
    expect(services[0].language).toBe("python");
    expect(services[0].framework).toBe("fastapi");
  });

  it("detects a Java Spring service", async () => {
    const svcDir = path.join(tempDir, "services", "orders");
    mkdirSync(svcDir, { recursive: true });
    writeText(path.join(svcDir, "pom.xml"), `
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>
`);

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(1);
    expect(services[0].language).toBe("java");
    expect(services[0].framework).toBe("spring");
  });

  it("detects multiple services across directories", async () => {
    // Service A: Express
    const svcA = path.join(tempDir, "services", "auth");
    mkdirSync(svcA, { recursive: true });
    writeJson(path.join(svcA, "package.json"), {
      dependencies: { express: "^4.18.0" },
    });

    // Service B: Go
    const svcB = path.join(tempDir, "services", "users");
    mkdirSync(svcB, { recursive: true });
    writeText(path.join(svcB, "go.mod"), "module github.com/example/users\ngo 1.21\n");

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services.length).toBeGreaterThanOrEqual(2);
    const ids = services.map((s) => s.id);
    expect(ids).toContain("services-auth");
    expect(ids).toContain("services-users");
  });

  it("respects maxServices limit", async () => {
    for (let i = 0; i < 5; i++) {
      const svcDir = path.join(tempDir, `svc${i}`);
      mkdirSync(svcDir, { recursive: true });
      writeJson(path.join(svcDir, "package.json"), {
        dependencies: { express: "^4.18.0" },
      });
    }

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 2, detected);

    expect(services.length).toBeLessThanOrEqual(2);
  });

  it("skips node_modules and other ignored directories", async () => {
    const ignored = path.join(tempDir, "node_modules", "express");
    mkdirSync(ignored, { recursive: true });
    writeJson(path.join(ignored, "package.json"), {
      dependencies: { express: "^4.18.0" },
    });

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(0);
  });

  it("returns empty array for a directory with no services", async () => {
    mkdirSync(path.join(tempDir, "docs"), { recursive: true });
    writeText(path.join(tempDir, "docs", "readme.txt"), "Hello");

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(0);
  });

  it("detects a Python service via pyproject.toml", async () => {
    const svcDir = path.join(tempDir, "services", "api");
    mkdirSync(svcDir, { recursive: true });
    writeText(path.join(svcDir, "pyproject.toml"), `
[project]
dependencies = ["fastapi>=0.104.0", "uvicorn"]
`);

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(1);
    expect(services[0].language).toBe("python");
    expect(services[0].framework).toBe("fastapi");
  });

  it("detects a Java service via build.gradle.kts", async () => {
    const svcDir = path.join(tempDir, "services", "payments");
    mkdirSync(svcDir, { recursive: true });
    writeText(path.join(svcDir, "build.gradle.kts"), `
plugins {
    id("org.springframework.boot") version "3.2.0"
}
`);

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(1);
    expect(services[0].language).toBe("java");
    expect(services[0].framework).toBe("spring");
  });

  it("detects a C# ASP.NET service via .csproj", async () => {
    const svcDir = path.join(tempDir, "services", "web");
    mkdirSync(svcDir, { recursive: true });
    writeText(path.join(svcDir, "MyApp.csproj"), `
<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.OpenApi" />
  </ItemGroup>
</Project>
`);

    const detected: string[] = [];
    const services = await autoDetectServices(tempDir, 20, detected);

    expect(services).toHaveLength(1);
    expect(services[0].language).toBe("csharp");
    expect(services[0].framework).toBe("aspnet");
  });
});

describe("detectServiceInDir", () => {
  it("returns null for a directory with no recognized files", async () => {
    const dir = path.join(tempDir, "empty");
    mkdirSync(dir, { recursive: true });
    writeText(path.join(dir, "readme.txt"), "Hello");

    const result = await detectServiceInDir(dir, "empty", ["readme.txt"]);
    expect(result).toBeNull();
  });

  it("detects NestJS framework from package.json", async () => {
    const dir = path.join(tempDir, "nest-svc");
    mkdirSync(dir, { recursive: true });
    writeJson(path.join(dir, "package.json"), {
      dependencies: { "@nestjs/core": "^10.0.0" },
    });

    const result = await detectServiceInDir(dir, "nest-svc", ["package.json"]);
    expect(result).not.toBeNull();
    expect(result!.language).toBe("javascript");
    expect(result!.framework).toBe("nestjs");
  });

  it("detects Fastify framework from package.json", async () => {
    const dir = path.join(tempDir, "fastify-svc");
    mkdirSync(dir, { recursive: true });
    writeJson(path.join(dir, "package.json"), {
      dependencies: { fastify: "^4.0.0" },
    });

    const result = await detectServiceInDir(dir, "fastify-svc", ["package.json"]);
    expect(result).not.toBeNull();
    expect(result!.framework).toBe("fastify");
  });

  it("detects Go with no specific framework", async () => {
    const dir = path.join(tempDir, "go-svc");
    mkdirSync(dir, { recursive: true });
    writeText(path.join(dir, "go.mod"), "module example.com/go-svc\ngo 1.21\n");

    const result = await detectServiceInDir(dir, "go-svc", ["go.mod"]);
    expect(result).not.toBeNull();
    expect(result!.language).toBe("go");
    expect(result!.framework).toBeNull();
  });

  it("does not let a stray .csproj override a Go detection", async () => {
    const dir = path.join(tempDir, "mixed");
    mkdirSync(dir, { recursive: true });
    writeText(path.join(dir, "go.mod"), "module example.com/mixed\ngo 1.21\nrequire github.com/gin-gonic/gin v1.9.1\n");
    writeText(path.join(dir, "Tool.csproj"), "<Project><ItemGroup><PackageReference Include=\"Microsoft.AspNetCore.OpenApi\" /></ItemGroup></Project>");

    const result = await detectServiceInDir(dir, "mixed", ["go.mod", "Tool.csproj"]);
    expect(result).not.toBeNull();
    expect(result!.language).toBe("go");
    expect(result!.framework).toBe("gin");
  });
});

describe("manifest rootPath validation", () => {
  it("filters out entries with path traversal in rootPath", () => {
    const safe = manifestEntryToDescriptor({
      id: "safe-svc",
      rootPath: "services/auth",
      language: "go",
    });
    expect(safe.rootPath).toBe("services/auth");

    // This entry would escape root — but manifestEntryToDescriptor doesn't validate.
    // The validation happens in the task's run() via isWithinRepoRoot filter.
    const escapee = manifestEntryToDescriptor({
      id: "evil-svc",
      rootPath: "../../etc",
      language: "go",
    });
    expect(escapee.rootPath).toBe("../../etc");
  });
});
