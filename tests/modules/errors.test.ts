import { describe, expect, it } from "vitest";
import { ModuleLoadError } from "../../src/modules/errors.js";

describe("ModuleLoadError", () => {
  it("extends Error with a code discriminator", () => {
    const err = new ModuleLoadError("MANIFEST_MISSING", "missing");
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ModuleLoadError);
    expect(err.code).toBe("MANIFEST_MISSING");
    expect(err.message).toBe("missing");
    expect(err.name).toBe("ModuleLoadError");
  });

  it("preserves details payload", () => {
    const err = new ModuleLoadError("SHAPE_INVALID", "bad shape", {
      moduleId: "foo",
      errors: ["a", "b"],
    });
    expect(err.details).toEqual({ moduleId: "foo", errors: ["a", "b"] });
  });

  it("omits details when not provided", () => {
    const err = new ModuleLoadError("SDK_INCOMPATIBLE", "nope");
    expect(err.details).toBeUndefined();
  });

  it("is catchable as Error (backward compatibility)", () => {
    try {
      throw new ModuleLoadError("ENTRY_NOT_FOUND", "gone");
    } catch (err) {
      // Callers that match on Error.message keep working.
      expect(err instanceof Error).toBe(true);
      expect((err as Error).message).toContain("gone");
    }
  });

  it("round-trips through JSON.stringify for logging", () => {
    const err = new ModuleLoadError("REQUIREMENTS_UNMET", "missing npm", { bin: "npm" });
    const json = JSON.parse(
      JSON.stringify({
        name: err.name,
        code: err.code,
        message: err.message,
        details: err.details,
      }),
    );
    expect(json.code).toBe("REQUIREMENTS_UNMET");
    expect(json.details.bin).toBe("npm");
  });
});
