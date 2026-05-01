import { describe, expect, it } from "vitest";
import { pickRecommendedFirst } from "../../src/ui/components/ModuleCatalog.js";
import type { ShellModuleCard } from "../../src/ui/state.js";

function card(
  id: string,
  category: ShellModuleCard["category"],
  description = "stub module",
): ShellModuleCard {
  return {
    id,
    displayName: id.toUpperCase(),
    category,
    description,
    toolCount: 1,
  };
}

describe("pickRecommendedFirst", () => {
  it("returns null on an empty catalog", () => {
    expect(pickRecommendedFirst([])).toBeNull();
  });

  it("prefers `sast` whenever it is loaded", () => {
    const cards = [
      card("randori", "intel"),
      card("shinsa", "governance"),
      card("sast", "offense"),
    ];
    expect(pickRecommendedFirst(cards)?.id).toBe("sast");
  });

  it("falls back to the first offense module when sast is not loaded", () => {
    const cards = [
      card("randori", "intel"),
      card("vuln-scout", "offense"),
      card("tob", "offense"),
    ];
    expect(pickRecommendedFirst(cards)?.id).toBe("vuln-scout");
  });

  it("falls back to the first card when no offense module is loaded", () => {
    const cards = [card("randori", "intel"), card("shinsa", "governance")];
    expect(pickRecommendedFirst(cards)?.id).toBe("randori");
  });

  it("does not mutate the input array", () => {
    const cards = [card("randori", "intel"), card("sast", "offense")];
    const before = cards.map((c) => c.id);
    pickRecommendedFirst(cards);
    expect(cards.map((c) => c.id)).toEqual(before);
  });
});
