import { describe, expect, it } from "vitest";
import type { TemplateContext } from "../../src/prompts/template.js";
import { processBlocks, renderTemplate, validateTemplate } from "../../src/prompts/template.js";

// ---------------------------------------------------------------------------
// 1. Conditionals
// ---------------------------------------------------------------------------

describe("conditionals", () => {
  describe("truthy values", () => {
    it("renders if-block for a truthy string", () => {
      const tpl = "{% if name %}Hello {{ name }}{% endif %}";
      expect(renderTemplate(tpl, { name: "Alice" })).toBe("Hello Alice");
    });

    it("renders if-block for a non-zero number", () => {
      const tpl = "{% if count %}count={{ count }}{% endif %}";
      expect(renderTemplate(tpl, { count: 42 })).toBe("count=42");
    });

    it("renders if-block for a non-empty array", () => {
      const tpl = "{% if items %}has items{% endif %}";
      expect(renderTemplate(tpl, { items: [1, 2] })).toBe("has items");
    });

    it("renders if-block for boolean true", () => {
      const tpl = "{% if enabled %}on{% endif %}";
      expect(renderTemplate(tpl, { enabled: true })).toBe("on");
    });
  });

  describe("falsy values", () => {
    it("skips if-block for null", () => {
      const tpl = "{% if val %}yes{% endif %}";
      expect(renderTemplate(tpl, { val: null })).toBe("");
    });

    it("skips if-block for undefined (missing key)", () => {
      const tpl = "{% if val %}yes{% endif %}";
      expect(renderTemplate(tpl, {})).toBe("");
    });

    it("skips if-block for empty string", () => {
      const tpl = "{% if val %}yes{% endif %}";
      expect(renderTemplate(tpl, { val: "" })).toBe("");
    });

    it("skips if-block for empty array", () => {
      const tpl = "{% if items %}yes{% endif %}";
      expect(renderTemplate(tpl, { items: [] })).toBe("");
    });

    it("skips if-block for zero", () => {
      const tpl = "{% if count %}yes{% endif %}";
      expect(renderTemplate(tpl, { count: 0 })).toBe("");
    });

    it("skips if-block for boolean false", () => {
      const tpl = "{% if flag %}yes{% endif %}";
      expect(renderTemplate(tpl, { flag: false })).toBe("");
    });
  });

  describe("equality (==)", () => {
    it("matches when value equals quoted string", () => {
      const tpl = '{% if status == "active" %}active!{% endif %}';
      expect(renderTemplate(tpl, { status: "active" })).toBe("active!");
    });

    it("does not match when value differs", () => {
      const tpl = '{% if status == "active" %}active!{% endif %}';
      expect(renderTemplate(tpl, { status: "inactive" })).toBe("");
    });

    it("compares two variable paths", () => {
      const tpl = "{% if a == b %}same{% endif %}";
      expect(renderTemplate(tpl, { a: "x", b: "x" })).toBe("same");
      expect(renderTemplate(tpl, { a: "x", b: "y" })).toBe("");
    });
  });

  describe("inequality (!=)", () => {
    it("matches when value differs from quoted string", () => {
      const tpl = '{% if role != "admin" %}not admin{% endif %}';
      expect(renderTemplate(tpl, { role: "user" })).toBe("not admin");
    });

    it("does not match when value equals quoted string", () => {
      const tpl = '{% if role != "admin" %}not admin{% endif %}';
      expect(renderTemplate(tpl, { role: "admin" })).toBe("");
    });
  });

  describe("negation (not)", () => {
    it("renders when variable is falsy", () => {
      const tpl = "{% if not disabled %}enabled{% endif %}";
      expect(renderTemplate(tpl, { disabled: false })).toBe("enabled");
      expect(renderTemplate(tpl, {})).toBe("enabled");
    });

    it("skips when variable is truthy", () => {
      const tpl = "{% if not active %}inactive{% endif %}";
      expect(renderTemplate(tpl, { active: true })).toBe("");
    });
  });

  describe("elif / else chains", () => {
    it("renders elif branch when if is false and elif is true", () => {
      const tpl =
        '{% if level == "high" %}HIGH{% elif level == "medium" %}MED{% else %}LOW{% endif %}';
      expect(renderTemplate(tpl, { level: "medium" })).toBe("MED");
    });

    it("renders else branch when all conditions are false", () => {
      const tpl =
        '{% if level == "high" %}HIGH{% elif level == "medium" %}MED{% else %}LOW{% endif %}';
      expect(renderTemplate(tpl, { level: "low" })).toBe("LOW");
    });

    it("renders if branch when it is true (ignoring elif/else)", () => {
      const tpl =
        '{% if level == "high" %}HIGH{% elif level == "medium" %}MED{% else %}LOW{% endif %}';
      expect(renderTemplate(tpl, { level: "high" })).toBe("HIGH");
    });

    it("handles if/else without elif", () => {
      const tpl = "{% if flag %}yes{% else %}no{% endif %}";
      expect(renderTemplate(tpl, { flag: true })).toBe("yes");
      expect(renderTemplate(tpl, { flag: false })).toBe("no");
    });

    it("handles multiple elif branches", () => {
      const tpl = [
        '{% if x == "a" %}A',
        '{% elif x == "b" %}B',
        '{% elif x == "c" %}C',
        "{% else %}other",
        "{% endif %}",
      ].join("");
      expect(renderTemplate(tpl, { x: "c" })).toBe("C");
      expect(renderTemplate(tpl, { x: "z" })).toBe("other");
    });
  });
});

// ---------------------------------------------------------------------------
// 2. Loops
// ---------------------------------------------------------------------------

describe("loops", () => {
  it("iterates over array items", () => {
    const tpl = "{% for color in colors %}{{ color }} {% endfor %}";
    expect(renderTemplate(tpl, { colors: ["red", "green", "blue"] })).toBe("red green blue ");
  });

  it("renders nothing for an empty array", () => {
    const tpl = "{% for item in items %}{{ item }}{% endfor %}";
    expect(renderTemplate(tpl, { items: [] })).toBe("");
  });

  it("provides loop.index (1-based)", () => {
    const tpl = "{% for x in list %}{{ loop.index }}.{{ x }} {% endfor %}";
    expect(renderTemplate(tpl, { list: ["a", "b", "c"] })).toBe("1.a 2.b 3.c ");
  });

  it("accesses nested properties on loop items", () => {
    const tpl = "{% for user in users %}{{ user.name }} {% endfor %}";
    const ctx = { users: [{ name: "Alice" }, { name: "Bob" }] };
    expect(renderTemplate(tpl, ctx)).toBe("Alice Bob ");
  });

  it("renders nothing when loop variable is not an array", () => {
    const tpl = "{% for x in notArray %}{{ x }}{% endfor %}";
    expect(renderTemplate(tpl, { notArray: "hello" })).toBe("");
  });

  it("renders nothing when loop variable is undefined", () => {
    const tpl = "{% for x in missing %}{{ x }}{% endfor %}";
    expect(renderTemplate(tpl, {})).toBe("");
  });
});

// ---------------------------------------------------------------------------
// 3. Nesting
// ---------------------------------------------------------------------------

describe("nesting", () => {
  it("supports if inside for", () => {
    const tpl =
      "{% for item in items %}{% if item.active %}{{ item.name }} {% endif %}{% endfor %}";
    const ctx = {
      items: [
        { name: "A", active: true },
        { name: "B", active: false },
        { name: "C", active: true },
      ],
    };
    expect(renderTemplate(tpl, ctx)).toBe("A C ");
  });

  it("supports for inside if", () => {
    const tpl = "{% if showList %}{% for x in list %}{{ x }} {% endfor %}{% endif %}";
    expect(renderTemplate(tpl, { showList: true, list: [1, 2, 3] })).toBe("1 2 3 ");
    expect(renderTemplate(tpl, { showList: false, list: [1, 2, 3] })).toBe("");
  });

  it("supports nested ifs", () => {
    const tpl = "{% if a %}{% if b %}both{% else %}only a{% endif %}{% endif %}";
    expect(renderTemplate(tpl, { a: true, b: true })).toBe("both");
    expect(renderTemplate(tpl, { a: true, b: false })).toBe("only a");
    expect(renderTemplate(tpl, { a: false, b: true })).toBe("");
  });

  it("supports nested for loops", () => {
    const tpl =
      "{% for group in groups %}[{% for item in group.items %}{{ item }}{% endfor %}]{% endfor %}";
    const ctx = {
      groups: [{ items: ["a", "b"] }, { items: ["c"] }],
    };
    expect(renderTemplate(tpl, ctx)).toBe("[ab][c]");
  });
});

// ---------------------------------------------------------------------------
// 4. Edge cases
// ---------------------------------------------------------------------------

describe("edge cases", () => {
  it("throws when nesting depth exceeds maximum of 10", () => {
    // Build a template with 12 levels of nesting
    let tpl = "";
    for (let i = 0; i < 12; i++) {
      tpl += "{% if ok %}";
    }
    tpl += "deep";
    for (let i = 0; i < 12; i++) {
      tpl += "{% endif %}";
    }
    expect(() => processBlocks(tpl, { ok: true })).toThrow(/nesting depth exceeded/);
  });

  it("passes through unmatched if tag as-is", () => {
    const tpl = "{% if flag %}no endif here";
    const result = processBlocks(tpl, { flag: true });
    expect(result).toContain("{% if flag %}");
  });

  it("passes through unmatched for tag as-is", () => {
    const tpl = "{% for x in list %}no endfor";
    const result = processBlocks(tpl, { list: [1] });
    expect(result).toContain("{% for x in list %}");
  });

  it("preserves text around blocks", () => {
    const tpl = "before {% if show %}middle{% endif %} after";
    expect(renderTemplate(tpl, { show: true })).toBe("before middle after");
    expect(renderTemplate(tpl, { show: false })).toBe("before  after");
  });

  it("handles multiple sequential if blocks", () => {
    const tpl = "{% if a %}A{% endif %}{% if b %}B{% endif %}";
    expect(renderTemplate(tpl, { a: true, b: true })).toBe("AB");
    expect(renderTemplate(tpl, { a: true, b: false })).toBe("A");
    expect(renderTemplate(tpl, { a: false, b: true })).toBe("B");
  });

  it("handles multiple sequential for blocks", () => {
    const tpl = "{% for x in xs %}{{ x }}{% endfor %}-{% for y in ys %}{{ y }}{% endfor %}";
    expect(renderTemplate(tpl, { xs: [1, 2], ys: [3, 4] })).toBe("12-34");
  });

  it("dotted path conditions work", () => {
    const tpl = "{% if config.debug %}debug on{% endif %}";
    expect(renderTemplate(tpl, { config: { debug: true } })).toBe("debug on");
    expect(renderTemplate(tpl, { config: { debug: false } })).toBe("");
  });
});

// ---------------------------------------------------------------------------
// 5. Existing features still work (regression tests)
// ---------------------------------------------------------------------------

describe("existing features (regression)", () => {
  it("simple variable substitution", () => {
    expect(renderTemplate("Hello {{ name }}!", { name: "World" })).toBe("Hello World!");
  });

  it("dotted path access", () => {
    expect(renderTemplate("{{ a.b.c }}", { a: { b: { c: "deep" } } })).toBe("deep");
  });

  it("missing variable renders empty", () => {
    expect(renderTemplate("{{ missing }}", {})).toBe("");
  });

  it("join filter", () => {
    expect(renderTemplate('{{ items | join(", ") }}', { items: ["a", "b", "c"] })).toBe("a, b, c");
  });

  it("upper filter", () => {
    expect(renderTemplate("{{ name | upper }}", { name: "hello" })).toBe("HELLO");
  });

  it("lower filter", () => {
    expect(renderTemplate("{{ name | lower }}", { name: "HELLO" })).toBe("hello");
  });

  it("default filter", () => {
    expect(renderTemplate('{{ missing | default("fallback") }}', {})).toBe("fallback");
    expect(renderTemplate('{{ present | default("fallback") }}', { present: "value" })).toBe(
      "value",
    );
  });

  it("env variable access", () => {
    // process.env.PATH is always set
    const result = renderTemplate("{{ env.PATH }}", {});
    expect(result.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// 6. validateTemplate with block tags
// ---------------------------------------------------------------------------

describe("validateTemplate", () => {
  it("strips block tags before checking variables", () => {
    // Variables inside blocks should still be checked, but the block
    // tags themselves should not cause issues
    const tpl = "{% if show %}{{ name }}{% endif %}";
    const missing = validateTemplate(tpl, { show: true });
    // 'name' is still detected as missing even inside a block
    expect(missing).toContain("name");
  });

  it("reports no missing variables when all are present", () => {
    const tpl = "{% if show %}{{ name }}{% endif %}";
    const missing = validateTemplate(tpl, { show: true, name: "Alice" });
    expect(missing).toEqual([]);
  });

  it("works for templates without blocks", () => {
    const missing = validateTemplate("{{ a }} {{ b }}", { a: "1" });
    expect(missing).toEqual(["b"]);
  });
});

// ---------------------------------------------------------------------------
// 7. processBlocks (exported, used directly)
// ---------------------------------------------------------------------------

describe("processBlocks", () => {
  it("returns template unchanged when no blocks present", () => {
    const tpl = "Hello {{ name }}";
    expect(processBlocks(tpl, { name: "World" })).toBe("Hello {{ name }}");
  });

  it("processes blocks without expanding {{ }} placeholders", () => {
    const tpl = "{% if show %}{{ name }}{% endif %}";
    // processBlocks should keep {{ name }} as-is — substitution happens later
    expect(processBlocks(tpl, { show: true })).toBe("{{ name }}");
  });

  it("accepts depth parameter for testing", () => {
    const tpl = "{% if ok %}yes{% endif %}";
    expect(processBlocks(tpl, { ok: true }, 0)).toBe("yes");
    expect(processBlocks(tpl, { ok: true }, 9)).toBe("yes");
    expect(() => processBlocks(tpl, { ok: true }, 11)).toThrow(/nesting depth exceeded/);
  });
});
