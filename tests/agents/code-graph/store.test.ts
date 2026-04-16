import Database from "better-sqlite3";
import { beforeEach, describe, expect, it } from "vitest";
import {
  getEdgesFromNode,
  getEntryNodes,
  getGraphNodeByFileAndLine,
  getGraphNodesForRepo,
  getPathsToNode,
  invalidateStaleNodes,
  makeEdgeId,
  makeNodeId,
  makePathId,
  upsertGraphEdge,
  upsertGraphNode,
  upsertGraphPath,
} from "../../../src/agents/tasks/code-graph/store.js";
import type {
  CodeGraphEdge,
  CodeGraphNode,
  CodeGraphPath,
} from "../../../src/agents/tasks/code-graph/types.js";
import { migration100 } from "../../../src/migrations/100_schema_reset.js";

function createTestDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migration100.up(db);
  return db;
}

function makeNode(overrides: Partial<CodeGraphNode> = {}): CodeGraphNode {
  return {
    nodeId: makeNodeId("test-repo", "src/app.ts", 10, "handler"),
    filePath: "src/app.ts",
    startLine: 10,
    symbol: "handler",
    nodeKind: "controller",
    framework: "express",
    metadata: {},
    confidence: 1.0,
    source: "static",
    ...overrides,
  };
}

describe("Code Graph Store", () => {
  let db: Database.Database;

  beforeEach(() => {
    db = createTestDb();
  });

  describe("makeNodeId", () => {
    it("produces deterministic IDs", () => {
      const id1 = makeNodeId("repo", "file.ts", 10, "fn");
      const id2 = makeNodeId("repo", "file.ts", 10, "fn");
      expect(id1).toBe(id2);
    });

    it("produces different IDs for different inputs", () => {
      const id1 = makeNodeId("repo", "file.ts", 10, "fn");
      const id2 = makeNodeId("repo", "file.ts", 11, "fn");
      expect(id1).not.toBe(id2);
    });

    it("handles null symbol", () => {
      const id = makeNodeId("repo", "file.ts", 1, null);
      expect(id).toBeTruthy();
      expect(id.length).toBe(32);
    });
  });

  describe("upsertGraphNode", () => {
    it("inserts a new node", () => {
      const node = makeNode();
      upsertGraphNode(db, "test-repo", node);

      const nodes = getGraphNodesForRepo(db, "test-repo");
      expect(nodes).toHaveLength(1);
      expect(nodes[0]!.nodeId).toBe(node.nodeId);
      expect(nodes[0]!.symbol).toBe("handler");
      expect(nodes[0]!.nodeKind).toBe("controller");
    });

    it("upserts with higher confidence", () => {
      const node = makeNode({ confidence: 0.5 });
      upsertGraphNode(db, "test-repo", node);

      const updated = makeNode({ confidence: 0.9 });
      upsertGraphNode(db, "test-repo", updated);

      const nodes = getGraphNodesForRepo(db, "test-repo");
      expect(nodes).toHaveLength(1);
      expect(nodes[0]!.confidence).toBe(0.9);
    });

    it("marks hybrid source on conflict with different source", () => {
      const staticNode = makeNode({ source: "static" });
      upsertGraphNode(db, "test-repo", staticNode);

      const llmNode = makeNode({ source: "llm" });
      upsertGraphNode(db, "test-repo", llmNode);

      const nodes = getGraphNodesForRepo(db, "test-repo");
      expect(nodes[0]!.source).toBe("hybrid");
    });
  });

  describe("getEntryNodes", () => {
    it("returns only entry nodes", () => {
      upsertGraphNode(db, "test-repo", makeNode({ nodeKind: "entry-http" }));
      upsertGraphNode(
        db,
        "test-repo",
        makeNode({
          nodeId: makeNodeId("test-repo", "src/service.ts", 20, "doWork"),
          filePath: "src/service.ts",
          startLine: 20,
          symbol: "doWork",
          nodeKind: "service",
        }),
      );

      const entries = getEntryNodes(db, "test-repo");
      expect(entries).toHaveLength(1);
      expect(entries[0]!.nodeKind).toBe("entry-http");
    });
  });

  describe("getGraphNodeByFileAndLine", () => {
    it("finds node by exact file and line", () => {
      upsertGraphNode(db, "test-repo", makeNode());

      const found = getGraphNodeByFileAndLine(db, "test-repo", "src/app.ts", 10);
      expect(found).not.toBeNull();
      expect(found!.symbol).toBe("handler");
    });

    it("finds node within tolerance", () => {
      upsertGraphNode(db, "test-repo", makeNode({ startLine: 10 }));

      const found = getGraphNodeByFileAndLine(db, "test-repo", "src/app.ts", 12, 5);
      expect(found).not.toBeNull();
    });

    it("returns null when out of tolerance", () => {
      upsertGraphNode(db, "test-repo", makeNode({ startLine: 10 }));

      const found = getGraphNodeByFileAndLine(db, "test-repo", "src/app.ts", 25, 5);
      expect(found).toBeNull();
    });
  });

  describe("edges", () => {
    it("inserts and queries edges", () => {
      const n1 = makeNode({ nodeId: "node-1", filePath: "a.ts" });
      const n2 = makeNode({ nodeId: "node-2", filePath: "b.ts" });
      upsertGraphNode(db, "test-repo", n1);
      upsertGraphNode(db, "test-repo", n2);

      const edge: CodeGraphEdge = {
        edgeId: makeEdgeId("node-1", "node-2", "calls"),
        fromNodeId: "node-1",
        toNodeId: "node-2",
        edgeKind: "calls",
        dataLabel: "req.body",
        ordinal: 1,
        confidence: 0.9,
        source: "llm",
      };
      upsertGraphEdge(db, "test-repo", edge);

      const edges = getEdgesFromNode(db, "node-1");
      expect(edges).toHaveLength(1);
      expect(edges[0]!.edgeKind).toBe("calls");
      expect(edges[0]!.dataLabel).toBe("req.body");
    });
  });

  describe("paths", () => {
    it("inserts and queries paths", () => {
      const n1 = makeNode({ nodeId: "entry-1" });
      const n2 = makeNode({ nodeId: "target-1" });
      upsertGraphNode(db, "test-repo", n1);
      upsertGraphNode(db, "test-repo", n2);

      const path: CodeGraphPath = {
        pathId: makePathId("entry-1", "target-1", ["entry-1", "mid-1", "target-1"]),
        entryNodeId: "entry-1",
        targetNodeId: "target-1",
        hopCount: 2,
        nodeIds: ["entry-1", "mid-1", "target-1"],
        edgeIds: ["e1", "e2"],
        hasSanitizer: true,
        sanitizerNodeIds: ["mid-1"],
        confidence: 0.8,
      };
      upsertGraphPath(db, "test-repo", path);

      const paths = getPathsToNode(db, "test-repo", "target-1");
      expect(paths).toHaveLength(1);
      expect(paths[0]!.hopCount).toBe(2);
      expect(paths[0]!.hasSanitizer).toBe(true);
      expect(paths[0]!.sanitizerNodeIds).toEqual(["mid-1"]);
    });
  });

  describe("invalidateStaleNodes", () => {
    it("removes nodes and related edges/paths for stale files", () => {
      const n1 = makeNode({ nodeId: "n1", filePath: "src/old.ts" });
      const n2 = makeNode({ nodeId: "n2", filePath: "src/fresh.ts" });
      upsertGraphNode(db, "test-repo", n1);
      upsertGraphNode(db, "test-repo", n2);

      const edge: CodeGraphEdge = {
        edgeId: "e1",
        fromNodeId: "n1",
        toNodeId: "n2",
        edgeKind: "calls",
        dataLabel: null,
        ordinal: null,
        confidence: 1.0,
        source: "static",
      };
      upsertGraphEdge(db, "test-repo", edge);

      const removed = invalidateStaleNodes(db, "test-repo", ["src/old.ts"]);
      expect(removed).toBe(1);

      expect(getGraphNodesForRepo(db, "test-repo")).toHaveLength(1);
      expect(getEdgesFromNode(db, "n1")).toHaveLength(0);
    });

    it("returns 0 for empty stale list", () => {
      expect(invalidateStaleNodes(db, "test-repo", [])).toBe(0);
    });
  });
});
