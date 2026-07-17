export interface MatchingEdge {
  findingIndex: number;
  distance: number;
  identity: string;
}

interface FlowEdge {
  to: number;
  reverse: number;
  capacity: number;
  cost: number;
  findingIndex?: number;
}

interface FlowGraph {
  graph: FlowEdge[][];
  groundTruthNodes: Array<{ originalIndex: number; node: number }>;
  sink: number;
}

const MAX_RESIDUAL_EDGE_VISITS = 2_000_000;
const MAX_MATCH_AUGMENTATIONS = 20_000;

class ResidualWorkBudget {
  private edgeVisits = 0;
  private augmentations = 0;

  visitEdge(): void {
    this.edgeVisits += 1;
    if (this.edgeVisits > MAX_RESIDUAL_EDGE_VISITS) {
      throw new Error(
        `Benchmark matching exceeds ${MAX_RESIDUAL_EDGE_VISITS} residual edge visits`,
      );
    }
  }

  recordAugmentation(): void {
    this.augmentations += 1;
    if (this.augmentations > MAX_MATCH_AUGMENTATIONS) {
      throw new Error(`Benchmark matching exceeds ${MAX_MATCH_AUGMENTATIONS} augmentations`);
    }
  }
}

export function minimumCostMaximumMatching(
  groundTruthOrder: number[],
  findingCount: number,
  edges: MatchingEdge[][],
): Map<number, number> {
  const flow = buildFlowGraph(groundTruthOrder, findingCount, edges);
  const budget = new ResidualWorkBudget();
  while (augmentShortestPath(flow.graph, 0, flow.sink, budget)) {
    budget.recordAugmentation();
    // Residual negative edges let later augmentations improve total distance.
  }
  return matchedFindingIndexes(flow);
}

function buildFlowGraph(
  groundTruthOrder: number[],
  findingCount: number,
  edges: MatchingEdge[][],
): FlowGraph {
  const findingOffset = 1 + groundTruthOrder.length;
  const sink = findingOffset + findingCount;
  const graph = Array.from({ length: sink + 1 }, () => [] as FlowEdge[]);
  const groundTruthNodes = groundTruthOrder.map((originalIndex, rank) => ({
    originalIndex,
    node: 1 + rank,
  }));
  for (const entry of groundTruthNodes) addFlowEdge(graph, 0, entry.node, 0);
  for (const entry of groundTruthNodes) addGroundTruthEdges(graph, entry, findingOffset, edges);
  for (let index = 0; index < findingCount; index += 1) {
    addFlowEdge(graph, findingOffset + index, sink, 0);
  }
  return { graph, groundTruthNodes, sink };
}

function addGroundTruthEdges(
  graph: FlowEdge[][],
  entry: { originalIndex: number; node: number },
  findingOffset: number,
  edges: MatchingEdge[][],
): void {
  for (const edge of edges[entry.originalIndex]) {
    addFlowEdge(
      graph,
      entry.node,
      findingOffset + edge.findingIndex,
      edge.distance,
      edge.findingIndex,
    );
  }
}

function addFlowEdge(
  graph: FlowEdge[][],
  from: number,
  to: number,
  cost: number,
  findingIndex?: number,
): void {
  const forward = graph[from].length;
  const reverse = graph[to].length;
  graph[from].push({ to, reverse, capacity: 1, cost, findingIndex });
  graph[to].push({ to: from, reverse: forward, capacity: 0, cost: -cost });
}

function augmentShortestPath(
  graph: FlowEdge[][],
  source: number,
  sink: number,
  budget: ResidualWorkBudget,
): boolean {
  const path = shortestResidualPath(graph, source, budget);
  if (path.previousNode[sink] < 0) return false;
  applyAugmentingPath(graph, source, sink, path.previousNode, path.previousEdge);
  return true;
}

function shortestResidualPath(
  graph: FlowEdge[][],
  source: number,
  budget: ResidualWorkBudget,
): { previousNode: number[]; previousEdge: number[] } {
  const distance = Array<number>(graph.length).fill(Number.POSITIVE_INFINITY);
  const previousNode = Array<number>(graph.length).fill(-1);
  const previousEdge = Array<number>(graph.length).fill(-1);
  const queued = Array<boolean>(graph.length).fill(false);
  const queue = [source];
  distance[source] = 0;
  queued[source] = true;
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const from = queue[cursor];
    queued[from] = false;
    relaxResidualNode(graph, from, distance, previousNode, previousEdge, queue, queued, budget);
  }
  return { previousNode, previousEdge };
}

function relaxResidualNode(
  graph: FlowEdge[][],
  from: number,
  distance: number[],
  previousNode: number[],
  previousEdge: number[],
  queue: number[],
  queued: boolean[],
  budget: ResidualWorkBudget,
): void {
  for (let edgeIndex = 0; edgeIndex < graph[from].length; edgeIndex += 1) {
    budget.visitEdge();
    const updatedNode = relaxEdge(graph, from, edgeIndex, distance, previousNode, previousEdge);
    if (updatedNode >= 0 && !queued[updatedNode]) {
      queue.push(updatedNode);
      queued[updatedNode] = true;
    }
  }
}

function relaxEdge(
  graph: FlowEdge[][],
  from: number,
  edgeIndex: number,
  distance: number[],
  previousNode: number[],
  previousEdge: number[],
): number {
  const edge = graph[from][edgeIndex];
  const candidate = distance[from] + edge.cost;
  if (edge.capacity === 0 || candidate >= distance[edge.to]) return -1;
  distance[edge.to] = candidate;
  previousNode[edge.to] = from;
  previousEdge[edge.to] = edgeIndex;
  return edge.to;
}

function applyAugmentingPath(
  graph: FlowEdge[][],
  source: number,
  sink: number,
  previousNode: number[],
  previousEdge: number[],
): void {
  for (let node = sink; node !== source; node = previousNode[node]) {
    const edge = graph[previousNode[node]][previousEdge[node]];
    edge.capacity -= 1;
    graph[node][edge.reverse].capacity += 1;
  }
}

function matchedFindingIndexes(flow: FlowGraph): Map<number, number> {
  const matches = new Map<number, number>();
  for (const entry of flow.groundTruthNodes) {
    const matched = flow.graph[entry.node].find(
      (edge) => edge.findingIndex !== undefined && edge.capacity === 0,
    );
    if (matched?.findingIndex !== undefined) matches.set(entry.originalIndex, matched.findingIndex);
  }
  return matches;
}
