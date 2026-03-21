export interface IndexedTextMatch {
  filePath: string;
  line: number;
  snippet: string;
}

export interface SymbolLookupQuery {
  symbol: string;
  receiverHint?: string | null;
  maxResults?: number;
}

export interface SymbolLookupMatch extends IndexedTextMatch {
  symbol: string;
  confidence: number;
  receiverMatched: boolean;
  arityHint?: number;
}

export interface IndexProvider {
  kind: string;
  searchText(query: string, options?: { maxResults?: number }): Promise<IndexedTextMatch[]>;
  getSnippet(filePath: string, line: number): Promise<string | undefined>;
}

export interface SymbolLookup {
  findSymbol(query: SymbolLookupQuery): Promise<SymbolLookupMatch[]>;
}

export interface DiffSlice {
  base: string;
  changedFiles: string[];
}

export interface DiffSlicer {
  getDiffSlice(base: string): Promise<DiffSlice>;
}

export interface CallGraphAssist {
  explainPath(args: {
    filePath: string;
    startLine: number;
    maxDepth?: number;
  }): Promise<{
    summary: string;
      callChain: Array<{ filePath: string; line: number; symbol: string }>;
  }>;
}

export interface DynamicVerifier {
  execute(args: {
    cwd: string;
    command: string[];
    timeoutMs?: number;
  }): Promise<{
    exitCode: number | null;
    stdout: string;
    stderr: string;
      timedOut: boolean;
  }>;
}

export interface SemanticPosition {
  filePath: string;
  line: number;
  column: number;
}

export interface SemanticLocation extends SemanticPosition {
  snippet?: string;
  symbol?: string;
  kind?: string;
  type?: string;
}

export interface ImportGraphEdge {
  fromFilePath: string;
  toPath: string;
}

export interface CodeIntelligenceProvider extends IndexProvider, SymbolLookup, DiffSlicer {
  scopeKey: string;
  getDefinitions(position: SemanticPosition): Promise<SemanticLocation[]>;
  getReferences(
    position: SemanticPosition,
    options?: { maxResults?: number },
  ): Promise<SemanticLocation[]>;
  getTypeAtPosition(position: SemanticPosition): Promise<SemanticLocation | undefined>;
  getImportGraph(): Promise<ImportGraphEdge[]>;
  getCallers(args: {
    functionName: string;
    searchPath?: string;
    maxResults?: number;
  }): Promise<string[]>;
  getCallees(args: {
    functionName: string;
    filePath: string;
  }): Promise<string[]>;
}
