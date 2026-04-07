export interface DiscoveredModule {
  name: string;
  path: string;
  description: string;
  language: string;
  buildSystem?: string;
  isParent?: boolean;
  parentModule?: string;
}

export interface DiscoveryResult {
  modules: DiscoveredModule[];
  costUsd: number;
  reasoning: string;
}

export interface DiscoveryOptions {
  model?: string;
  maxModules?: number;
  maxDepth?: number;
  clusterThreshold?: number;
}
