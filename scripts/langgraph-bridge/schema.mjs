import { DynamicStructuredTool } from "@langchain/core/tools";

export const LANGGRAPH_BRIDGE_PROTOCOL_VERSION = 1;

export function validateBridgeRequest(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw new Error("LangGraph bridge request must be a JSON object");
  }
  const version = request.protocolVersion ?? request.protocol_version;
  if (version !== LANGGRAPH_BRIDGE_PROTOCOL_VERSION) {
    throw new Error(
      `Unsupported LangGraph bridge protocolVersion ${version ?? "<missing>"}; expected ${LANGGRAPH_BRIDGE_PROTOCOL_VERSION}`,
    );
  }
  return request;
}

export function bridgeToolsForNextStep(request) {
  return (request.tools ?? []).map(
    (tool) =>
      new DynamicStructuredTool({
        name: tool.name,
        description: tool.description ?? "",
        // These are declarations; Rust validates and executes next-step tools.
        // Keep the canonical schema intact instead of rebuilding a lossy subset.
        schema: tool.input_schema ?? tool.inputSchema ?? { type: "object", properties: {} },
        func: async () => "Kuzushi executes this tool outside the LangGraph bridge.",
      }),
  );
}
