import { DynamicStructuredTool } from "@langchain/core/tools";
import * as z from "zod/v4";

const primitiveSchemas = {
  string: () => z.string(),
  integer: () => z.number().int(),
  number: () => z.number(),
  boolean: () => z.boolean(),
};
const typedSchemas = {
  ...primitiveSchemas,
  array: (schema) => z.array(zodValueForJsonSchema(schema.items)),
  object: (schema) => zodSchemaForJsonSchema(schema),
};

export function bridgeToolsForNextStep(request) {
  return (request.tools ?? []).map(
    (tool) =>
      new DynamicStructuredTool({
        name: tool.name,
        description: tool.description ?? "",
        schema: zodSchemaForJsonSchema(tool.input_schema ?? tool.inputSchema),
        func: async () => "Kuzushi executes this tool outside the LangGraph bridge.",
      }),
  );
}

function zodSchemaForJsonSchema(schema) {
  if (!schema || typeof schema !== "object") return z.object({}).passthrough();
  if (schema.type === "object" || schema.properties) return objectSchema(schema);
  return z.object({}).passthrough();
}

function objectSchema(schema) {
  const shape = {};
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  for (const [key, value] of Object.entries(schema.properties ?? {})) {
    const field = zodValueForJsonSchema(value);
    shape[key] = required.has(key) ? field : field.optional();
  }
  return z.object(shape).passthrough();
}

function zodValueForJsonSchema(schema) {
  if (!schema || typeof schema !== "object") return z.unknown();
  if (Array.isArray(schema.enum) && schema.enum.length > 0) return z.enum(schema.enum.map(String));
  const type = normalizedType(schema.type);
  return typedSchemas[type]?.(schema) ?? z.unknown();
}

function normalizedType(type) {
  if (!Array.isArray(type)) return type;
  return type.find((kind) => kind !== "null");
}
