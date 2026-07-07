#!/usr/bin/env node
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const [command, specifier, toolName] = process.argv.slice(2);
const OPTION_TYPES_BY_JSON_SCHEMA_TYPE = {
  string: "string",
  boolean: "bool",
  integer: "int",
  number: "float",
};

try {
  if (!command || !specifier) {
    throw new Error("usage: kuzushi-dynamic-module-host <describe|execute> <specifier> [tool]");
  }
  const mod = await loadModule(specifier);
  if (command === "describe") {
    process.stdout.write(JSON.stringify(describeModule(mod)));
  } else if (command === "execute") {
    if (!toolName) throw new Error("execute requires a tool name");
    const request = JSON.parse(await readStdin());
    process.stdout.write(JSON.stringify(await executeTool(mod, toolName, request)));
  } else if (command === "execute-runtime") {
    if (!toolName) throw new Error("execute-runtime requires a tool name");
    await executeToolWithRuntimeProtocol(mod, toolName);
  } else {
    throw new Error(`unknown command ${command}`);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

async function loadModule(specifier) {
  const importSpecifier = specifier.startsWith("file://")
    ? specifier
    : specifier.startsWith("/") || specifier.startsWith(".")
      ? pathToFileURL(specifier).href
      : specifier.startsWith("package:")
        ? specifier.slice("package:".length)
        : specifier;
  const imported = await import(importSpecifier);
  const module = imported.default ?? imported.module ?? imported;
  if (!module || typeof module !== "object") {
    throw new Error(`dynamic module ${specifier} did not export a module object`);
  }
  return module;
}

function describeModule(module) {
  const id = stringField(module.id, "module.id");
  const tools = arrayField(module.tools, "module.tools").map((tool) => describeTool(id, tool));
  return {
    module: {
      id,
      name: module.name ?? id,
      kind: normalizeKind(module.kind ?? "Internal"),
      description: module.description ?? `Dynamic module ${id}`,
    },
    tools,
  };
}

function describeTool(moduleId, tool) {
  const name = stringField(tool.name, "tool.name");
  if (!name.startsWith(`${moduleId}:`)) {
    throw new Error(`dynamic tool ${name} must start with module id ${moduleId}`);
  }
  const options = tool.options ?? optionsFromInputSchema(tool.inputSchema, name);
  return {
    name,
    description: tool.description ?? name,
    headless: tool.headless ?? true,
    hidden: tool.hidden ?? false,
    runtime_requirement: tool.requires?.runtime === true ? "always" : "never",
    options: normalizeOptions(options),
  };
}

function normalizeOptions(options) {
  return arrayField(options, "tool.options").map((option) => ({
    name: stringField(option.name, "option.name"),
    type: normalizeOptionType(option.type ?? option.optionType ?? "Json"),
    description: option.description ?? option.name,
    required: option.required ?? false,
    advanced: option.advanced ?? false,
    evasion: option.evasion ?? false,
    ...(option.default === undefined ? {} : { default: option.default }),
    choices: option.choices ?? [],
    aliases: option.aliases ?? [],
    deprecatedAliases: option.deprecatedAliases ?? option.deprecated_aliases ?? [],
  }));
}

function optionsFromInputSchema(schema, toolName) {
  if (schema === undefined) return [];
  assertObjectInputSchema(schema, toolName);
  const properties = schema.properties;
  if (properties === undefined) return [];
  assertSchemaProperties(properties, toolName);
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  return Object.entries(properties).map(([name, property]) =>
    optionFromSchemaProperty(name, property, required.has(name)),
  );
}

function assertObjectInputSchema(schema, toolName) {
  if (!isPlainObject(schema)) {
    throw new Error(`${toolName} inputSchema must be an object schema`);
  }
  if (schema.type !== undefined && schema.type !== "object") {
    throw new Error(`${toolName} inputSchema top-level type must be object`);
  }
}

function assertSchemaProperties(properties, toolName) {
  if (!isPlainObject(properties)) {
    throw new Error(`${toolName} inputSchema.properties must be an object`);
  }
}

function optionFromSchemaProperty(name, property, required) {
  const schema = isPlainObject(property) ? property : {};
  const choices = schemaEnumValues(schema.enum);
  const type = choices.length > 0 ? "enum" : optionTypeFromSchema(schema);
  return {
    name,
    type,
    description: typeof schema.description === "string" ? schema.description : name,
    required,
    advanced: false,
    evasion: false,
    ...(schema.default === undefined ? {} : { default: schema.default }),
    choices,
    aliases: [],
    deprecatedAliases: [],
  };
}

function optionTypeFromSchema(schema) {
  const type = nonNullSchemaType(schema.type);
  return OPTION_TYPES_BY_JSON_SCHEMA_TYPE[type] ?? arrayOptionType(schema, type) ?? "json";
}

function nonNullSchemaType(type) {
  return Array.isArray(type) ? type.find((value) => value !== "null") : type;
}

function arrayOptionType(schema, type) {
  return type === "array" && schema.items?.type === "string" ? "string-list" : null;
}

function schemaEnumValues(values) {
  return Array.isArray(values) ? values.filter((value) => typeof value === "string") : [];
}

async function executeTool(module, name, request) {
  const tool = arrayField(module.tools, "module.tools").find(
    (candidate) => candidate.name === name,
  );
  if (!tool) throw new Error(`dynamic module does not expose ${name}`);
  if (tool.requires?.runtime === true && !request.context?.runtime) {
    throw new Error(
      `${name} declares requires.runtime=true; Rust runtime callbacks are not available to dynamic modules yet`,
    );
  }
  return await toolExecutor(tool, name)(request.input, request.context);
}

function toolExecutor(tool, name) {
  if (typeof tool.run === "function") return tool.run.bind(tool);
  if (typeof tool.execute === "function") return tool.execute.bind(tool);
  throw new Error(`${name} does not export run(input, ctx) or execute(input, ctx)`);
}

async function executeToolWithRuntimeProtocol(module, name) {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const reader = lines[Symbol.asyncIterator]();
  const first = await reader.next();
  if (first.done) throw new Error("execute-runtime did not receive an initial request");
  const envelope = JSON.parse(first.value);
  if (envelope.type !== "request")
    throw new Error("execute-runtime expected an initial request envelope");
  const request = envelope.payload;
  const runtime = runtimeProxy(request.context, reader);
  const result = await executeTool(module, name, {
    ...request,
    context: {
      ...request.context,
      runtime,
    },
  });
  process.stdout.write(`${JSON.stringify({ type: "result", value: result })}\n`);
  lines.close();
}

function runtimeProxy(context, reader) {
  let nextId = 1;
  return {
    async query(request) {
      const id = nextId++;
      const normalized = normalizeRuntimeQueryRequest(request, context);
      process.stdout.write(
        `${JSON.stringify({ type: "runtime.query", id, request: normalized })}\n`,
      );
      const response = await readRuntimeCallbackResponse(reader, id);
      return response.response;
    },
  };
}

async function readRuntimeCallbackResponse(reader, id) {
  const line = await reader.next();
  if (line.done) throw new Error("runtime callback ended before a response");
  return parseRuntimeCallbackResponse(line.value, id);
}

function parseRuntimeCallbackResponse(line, id) {
  const response = JSON.parse(line);
  if (response.id !== id)
    throw new Error(`runtime callback id mismatch: expected ${id}, got ${response.id}`);
  if (response.type === "runtime.error")
    throw new Error(response.error ?? "runtime callback failed");
  if (response.type !== "runtime.response")
    throw new Error(`unexpected runtime callback response ${response.type}`);
  return response;
}

function normalizeRuntimeQueryRequest(request, context) {
  const configModel = context?.config?.model;
  const model = request.model ?? configModel;
  if (!model) throw new Error("ctx.runtime.query requires request.model or config.model");
  return {
    model,
    cwd: request.cwd ?? context?.cwd ?? ".",
    system_prompt: request.systemPrompt ?? request.system_prompt ?? "",
    prompt: stringField(request.prompt, "runtime query prompt"),
    ...(request.toolPolicy ? { tool_policy: request.toolPolicy } : {}),
    ...(request.tool_policy ? { tool_policy: request.tool_policy } : {}),
    ...(request.structuredOutput ? { structured_output: request.structuredOutput } : {}),
    ...(request.structured_output ? { structured_output: request.structured_output } : {}),
    ...(request.thinkingLevel ? { thinking_level: request.thinkingLevel } : {}),
    ...(request.thinking_level ? { thinking_level: request.thinking_level } : {}),
    ...(request.maxOutputTokens ? { max_output_tokens: request.maxOutputTokens } : {}),
    ...(request.max_output_tokens ? { max_output_tokens: request.max_output_tokens } : {}),
    ...(request.runtimeOptions ? { runtime_options: request.runtimeOptions } : {}),
    ...(request.runtime_options ? { runtime_options: request.runtime_options } : {}),
    ...(request.temperature === undefined ? {} : { temperature: request.temperature }),
  };
}

function normalizeKind(kind) {
  const value = String(kind).toLowerCase();
  const allowed = new Set([
    "offense",
    "intel",
    "governance",
    "defense",
    "internal",
    "catalog",
    "config",
    "context",
    "scan",
    "findings",
    "triage",
    "workspace",
  ]);
  if (!allowed.has(value)) return "internal";
  return value;
}

function normalizeOptionType(type) {
  const compact = String(type).replace(/[-_]/g, "").toLowerCase();
  const map = {
    string: "string",
    bool: "bool",
    boolean: "bool",
    int: "int",
    integer: "int",
    float: "float",
    number: "float",
    path: "path",
    enum: "enum",
    stringlist: "string-list",
    json: "json",
  };
  return map[compact] ?? "json";
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(value, label) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function arrayField(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}
