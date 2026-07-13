#!/usr/bin/env node
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

const [command, specifier, toolName] = process.argv.slice(2);
const protocolWrite = process.stdout.write.bind(process.stdout);
const DYNAMIC_HOST_PROTOCOL_VERSION = 1;
// Baked at release time and checked by scripts/check-release-contract.mjs.
// Do not derive this from KUZUSHI_HOST_VERSION: that would let a stale host
// simply echo the native process's expectation and defeat the ABI handshake.
const HOST_PACKAGE_VERSION = "0.24.0-alpha.8";
const OPTION_TYPES_BY_JSON_SCHEMA_TYPE = {
  string: "string",
  boolean: "bool",
  integer: "int",
  number: "float",
};
const KWP_REQUEST_HANDLERS = new Map([
  ["initialize", (module, _host, params, state) => initializeKwpModule(module, params, state)],
  ["tools/call", dispatchKwpToolCall],
  ["kuzushi/module/run", dispatchLegacyKwpModuleRun],
  ["shutdown", () => ({})],
]);

try {
  if (!command || !specifier) {
    throw new Error(
      "usage: kuzushi-dynamic-module-host <describe|execute|execute-runtime|serve> <specifier> [tool]",
    );
  }
  validateHostContractEnvironment();
  redirectWorkerStdoutToStderr();
  const mod = await loadModule(specifier);
  if (command === "describe") {
    protocolWrite(JSON.stringify(protocolEnvelope(describeModule(mod))));
  } else if (command === "execute") {
    if (!toolName) throw new Error("execute requires a tool name");
    const request = JSON.parse(await readStdin());
    protocolWrite(JSON.stringify(protocolEnvelope(await executeTool(mod, toolName, request))));
  } else if (command === "execute-runtime") {
    if (!toolName) throw new Error("execute-runtime requires a tool name");
    await executeToolWithRuntimeProtocol(mod, toolName);
  } else if (command === "serve") {
    await serveKwp(mod, protocolWrite);
  } else {
    throw new Error(`unknown command ${command}`);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}

function validateHostContractEnvironment() {
  const expectedProtocol = Number(process.env.KUZUSHI_DYNAMIC_HOST_PROTOCOL_VERSION);
  if (expectedProtocol !== DYNAMIC_HOST_PROTOCOL_VERSION) {
    throw new Error(
      `dynamic host protocol mismatch: host=${DYNAMIC_HOST_PROTOCOL_VERSION} native=${expectedProtocol}`,
    );
  }
  const expectedVersion = process.env.KUZUSHI_HOST_VERSION;
  if (expectedVersion !== HOST_PACKAGE_VERSION) {
    throw new Error(
      `dynamic host version mismatch: host=${HOST_PACKAGE_VERSION} native=${expectedVersion ?? "<missing>"}`,
    );
  }
}

function protocolEnvelope(payload) {
  return {
    protocolVersion: DYNAMIC_HOST_PROTOCOL_VERSION,
    hostVersion: HOST_PACKAGE_VERSION,
    payload,
  };
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
  rejectUnsupportedModuleSemantics(module);
  const id = stringField(module.id, "module.id");
  const tools = arrayField(module.tools, "module.tools").map((tool) => describeTool(id, tool));
  return {
    module: {
      id,
      name: stringField(module.displayName ?? module.name ?? id, "module.displayName"),
      kind: normalizeKind(module.category ?? module.kind ?? "internal"),
      description: stringField(module.description ?? `Dynamic module ${id}`, "module.description"),
    },
    hidden: optionalBooleanField(module.hidden, false, "module.hidden"),
    tools,
  };
}

function describeTool(moduleId, tool) {
  rejectUnsupportedToolSemantics(tool);
  const name = stringField(tool.name, "tool.name");
  if (!name.startsWith(`${moduleId}:`)) {
    throw new Error(`dynamic tool ${name} must start with module id ${moduleId}`);
  }
  toolExecutor(tool, name);
  const options = tool.options ?? optionsFromInputSchema(tool.inputSchema, name);
  const normalizedOptions = normalizeOptions(options);
  const effect = normalizeEffect(tool.effect, name);
  const approval = normalizeApproval(tool.approval, effect, name);
  const prompts = normalizePrompts(tool.prompts ?? [], moduleId, name, normalizedOptions);
  return {
    name,
    description: stringField(tool.description ?? name, `${name}.description`),
    headless: booleanField(tool.headless, `${name}.headless`),
    hidden: optionalBooleanField(tool.hidden, false, `${name}.hidden`),
    runtime_requirement: normalizeRuntimeRequirement(tool, name),
    phase: normalizePhase(tool.phase, effect, name),
    effect,
    approval,
    workspace_requirement: normalizeWorkspaceRequirement(tool.workspaceRequirement, name),
    finding_store_requirement: "optional",
    options: normalizedOptions,
    ...(prompts.length > 0 ? { prompts } : {}),
  };
}

function normalizePrompts(prompts, moduleId, toolName, options) {
  const optionNames = new Set(options.map((option) => option.name));
  return arrayField(prompts, `${toolName}.prompts`).map((prompt) => {
    const promptModule = stringField(
      prompt.moduleId ?? prompt.module_id ?? moduleId,
      `${toolName}.prompt.moduleId`,
    );
    if (promptModule !== moduleId) {
      throw new Error(`${toolName} prompt moduleId must match ${moduleId}`);
    }
    const optionKey = stringField(
      prompt.optionKey ?? prompt.option_key,
      `${toolName}.prompt.optionKey`,
    );
    if (!optionNames.has(optionKey)) {
      throw new Error(`${toolName} prompt optionKey ${optionKey} is not declared in options`);
    }
    return {
      role: stringField(prompt.role, `${toolName}.prompt.role`),
      moduleId: promptModule,
      verb: stringField(prompt.verb, `${toolName}.prompt.verb`),
      optionKey,
      defaultContent: stringField(
        prompt.defaultContent ?? prompt.default_content,
        `${toolName}.prompt.defaultContent`,
      ),
      contextNote:
        prompt.contextNote ??
        prompt.context_note ??
        "Repository context is generated at runtime and is not part of this editable instruction template.",
    };
  });
}

function normalizeOptions(options) {
  return arrayField(options, "tool.options").map((option) => {
    const type = normalizeOptionType(option.type ?? option.optionType ?? "Json");
    return {
      name: stringField(option.name, "option.name"),
      type,
      description: stringField(option.description ?? option.name, `${option.name}.description`),
      required: optionalBooleanField(option.required, false, `${option.name}.required`),
      advanced: optionalBooleanField(option.advanced, false, `${option.name}.advanced`),
      evasion: optionalBooleanField(option.evasion, false, `${option.name}.evasion`),
      ...(type === "path"
        ? { pathSemantics: normalizePathSemantics(option.pathSemantics, option.name) }
        : {}),
      ...(option.default === undefined ? {} : { default: option.default }),
      choices: stringArrayField(option.choices ?? [], `${option.name}.choices`),
      aliases: stringArrayField(option.aliases ?? [], `${option.name}.aliases`),
      deprecatedAliases: stringArrayField(
        option.deprecatedAliases ?? option.deprecated_aliases ?? [],
        `${option.name}.deprecatedAliases`,
      ),
    };
  });
}

function normalizePathSemantics(value, optionName) {
  const allowed = new Set([
    "workspace-read",
    "state-write",
    "target-write",
    "external-read",
    "external-write",
    "executable",
  ]);
  if (!allowed.has(value)) {
    throw new Error(`${optionName}.pathSemantics must declare ${[...allowed].join("|")}`);
  }
  return value;
}

function optionsFromInputSchema(schema, toolName) {
  if (schema === undefined) return [];
  assertObjectInputSchema(schema, toolName);
  const required = schemaRequiredNames(schema.required, toolName);
  const properties = schemaProperties(schema.properties, required, toolName);
  ensureRequiredPropertiesExist(properties, required, toolName);
  return Object.entries(properties).map(([name, property]) =>
    optionFromSchemaProperty(name, property, required.has(name)),
  );
}

function schemaProperties(properties, required, toolName) {
  if (properties === undefined && required.size > 0) {
    throw new Error(`${toolName} inputSchema.required names properties that are not declared`);
  }
  if (properties === undefined) return {};
  assertSchemaProperties(properties, toolName);
  return properties;
}

function ensureRequiredPropertiesExist(properties, required, toolName) {
  for (const name of required) {
    if (!(name in properties)) {
      throw new Error(`${toolName} inputSchema.required names missing property ${name}`);
    }
  }
}

function schemaRequiredNames(required, toolName) {
  if (required === undefined) return new Set();
  return new Set(stringArrayField(required, `${toolName} inputSchema.required`));
}

function assertObjectInputSchema(schema, toolName) {
  if (!isPlainObject(schema)) {
    throw new Error(`${toolName} inputSchema must be an object schema`);
  }
  if (schema.type !== undefined && schema.type !== "object") {
    throw new Error(`${toolName} inputSchema top-level type must be object`);
  }
  rejectUnsupportedSchemaKeys(
    schema,
    new Set([
      "type",
      "properties",
      "required",
      "additionalProperties",
      "description",
      "title",
      "$schema",
    ]),
    `${toolName} inputSchema`,
  );
  if (schema.additionalProperties !== false) {
    throw new Error(
      `${toolName} inputSchema must declare additionalProperties: false because native option validation rejects unknown keys`,
    );
  }
}

function assertSchemaProperties(properties, toolName) {
  if (!isPlainObject(properties)) {
    throw new Error(`${toolName} inputSchema.properties must be an object`);
  }
}

function optionFromSchemaProperty(name, property, required) {
  if (!isPlainObject(property)) {
    throw new Error(`inputSchema.properties.${name} must be an object schema`);
  }
  const schema = property;
  rejectUnsupportedSchemaKeys(
    schema,
    new Set(["type", "description", "default", "enum", "items"]),
    `inputSchema.properties.${name}`,
  );
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
  if (type === undefined || type === "object") return "json";
  const normalized = OPTION_TYPES_BY_JSON_SCHEMA_TYPE[type] ?? arrayOptionType(schema, type);
  if (!normalized) throw new Error(`unsupported inputSchema property type ${type}`);
  return normalized;
}

function nonNullSchemaType(type) {
  if (!Array.isArray(type)) return type;
  const nonNull = type.filter((value) => value !== "null");
  if (nonNull.length !== 1 || type.length !== 2) {
    throw new Error("native dynamic host supports only one property type plus optional null");
  }
  return nonNull[0];
}

function arrayOptionType(schema, type) {
  if (type !== "array") return null;
  if (!isPlainObject(schema.items)) {
    throw new Error("array inputSchema properties must declare string items");
  }
  rejectUnsupportedSchemaKeys(schema.items, new Set(["type"]), "array items schema");
  if (schema.items.type !== "string") {
    throw new Error("native dynamic host supports only arrays of strings");
  }
  return "string-list";
}

function schemaEnumValues(values) {
  if (values === undefined) return [];
  const choices = stringArrayField(values, "schema enum");
  if (choices.length === 0) throw new Error("schema enum must not be empty");
  return choices;
}

async function executeTool(module, name, request) {
  const tool = arrayField(module.tools, "module.tools").find(
    (candidate) => candidate.name === name,
  );
  if (!tool) throw new Error(`dynamic module does not expose ${name}`);
  if (toolRequiresRuntime(tool) && !request.context?.runtime) {
    throw new Error(
      `${name} declares runtimeRequirement=always but no native runtime callback is available`,
    );
  }
  const context = nativeExecutionContext(module, tool, request.context ?? {});
  return await toolExecutor(tool, name)(request.input, context);
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
  protocolWrite(
    `${JSON.stringify({
      type: "handshake",
      protocolVersion: DYNAMIC_HOST_PROTOCOL_VERSION,
      hostVersion: HOST_PACKAGE_VERSION,
    })}\n`,
  );
  const runtime = runtimeProxy(request.context, reader);
  const result = await executeTool(module, name, {
    ...request,
    context: {
      ...request.context,
      runtime,
    },
  });
  protocolWrite(`${JSON.stringify({ type: "result", value: result })}\n`);
  lines.close();
}

function serveKwp(module, writeProtocol) {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let nextId = 1;
  const pending = new Map();
  const state = { live: new Map(), mcpAliases: new Set() };
  const host = {
    call(method, params) {
      const id = nextId++;
      writeProtocol(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      return new Promise((resolve, reject) => {
        pending.set(id, {
          resolve,
          reject,
          invocationId: invocationIdFromParams(params),
        });
      });
    },
  };

  lines.on("line", (line) => {
    void handleKwpLine(module, host, pending, writeProtocol, line, state);
  });
  return new Promise((resolve) => {
    lines.on("close", resolve);
  });
}

function redirectWorkerStdoutToStderr() {
  process.stdout.write = (chunk, encoding, callback) => {
    if (typeof encoding === "function") {
      callback = encoding;
      encoding = undefined;
    }
    const value = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    process.stderr.write(`[stdout] ${value}`, encoding);
    callback?.();
    return true;
  };
  for (const method of ["log", "info", "warn", "error", "debug"]) {
    console[method] = (...args) => {
      process.stderr.write(`[console.${method}] ${args.map(String).join(" ")}\n`);
    };
  }
}

async function handleKwpLine(module, host, pending, writeProtocol, line, state) {
  let message;
  try {
    message = JSON.parse(line);
  } catch (error) {
    writeKwpError(writeProtocol, 0, -32700, error instanceof Error ? error.message : String(error));
    return;
  }
  if (message.jsonrpc !== "2.0") {
    writeKwpError(writeProtocol, message.id ?? 0, -32600, "jsonrpc version must be 2.0");
    return;
  }
  if (message.method) {
    if (message.id === undefined) {
      handleKwpNotification(message, state, pending);
      return;
    }
    await handleKwpRequest(module, host, writeProtocol, message, state);
    return;
  }
  settlePendingHostCall(pending, message);
}

async function handleKwpRequest(module, host, writeProtocol, message, state) {
  try {
    const result = await dispatchKwpRequest(
      module,
      host,
      message.method,
      message.params ?? {},
      state,
    );
    writeProtocol(`${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\n`);
  } catch (error) {
    writeKwpError(
      writeProtocol,
      message.id,
      error?.code ?? -32603,
      error instanceof Error ? error.message : String(error),
    );
  }
}

function writeKwpError(writeProtocol, id, code, message) {
  writeProtocol(`${JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } })}\n`);
}

function settlePendingHostCall(pending, message) {
  const pendingCall = pending.get(message.id);
  if (!pendingCall) return;
  pending.delete(message.id);
  if (message.error) {
    const error = new Error(message.error.message ?? "KWP host call failed");
    error.code = message.error.code;
    pendingCall.reject(error);
    return;
  }
  pendingCall.resolve(message.result);
}

function handleKwpNotification(message, state, pending) {
  if (message.method === "notifications/cancelled") {
    cancelKwpInvocation(message.params, state, pending);
  }
}

function cancelKwpInvocation(params, state, pending) {
  const live = cancellableKwpInvocation(params, state);
  if (!live) return;
  live.settled = true;
  live.abort.abort(typeof params?.reason === "string" ? params.reason : "cancelled");
  rejectPendingInvocationCalls(pending, live.invocationId);
}

function cancellableKwpInvocation(params, state) {
  const invocationId = cancelledInvocationId(params);
  return invocationId ? state.live.get(invocationId) : undefined;
}

function cancelledInvocationId(params) {
  const invocationId = invocationIdFromParams(params) ?? params?.requestId;
  return typeof invocationId === "string" && invocationId.length > 0 ? invocationId : undefined;
}

function rejectPendingInvocationCalls(pending, invocationId) {
  for (const [id, call] of pending.entries()) {
    if (call.invocationId !== invocationId) continue;
    pending.delete(id);
    const error = new Error("invocation cancelled");
    error.code = -32030;
    call.reject(error);
  }
}

async function dispatchKwpRequest(module, host, method, params, state) {
  return await requiredKwpRequestHandler(method)(module, host, params, state);
}

function requiredKwpRequestHandler(method) {
  const handler = KWP_REQUEST_HANDLERS.get(method);
  if (handler) return handler;
  const error = new Error(`unknown KWP request ${method}`);
  error.code = -32601;
  throw error;
}

function initializeKwpModule(module, params, state) {
  const description = describeModule(module);
  state.mcpAliases = mcpAliasesFromInitialize(params);
  return {
    protocolVersion: "0.1.0",
    module: description.module,
    hidden: description.hidden,
    tools: description.tools,
    concurrency: 1,
  };
}

function mcpAliasesFromInitialize(params) {
  const metadata = isPlainObject(params?._kuzushi) ? params._kuzushi : params;
  const grant = isPlainObject(metadata?.grant) ? metadata.grant : {};
  const entries = Array.isArray(grant.mcp) ? grant.mcp : [];
  return new Set(
    entries
      .map((entry) => (isPlainObject(entry) ? entry.alias : undefined))
      .filter((alias) => typeof alias === "string" && alias.trim() !== ""),
  );
}

async function dispatchKwpToolCall(module, host, params, state) {
  const name = stringField(params.name, "params.name");
  const input = params.arguments ?? {};
  const baseContext = kwpContextFromToolCall(params);
  return await runKwpInvocation(module, host, name, input, baseContext, state);
}

async function dispatchLegacyKwpModuleRun(module, host, params, state) {
  const name = stringField(params.toolName, "params.toolName");
  return await runKwpInvocation(
    module,
    host,
    name,
    params.input ?? {},
    params.context ?? {},
    state,
  );
}

async function runKwpInvocation(module, host, name, input, baseContext, state) {
  const live = liveInvocationFromContext(baseContext);
  state.live.set(live.invocationId, live);
  try {
    const context = kwpToolContext(baseContext, host, live, state);
    return sanitizeToolResult(await executeKwpTool(module, name, input, context));
  } finally {
    live.settled = true;
    state.live.delete(live.invocationId);
  }
}

function kwpContextFromToolCall(params) {
  const base = isPlainObject(params.context) ? params.context : {};
  const metadata = isPlainObject(params._kuzushi) ? params._kuzushi : {};
  return {
    ...base,
    kwp: {
      ...(isPlainObject(base.kwp) ? base.kwp : {}),
      version: base.kwp?.version ?? "0.1.0",
      invocationId: metadata.invocationId ?? base.kwp?.invocationId,
      runId: metadata.runId ?? base.kwp?.runId,
      epoch: metadata.epoch ?? base.kwp?.epoch,
    },
  };
}

function liveInvocationFromContext(context) {
  const epoch = Number(context?.kwp?.epoch ?? 0);
  if (!Number.isSafeInteger(epoch) || epoch < 0) {
    throw new Error("context.kwp.epoch must be a non-negative integer");
  }
  return {
    invocationId: stringField(context?.kwp?.invocationId, "context.kwp.invocationId"),
    runId: stringField(context?.kwp?.runId, "context.kwp.runId"),
    epoch,
    abort: new AbortController(),
    settled: false,
  };
}

function invocationIdFromParams(params) {
  return typeof params?.invocationId === "string"
    ? params.invocationId
    : typeof params?.invocation_id === "string"
      ? params.invocation_id
      : undefined;
}

function sanitizeToolResult(result) {
  if (!isPlainObject(result)) return result;
  const copy = { ...result };
  delete copy.costUsd;
  return copy;
}

async function executeKwpTool(module, name, input, context) {
  const tool = arrayField(module.tools, "module.tools").find(
    (candidate) => candidate.name === name,
  );
  if (!tool) throw new Error(`dynamic module does not expose ${name}`);
  return await toolExecutor(tool, name)(input, context);
}

function kwpToolContext(context, host, live, state) {
  return {
    ...context,
    invocationId: live.invocationId,
    runId: live.runId,
    signal: live.abort.signal,
    fs: kwpFsProxy(host, live),
    runtime: kwpRuntimeProxy(host, live, context),
    artifacts: {
      record(artifacts) {
        return brokerCall(host, live, "kuzushi/artifacts/record", { artifacts });
      },
    },
    findings: {
      create(findings) {
        return brokerCall(host, live, "kuzushi/findings/create", { findings });
      },
    },
    mcp: kwpMcpProxy(host, live, state.mcpAliases),
    fuzz: {
      run(request) {
        return brokerCall(host, live, "kuzushi/fuzz/run", request);
      },
    },
    net: kwpNetProxy(host, live),
    bus: {
      async publish(topic, payload) {
        await brokerCall(host, live, "kuzushi/bus/publish", { topic, payload });
      },
    },
  };
}

function kwpMcpProxy(host, live, aliases) {
  return {
    has(alias) {
      return aliases.has(alias);
    },
    grantedAliases() {
      return [...aliases];
    },
    call(alias, tool, args = {}, options = {}) {
      if (!aliases.has(alias)) {
        const error = new Error(`MCP alias ${alias} is not granted for this invocation`);
        error.code = -32031;
        throw error;
      }
      return brokerCall(host, live, "kuzushi/mcp/call", {
        alias,
        tool,
        arguments: args,
        limits: mcpCallLimits(options),
      });
    },
  };
}

function mcpCallLimits(options) {
  if (!isPlainObject(options)) return {};
  return isPlainObject(options.limits) ? options.limits : options;
}

function kwpNetProxy(host, live) {
  return {
    async fetch(requestOrUrl, init = {}) {
      const request = normalizeKwpNetRequest(requestOrUrl, init);
      const result = await brokerCall(host, live, "kuzushi/net/fetch", request);
      return {
        status: result.status,
        headers: result.headers ?? {},
        body: async () => Buffer.from(result.bodyBase64 ?? "", "base64"),
        artifact: result.artifact,
      };
    },
  };
}

function normalizeKwpNetRequest(requestOrUrl, init) {
  const request = typeof requestOrUrl === "string" ? { ...init, url: requestOrUrl } : requestOrUrl;
  if (!isPlainObject(request)) throw new Error("ctx.net.fetch request must be an object");
  const { body, ...fields } = request;
  return {
    ...fields,
    method: fields.method ?? "GET",
    url: stringField(fields.url, "ctx.net.fetch request.url"),
    ...(body === undefined ? {} : { bodyBase64: encodeWorkerBody(body) }),
  };
}

function encodeWorkerBody(body) {
  if (typeof body === "string" || body instanceof Uint8Array) {
    return Buffer.from(body).toString("base64");
  }
  throw new Error("ctx.net.fetch request.body must be a string or Uint8Array");
}

function brokerCall(host, live, method, params = {}) {
  if (live.settled || live.abort.signal.aborted) {
    const error = new Error("invocation already settled");
    error.code = -32030;
    throw error;
  }
  return host.call(method, {
    ...params,
    invocationId: live.invocationId,
    epoch: live.epoch,
  });
}

function kwpFsProxy(host, live) {
  return {
    read: (scope, path, options = {}) => readKwpFile(host, live, scope, path, options),
    readText: (scope, path, options = {}) => readKwpText(host, live, scope, path, options),
    write: (scope, path, data, options = {}) =>
      writeKwpFile(host, live, scope, path, data, options),
    writeText: (scope, path, text, options = {}) =>
      writeKwpFile(host, live, scope, path, text, options),
    list: (scope, path) => listKwpFiles(host, live, scope, path),
    stat: (scope, path) => brokerCall(host, live, "kuzushi/fs/stat", { scope, path }),
    remove: (scope, path) => removeKwpFile(host, live, scope, path),
  };
}

async function readKwpText(host, live, scope, path, options) {
  const contents = await readKwpFile(host, live, scope, path, options);
  return contents.toString(options.encoding ?? "utf8");
}

async function readKwpFile(host, live, scope, path, options) {
  const result = await brokerCall(host, live, "kuzushi/fs/read", {
    scope,
    path,
    offset: options.offset,
    length: options.length,
  });
  return Buffer.from(result.dataBase64 ?? "", "base64");
}

async function writeKwpFile(host, live, scope, path, data, options) {
  const buffer = Buffer.isBuffer(data)
    ? data
    : Buffer.from(String(data), options.encoding ?? "utf8");
  const result = await brokerCall(host, live, "kuzushi/fs/write", {
    scope,
    path,
    dataBase64: buffer.toString("base64"),
    append: options.append ?? false,
  });
  return result.bytesWritten;
}

async function listKwpFiles(host, live, scope, path) {
  const result = await brokerCall(host, live, "kuzushi/fs/list", { scope, path });
  return result.entries ?? [];
}

async function removeKwpFile(host, live, scope, path) {
  await brokerCall(host, live, "kuzushi/fs/remove", { scope, path });
}

function kwpRuntimeProxy(host, live, context) {
  return {
    query(request) {
      const normalized = normalizeKwpRuntimeQueryRequest(request, context);
      const response = brokerCall(host, live, "kuzushi/runtime/query", { request: normalized });
      return runtimeQueryHandle(response);
    },
  };
}

function runtimeProxy(context, reader) {
  let nextId = 1;
  return {
    id: "kuzushi-native-dynamic",
    query(request) {
      const id = nextId++;
      const response = queryNativeRuntime(id, request, context, reader);
      return runtimeQueryHandle(response);
    },
  };
}

async function queryNativeRuntime(id, request, context, reader) {
  const normalized = normalizeLegacyRuntimeQueryRequest(request, context);
  protocolWrite(`${JSON.stringify({ type: "runtime.query", id, request: normalized })}\n`);
  const response = await readRuntimeCallbackResponse(reader, id);
  return response.response;
}

function runtimeQueryHandle(response) {
  return {
    // biome-ignore lint/suspicious/noThenProperty: bridge must support legacy await and SDK streaming
    then: response.then.bind(response),
    catch: response.catch.bind(response),
    finally: response.finally.bind(response),
    async *[Symbol.asyncIterator]() {
      try {
        const value = await response;
        yield {
          type: "result",
          subtype: "success",
          result: value.text ?? "",
          ...(value.structured === undefined ? {} : { structuredOutput: value.structured }),
          totalCostUsd: value.cost_usd ?? 0,
        };
      } catch (error) {
        yield {
          type: "result",
          subtype: "error",
          errors: [error instanceof Error ? error.message : String(error)],
        };
      }
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

function normalizeKwpRuntimeQueryRequest(request, context) {
  if (!isPlainObject(request)) throw new Error("ctx.runtime.query request must be an object");
  if (request.options !== undefined) return normalizeKwpSdkRuntimeQueryRequest(request, context);
  validateHostOwnedRuntimeFields(request, context);
  rejectWorkerRuntimeAuthority(request);
  rejectUnsupportedKwpRuntimeFields(request);
  const systemPrompt = request.systemPrompt ?? request.system_prompt;
  return {
    prompt: stringField(request.prompt, "runtime query prompt"),
    ...(systemPrompt === undefined ? {} : { system_prompt: systemPrompt }),
    ...(request.structuredOutput ? { structured_output: request.structuredOutput } : {}),
    ...(request.structured_output ? { structured_output: request.structured_output } : {}),
    ...(request.thinkingLevel ? { thinking_level: request.thinkingLevel } : {}),
    ...(request.thinking_level ? { thinking_level: request.thinking_level } : {}),
    ...(request.maxOutputTokens ? { max_output_tokens: request.maxOutputTokens } : {}),
    ...(request.max_output_tokens ? { max_output_tokens: request.max_output_tokens } : {}),
    ...(request.temperature === undefined ? {} : { temperature: request.temperature }),
  };
}

function rejectUnsupportedKwpRuntimeFields(request) {
  const supported = new Set([
    "prompt",
    "systemPrompt",
    "system_prompt",
    "structuredOutput",
    "structured_output",
    "thinkingLevel",
    "thinking_level",
    "maxOutputTokens",
    "max_output_tokens",
    "temperature",
    "model",
    "cwd",
  ]);
  const unsupported = Object.keys(request).find((name) => !supported.has(name));
  if (unsupported) throw new Error(`KWP runtime query does not support field ${unsupported}`);
}

function normalizeKwpSdkRuntimeQueryRequest(request, context) {
  const options = request.options;
  if (!isPlainObject(options)) {
    throw new Error("ctx.runtime.query request.options must be an object");
  }
  validateHostOwnedRuntimeFields(options, context);
  rejectUnsupportedRuntimeOptions(options);
  if (
    options.allowedTools !== undefined &&
    stringArrayField(options.allowedTools, "allowedTools").length > 0
  ) {
    throw new Error("KWP runtime queries cannot select agent tools");
  }
  return {
    system_prompt: options.systemPromptPrefix ?? "",
    prompt: stringField(request.prompt, "runtime query prompt"),
    ...(options.outputFormat === undefined
      ? {}
      : { structured_output: normalizeSdkOutputFormat(options.outputFormat) }),
    ...(options.effort === undefined ? {} : { thinking_level: options.effort }),
    ...(options.maxOutputTokens === undefined
      ? {}
      : { max_output_tokens: options.maxOutputTokens }),
    ...(options.temperature === undefined ? {} : { temperature: options.temperature }),
  };
}

function validateHostOwnedRuntimeFields(request, context) {
  const configuredModel = context?.config?.model;
  if (request.model !== undefined && request.model !== configuredModel) {
    throw new Error("KWP runtime model is selected by the host");
  }
  if (request.cwd !== undefined && request.cwd !== context?.cwd) {
    throw new Error("KWP runtime cwd is selected by the host");
  }
}

function rejectWorkerRuntimeAuthority(request) {
  for (const name of ["toolPolicy", "tool_policy", "runtimeOptions", "runtime_options"]) {
    if (request[name] !== undefined) {
      throw new Error(`KWP runtime query cannot set host-owned field ${name}`);
    }
  }
}

function normalizeLegacyRuntimeQueryRequest(request, context) {
  if (!isPlainObject(request)) throw new Error("ctx.runtime.query request must be an object");
  if (request.options !== undefined) return normalizeSdkRuntimeQueryRequest(request);
  const configModel = context?.config?.model;
  const model = request.model ?? configModel;
  if (!model) throw new Error("ctx.runtime.query requires request.model or config.model");
  const cwd = request.cwd ?? context?.cwd;
  return {
    model,
    cwd: stringField(cwd, "runtime query cwd"),
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

function normalizeSdkRuntimeQueryRequest(request) {
  const options = request.options;
  if (!isPlainObject(options)) {
    throw new Error("ctx.runtime.query request.options must be an object");
  }
  rejectUnsupportedRuntimeOptions(options);
  return {
    model: stringField(options.model, "runtime query options.model"),
    cwd: stringField(options.cwd, "runtime query options.cwd"),
    system_prompt: options.systemPromptPrefix ?? "",
    prompt: stringField(request.prompt, "runtime query prompt"),
    ...(options.allowedTools === undefined
      ? {}
      : {
          tool_policy: {
            profile: "default",
            tools: stringArrayField(options.allowedTools, "allowedTools"),
          },
        }),
    ...(options.outputFormat === undefined
      ? {}
      : { structured_output: normalizeSdkOutputFormat(options.outputFormat) }),
    ...(options.effort === undefined ? {} : { thinking_level: options.effort }),
    ...(options.maxOutputTokens === undefined
      ? {}
      : { max_output_tokens: options.maxOutputTokens }),
    ...(options.temperature === undefined ? {} : { temperature: options.temperature }),
  };
}

function normalizeSdkOutputFormat(outputFormat) {
  if (!isPlainObject(outputFormat) || outputFormat.type !== "json_schema") {
    throw new Error("runtime query outputFormat must be a json_schema object");
  }
  return {
    name: "dynamic-module-output",
    schema: outputFormat.schema,
    strict: optionalBooleanField(outputFormat.strict, false, "runtime query outputFormat.strict"),
  };
}

function rejectUnsupportedRuntimeOptions(options) {
  for (const name of [
    "disallowedTools",
    "customTools",
    "permissionMode",
    "maxBudgetUsd",
    "abortController",
    "history",
    "taskId",
    "fingerprint",
    "phase",
    "thinkingDisabled",
    "plugins",
    "canUseTool",
  ]) {
    if (options[name] !== undefined) {
      throw new Error(`native dynamic runtime does not support query option ${name}`);
    }
  }
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
  if (!allowed.has(value)) throw new Error(`unsupported dynamic module category ${kind}`);
  return value;
}

function normalizePhase(phase, effect, name) {
  const value = phase ?? (effect === "read" ? "operate" : undefined);
  if (!["map", "hunt", "confirm", "fix", "operate"].includes(value)) {
    throw new Error(`${name}.phase must be map, hunt, confirm, fix, or operate`);
  }
  if (effect !== "read" && value === "operate") {
    throw new Error(`${name}.phase must be map, hunt, confirm, or fix for effect ${effect}`);
  }
  return value;
}

function normalizeEffect(effect, name) {
  if (
    !["read", "workspace-write", "target-write", "repository-execute", "external-action"].includes(
      effect,
    )
  ) {
    throw new Error(
      `${name}.effect must be read, workspace-write, target-write, repository-execute, or external-action`,
    );
  }
  return effect;
}

function normalizeApproval(approval, effect, name) {
  if (!["none", "explicit"].includes(approval)) {
    throw new Error(`${name}.approval must be none or explicit`);
  }
  if (
    ["target-write", "repository-execute", "external-action"].includes(effect) &&
    approval !== "explicit"
  ) {
    throw new Error(`${name}.effect=${effect} requires approval=explicit`);
  }
  return approval;
}

function normalizeWorkspaceRequirement(requirement, name) {
  if (!["optional", "required"].includes(requirement)) {
    throw new Error(`${name}.workspaceRequirement must be optional or required`);
  }
  return requirement;
}

function normalizeRuntimeRequirement(tool, name) {
  const requirement =
    tool.runtimeRequirement ?? (tool.requires?.runtime === true ? "always" : "never");
  if (requirement !== "always" && requirement !== "never") {
    throw new Error(`${name}.runtimeRequirement must be always or never`);
  }
  return requirement;
}

function toolRequiresRuntime(tool) {
  return normalizeRuntimeRequirement(tool, tool.name) === "always";
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
  const normalized = map[compact];
  if (!normalized) throw new Error(`unsupported dynamic option type ${type}`);
  return normalized;
}

function rejectUnsupportedModuleSemantics(module) {
  rejectDefinedFields(
    module,
    ["init", "ready", "dispose", "requires", "knowledge", "events"],
    "module",
  );
}

function rejectUnsupportedToolSemantics(tool) {
  rejectDefinedFields(tool, ["init", "dag", "runLifecycle"], tool.name ?? "tool");
}

function rejectDefinedFields(value, fields, label) {
  for (const field of fields) {
    if (value[field] !== undefined) {
      throw new Error(`native dynamic host does not support ${label}.${field}`);
    }
  }
}

function rejectUnsupportedSchemaKeys(schema, supported, label) {
  const unsupported = Object.keys(schema).find((key) => !supported.has(key));
  if (unsupported) throw new Error(`${label} uses unsupported keyword ${unsupported}`);
}

function nativeExecutionContext(module, tool, context) {
  return {
    ...context,
    target: context.target ?? context.cwd,
    tool: {
      moduleId: module.id,
      name: tool.name,
      displayName: tool.displayName ?? tool.name,
    },
    runtime: context.runtime ?? unavailableRuntime(tool.name),
    bus: unsupportedHandle(tool.name, "bus"),
    host: { sdkVersion: HOST_PACKAGE_VERSION, capabilities: new Set() },
  };
}

function unavailableRuntime(toolName) {
  return {
    id: "unavailable",
    query() {
      throw new Error(`${toolName} used ctx.runtime without declaring runtimeRequirement=always`);
    },
  };
}

function unsupportedHandle(toolName, capability) {
  return new Proxy(
    {},
    {
      get() {
        throw new Error(
          `${toolName} used unsupported native dynamic context capability ctx.${capability}`,
        );
      },
    },
  );
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

function booleanField(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean`);
  return value;
}

function optionalBooleanField(value, fallback, label) {
  return value === undefined ? fallback : booleanField(value, label);
}

function stringArrayField(value, label) {
  const items = arrayField(value, label);
  if (!items.every((item) => typeof item === "string")) {
    throw new Error(`${label} must contain only strings`);
  }
  return items;
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
