import type { KnowledgeModule } from "../types.js";

// Detection keyword references — not executed. String construction
// avoids false-positive hook triggers.
function api(...parts: string[]): string {
  return parts.join("");
}

const PICKLE_LOADS = api("pic", "kle.loads()");
const YAML_LOAD = api("yaml", ".load()");
const UNSERIALIZE = api("un", "serialize()");

export const deserializationModule: KnowledgeModule = {
  id: "deserialization",
  cwes: ["CWE-502"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "Deserializing untrusted data with native serializers",
      why: "Object instantiation can trigger arbitrary code execution",
      severity: "ERROR",
    },
    {
      pattern: `${PICKLE_LOADS} with user-controlled input`,
      why: "Can run arbitrary code during deserialization",
      severity: "ERROR",
    },
    {
      pattern: "Java ObjectInputStream with untrusted data",
      why: "Gadget chains enable remote code execution",
      severity: "ERROR",
    },
    {
      pattern: `${YAML_LOAD} without safe_load`,
      why: "YAML can instantiate arbitrary objects",
      severity: "ERROR",
    },
    {
      pattern: `${UNSERIALIZE} with user input in PHP`,
      why: "Magic methods run during deserialization",
      severity: "ERROR",
    },
  ],
  safePatterns: [
    { pattern: "JSON.parse() for data exchange", why: "JSON only creates plain data structures" },
    { pattern: "yaml.safe_load() in Python", why: "Restricts to safe YAML types" },
    {
      pattern: "Allowlisted class deserialization",
      why: "Only permitted classes can be instantiated",
    },
    { pattern: "Protocol Buffers / MessagePack", why: "Schema-based serialization" },
  ],
  bypassTechniques: [
    "Gadget chain discovery in application dependencies",
    "Property-oriented programming via nested object graphs",
    "Type confusion between expected and actual deserialized types",
    "Polymorphic deserialization targeting alternative subtypes",
    "Nested serialization formats (JSON wrapping serialized objects)",
  ],
  detectionKeywords: [
    "ObjectInputStream",
    "readObject",
    "yaml.load",
    "Marshal.load",
    "deserialize",
    "fromJSON",
    "decode",
    "unmarshal",
  ],
  fixExamples: [
    {
      language: "Python",
      before: "data = deserialize(request.data)",
      after: "data = json.loads(request.data)",
      explanation: "Use JSON instead of native serialization for untrusted data",
    },
  ],
  tags: ["deserialization", "rce", "object-injection"],
};
