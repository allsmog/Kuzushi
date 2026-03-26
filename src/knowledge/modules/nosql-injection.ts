import type { KnowledgeModule } from "../types.js";

export const nosqlInjectionModule: KnowledgeModule = {
  id: "nosql-injection",
  cwes: ["CWE-943"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    { pattern: "User object passed directly to MongoDB find/findOne", why: "Allows operator injection ({$ne: null}, {$gt: ''})", severity: "ERROR" },
    { pattern: "$where clause with user-controlled string", why: "Arbitrary JavaScript execution on MongoDB server", severity: "ERROR" },
    { pattern: "$regex with unescaped user input", why: "ReDoS and data extraction via regex patterns", severity: "WARNING" },
    { pattern: "Aggregation pipeline with user-controlled stages", why: "Operator injection in $match, $lookup, $group", severity: "ERROR" },
  ],
  safePatterns: [
    { pattern: "express-mongo-sanitize middleware", why: "Strips $ and . from request parameters" },
    { pattern: "Mongoose schema with strict: true", why: "Rejects unknown fields, limits operator injection surface" },
    { pattern: "Class-validator DTO validation", why: "Validates and transforms input before query construction" },
    { pattern: "Explicit field extraction from request", why: "Only expected fields reach the query" },
  ],
  bypassTechniques: [
    "Nested object injection: req.body.username = {$ne: null} to match any user",
    "Regex injection: {$regex: '.*', $options: 'i'} for wildcard matching",
    "$where with string concatenation: {$where: 'this.pw == \"' + input + '\"'}",
    "Operator injection via query string: ?username[$ne]=&password[$ne]=",
    "Bypassing express-mongo-sanitize via JSON body (Content-Type: application/json)",
  ],
  detectionKeywords: [
    "find(", "findOne(", "findById(", "updateOne(", "deleteMany(",
    "$where", "$regex", "$ne", "$gt", "$lt", "$in",
    "aggregate(", "collection.", "Model.find",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "User.find({ email: req.body.email, password: req.body.password })",
      after: "User.find({ email: String(req.body.email), password: String(req.body.password) })",
      explanation: "Cast to String to prevent operator injection objects",
    },
  ],
  tags: ["nosql", "mongodb", "injection"],
};
