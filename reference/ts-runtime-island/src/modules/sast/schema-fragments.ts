export const targetProperty = {
  type: "string",
  description: "Path to the repository to scan.",
} as const;

export const severityProperty = {
  type: "array",
  items: { type: "string", enum: ["critical", "high", "medium", "low"] },
  description: "Minimum severity levels to include.",
} as const;
