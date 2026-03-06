export interface TaskOutputMeta {
  costUsd?: number;
  degradation?: {
    type: string;
    reason: string;
    message: string;
    [key: string]: unknown;
  };
}

const TASK_OUTPUT_META = Symbol.for("kuzushi.task-output-meta");

export function attachTaskOutputMeta<T>(
  output: T,
  meta: TaskOutputMeta,
): T {
  if (output == null || (typeof output !== "object" && typeof output !== "function")) {
    return output;
  }

  const nextMeta = {
    ...(getTaskOutputMeta(output) ?? {}),
    ...meta,
  };

  Object.defineProperty(output, TASK_OUTPUT_META, {
    value: nextMeta,
    enumerable: false,
    configurable: true,
    writable: true,
  });

  return output;
}

export function getTaskOutputMeta(output: unknown): TaskOutputMeta | undefined {
  if (output == null || (typeof output !== "object" && typeof output !== "function")) {
    return undefined;
  }

  return (output as { [TASK_OUTPUT_META]?: TaskOutputMeta })[TASK_OUTPUT_META];
}
