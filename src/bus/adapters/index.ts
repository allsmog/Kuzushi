import type { KuzushiConfig } from "../../types.js";
import type { MessageBus } from "../types.js";
import { InProcessBus } from "./in-process.js";

/** Create the configured message bus adapter. */
export function createBus(config: KuzushiConfig): MessageBus {
  switch (config.busBackend) {
    case "in-process":
      return new InProcessBus();
    default:
      throw new Error(
        `Unknown bus backend: ${String(config.busBackend)}. ` + "Expected one of: in-process.",
      );
  }
}

export { InProcessBus };
