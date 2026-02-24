import type { KuzushiConfig } from "../../types.js";
import type { MessageBus } from "../types.js";
import { InProcessBus } from "./in-process.js";
import { RedisBus } from "./redis.js";
import { GooglePubSubBus } from "./google-pubsub.js";
import { NatsBus } from "./nats.js";

/** Create the configured message bus adapter. */
export function createBus(config: KuzushiConfig): MessageBus {
  switch (config.busBackend) {
    case "in-process":
      return new InProcessBus();
    case "redis":
      return new RedisBus();
    case "google-pubsub":
      return new GooglePubSubBus();
    case "nats":
      return new NatsBus();
    default:
      throw new Error(
        `Unknown bus backend: ${String(config.busBackend)}. `
        + "Expected one of: in-process, redis, google-pubsub, nats.",
      );
  }
}

export { InProcessBus };
