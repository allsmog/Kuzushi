import { authBypassModule } from "./modules/auth-bypass.js";
import { commandInjectionModule } from "./modules/command-injection.js";
import { cryptoModule } from "./modules/crypto.js";
import { deserializationModule } from "./modules/deserialization.js";
import { fileUploadModule } from "./modules/file-upload.js";
import { idorModule } from "./modules/idor.js";
import { nosqlInjectionModule } from "./modules/nosql-injection.js";
import { pathTraversalModule } from "./modules/path-traversal.js";
import { raceConditionModule } from "./modules/race-condition.js";
import { sqliModule } from "./modules/sqli.js";
import { ssrfModule } from "./modules/ssrf.js";
import { xssModule } from "./modules/xss.js";
import { xxeModule } from "./modules/xxe.js";
import { InMemoryKnowledgeRegistry } from "./registry.js";

export { InMemoryKnowledgeRegistry } from "./registry.js";
export type { KnowledgeModule, KnowledgeQuery, KnowledgeRegistry } from "./types.js";

/**
 * Create the default knowledge registry populated with all built-in modules.
 */
export function createDefaultKnowledgeRegistry(): InMemoryKnowledgeRegistry {
  const registry = new InMemoryKnowledgeRegistry();

  registry.register(sqliModule);
  registry.register(xssModule);
  registry.register(ssrfModule);
  registry.register(cryptoModule);
  registry.register(commandInjectionModule);
  registry.register(pathTraversalModule);
  registry.register(authBypassModule);
  registry.register(deserializationModule);
  registry.register(raceConditionModule);
  registry.register(xxeModule);
  registry.register(fileUploadModule);
  registry.register(idorModule);
  registry.register(nosqlInjectionModule);

  return registry;
}
