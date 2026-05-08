/**
 * Shared attachment subsystem — public surface.
 *
 * Modules that want a "knowledge base" affordance (file/URL attachments
 * surfaced to the LLM as untrusted reference material) consume this package
 * via `createAttachmentTools(spec)` and a `KindSpec<K>` they declare locally.
 * See `src/modules/threat-model/attachments.ts` for the canonical example.
 */

export type { AttachDocumentInput, AttachDocumentOptions } from "./documents.js";
export { attachDocument, DEFAULT_MAX_BYTES, inferKind } from "./documents.js";
export type {
  RenderedAttachments,
  RenderUntrustedAttachmentsOptions,
} from "./prompts.js";
export { renderUntrustedAttachments } from "./prompts.js";
export {
  attachmentsPath,
  defaultAttachmentAdapter,
  removeAttachment,
  upsertAttachment,
} from "./storage.js";
export type {
  AttachmentHomeRow,
  AttachmentsHomeSlice,
  AttachmentTool,
  CreateAttachmentToolsOptions,
} from "./tools.js";
export {
  buildHomeSlice,
  createAttachmentTools,
} from "./tools.js";
export type {
  AttachmentDocument,
  AttachmentScope,
  AttachmentStatus,
  AttachmentStorageAdapter,
  KindSpec,
} from "./types.js";
