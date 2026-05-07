//! Kuzushi `AgentRuntime` implementations.
//!
//! Despite the historical crate name (`kuzushi-openai`), this crate
//! hosts every concrete `AgentRuntime` impl:
//!
//! - [`PiAgentCoreRuntime`] — bridges to `scripts/pi-agent-core-bridge.mjs`,
//!   the existing TypeScript-side OAuth-aware client. Used for the
//!   OpenAI Codex flow and the legacy Anthropic refresh-token bridge.
//! - [`AnthropicOAuthRuntime`] — native Rust runtime that talks
//!   directly to `api.anthropic.com` over `reqwest`/`rustls` with an
//!   OAuth bearer token. No Node.js or pi-ai dependency. Suitable for
//!   environments where only a long-lived OAuth access token is
//!   available (e.g. a host-managed Claude Code token).

include!("__lib_impl.inc");
