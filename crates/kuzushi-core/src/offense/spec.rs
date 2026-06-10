//! Declarative chain specs.
//!
//! An operator authors a chain as data — a name and an ordered list of HTTP
//! probe plays — rather than code. This keeps live offense deterministic and
//! auditable: the same spec always builds the same chain. Specs come from the
//! tool input inline or from a `.kuzushi/plays/<name>.json` file. An
//! LLM-planned loop can layer on top later, but the spec is the floor.

use super::chain::AttackChain;
use super::http_probe::HttpProbePlay;
use super::play::Play;
use super::transport::PlayRequest;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChainSpec {
    pub name: String,
    pub plays: Vec<PlaySpec>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlaySpec {
    pub name: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub headers: Vec<HeaderSpec>,
    #[serde(default)]
    pub body: Option<String>,
    /// Status that signifies the step landed.
    #[serde(default)]
    pub expect_status: Option<u16>,
    /// Strings that, if present in the response, signify the step landed.
    #[serde(default)]
    pub expect_signals: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HeaderSpec {
    pub name: String,
    pub value: String,
}

fn default_method() -> String {
    "GET".to_string()
}

impl ChainSpec {
    /// Build the executable chain. Fails when the spec has no plays or a play
    /// declares no success condition (a probe with neither an expected status
    /// nor a signal can never land, so it would silently break every chain).
    pub fn build(&self) -> Result<AttackChain, String> {
        if self.plays.is_empty() {
            return Err(format!("chain {:?} has no plays", self.name));
        }
        let mut plays: Vec<Box<dyn Play>> = Vec::with_capacity(self.plays.len());
        for spec in &self.plays {
            plays.push(spec.build()?);
        }
        Ok(AttackChain::new(self.name.clone(), plays))
    }
}

impl PlaySpec {
    fn build(&self) -> Result<Box<dyn Play>, String> {
        if self.expect_status.is_none() && self.expect_signals.is_empty() {
            return Err(format!(
                "play {:?} declares no success condition (expectStatus or expectSignals)",
                self.name
            ));
        }
        let mut probe = HttpProbePlay::new(self.name.clone(), self.request());
        if let Some(status) = self.expect_status {
            probe = probe.expect_status(status);
        }
        for signal in &self.expect_signals {
            probe = probe.expect_signal(signal.clone());
        }
        Ok(Box::new(probe))
    }

    fn request(&self) -> PlayRequest {
        PlayRequest {
            scheme: self.scheme.clone().unwrap_or_else(|| "https".to_string()),
            port: self.port,
            method: self.method.clone(),
            path: self.path.clone(),
            headers: self
                .headers
                .iter()
                .map(|header| (header.name.clone(), header.value.clone()))
                .collect(),
            body: self.body.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_json() -> serde_json::Value {
        serde_json::json!({
            "name": "bypass-idor",
            "plays": [
                {"name": "auth-bypass", "method": "POST", "path": "/login",
                 "body": "u=a&p=b", "expectStatus": 302, "expectSignals": ["Set-Cookie"]},
                {"name": "idor", "path": "/api/users/1", "expectStatus": 200}
            ]
        })
    }

    #[test]
    fn builds_a_chain_from_a_spec() {
        let spec: ChainSpec = serde_json::from_value(spec_json()).unwrap();
        let chain = spec.build().unwrap();
        assert_eq!(chain.name(), "bypass-idor");
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn play_defaults_to_get() {
        let spec: ChainSpec = serde_json::from_value(spec_json()).unwrap();
        assert_eq!(spec.plays[1].method, "GET");
    }

    #[test]
    fn empty_chain_is_rejected() {
        let spec = ChainSpec {
            name: "empty".to_string(),
            plays: Vec::new(),
        };
        assert!(spec.build().is_err());
    }

    #[test]
    fn play_without_success_condition_is_rejected() {
        let spec: ChainSpec = serde_json::from_value(serde_json::json!({
            "name": "bad",
            "plays": [{"name": "noop", "path": "/"}]
        }))
        .unwrap();
        let err = spec.build().unwrap_err();
        assert!(err.contains("success condition"));
    }
}
