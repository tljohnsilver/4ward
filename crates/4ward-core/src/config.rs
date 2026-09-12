use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

fn default_profile() -> String {
    "default".to_string()
}

fn default_true() -> bool {
    true
}

fn default_retention() -> u32 {
    1
}

fn default_sender_format() -> String {
    "{name} (via {alias}) <relay@{domain}>".to_string()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to parse config: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FourwardConfig {
    #[serde(default = "default_version")]
    pub version: String,
    pub project: String,
    pub aws: AwsConfig,
    pub api: ApiConfig,
    #[serde(default)]
    pub settings: EngineSettings,
    pub domains: Vec<DomainConfig>,
}

fn default_version() -> String {
    "1".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AwsConfig {
    pub region: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    pub stack_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub cors: Vec<String>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RateLimitConfig {
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
}

fn default_rps() -> u32 {
    100
}

fn default_burst() -> u32 {
    200
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EngineSettings {
    #[serde(default = "default_true")]
    pub banner_enabled: bool,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    #[serde(default = "default_sender_format")]
    pub sender_format: String,
}

impl Default for EngineSettings {
    fn default() -> Self {
        Self {
            banner_enabled: true,
            retention_days: 1,
            sender_format: default_sender_format(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsProvider {
    #[default]
    Route53,
    External,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainConfig {
    pub domain: String,
    #[serde(default)]
    pub dns_provider: DnsProvider,
    pub catch_all: Option<String>,
    #[serde(default)]
    pub routes: HashMap<String, Vec<String>>,
}

impl FourwardConfig {
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn from_file_contents(s: &str) -> Result<Self, ConfigError> {
        Self::from_json(s)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.project.trim().is_empty() {
            return Err(ConfigError::Validation("project must not be empty".into()));
        }
        if self.domains.is_empty() {
            return Err(ConfigError::Validation(
                "at least one domain is required".into(),
            ));
        }
        for d in &self.domains {
            if !d.domain.contains('.') {
                return Err(ConfigError::Validation(format!(
                    "invalid domain: {}",
                    d.domain
                )));
            }
            for (alias, dests) in &d.routes {
                if alias.trim().is_empty() {
                    return Err(ConfigError::Validation("alias must not be empty".into()));
                }
                if dests.is_empty() {
                    return Err(ConfigError::Validation(format!(
                        "alias '{alias}' must have at least one destination"
                    )));
                }
                for dest in dests {
                    if !dest.contains('@') {
                        return Err(ConfigError::Validation(format!(
                            "invalid destination email: {dest}"
                        )));
                    }
                }
            }
            if let Some(catch) = &d.catch_all {
                if !catch.contains('@') {
                    return Err(ConfigError::Validation(format!(
                        "invalid catch_all email: {catch}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Resolve destinations for `alias@domain`. Falls back to catch-all.
    pub fn resolve(&self, alias: &str, domain: &str) -> Vec<String> {
        for d in &self.domains {
            if d.domain.eq_ignore_ascii_case(domain) {
                if let Some(dests) = d.routes.get(alias) {
                    return dests.clone();
                }
                // case-insensitive alias lookup
                for (k, v) in &d.routes {
                    if k.eq_ignore_ascii_case(alias) {
                        return v.clone();
                    }
                }
                if let Some(catch) = &d.catch_all {
                    return vec![catch.clone()];
                }
                return vec![];
            }
        }
        vec![]
    }

    /// Render the `From:` display address for a relayed message.
    pub fn render_sender(&self, sender_name: &str, alias: &str, domain: &str) -> String {
        let name = if sender_name.trim().is_empty() {
            alias.to_string()
        } else {
            sender_name.to_string()
        };
        self.settings
            .sender_format
            .replace("{name}", &name)
            .replace("{alias}", alias)
            .replace("{domain}", domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> &'static str {
        r#"{
            "version": "1",
            "project": "demo",
            "aws": {"region": "us-east-1", "profile": "default", "stack_name": "fourward-demo"},
            "api": {"enabled": true, "cors": ["*"], "rate_limit": {"requests_per_second": 100, "burst": 200}},
            "settings": {"banner_enabled": true, "retention_days": 1, "sender_format": "{name} (via {alias}) <relay@{domain}>"},
            "domains": [
                {"domain": "example.com", "dns_provider": "route53", "catch_all": "me@gmail.com", "routes": {"support": ["a@x.com", "b@x.com"]}}
            ]
        }"#
    }

    #[test]
    fn parses_and_validates() {
        let cfg = FourwardConfig::from_json(sample()).unwrap();
        assert_eq!(cfg.project, "demo");
        assert_eq!(cfg.domains.len(), 1);
    }

    #[test]
    fn rejects_empty_domains() {
        let mut cfg = FourwardConfig::from_json(sample()).unwrap();
        cfg.domains.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn resolves_routes_and_catch_all() {
        let cfg = FourwardConfig::from_json(sample()).unwrap();
        assert_eq!(
            cfg.resolve("support", "example.com"),
            vec!["a@x.com".to_string(), "b@x.com".to_string()]
        );
        assert_eq!(
            cfg.resolve("unknown", "example.com"),
            vec!["me@gmail.com".to_string()]
        );
        assert!(cfg.resolve("support", "other.com").is_empty());
    }

    #[test]
    fn renders_sender() {
        let cfg = FourwardConfig::from_json(sample()).unwrap();
        let from = cfg.render_sender("Acme", "support", "example.com");
        assert!(from.contains("relay@example.com"));
        assert!(from.contains("via support"));
    }
}
