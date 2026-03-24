//! Serializable secrets configuration types.
//!
//! These types flow through the JSON config pipeline from the SDK supervisor
//! to `msbnet`. They are the transport representation — the SDK crate has
//! higher-level builder types that convert into these.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Secrets configuration for a sandbox's network layer.
///
/// Carried inside [`NetworkConfig`](crate::config::NetworkConfig) and consumed
/// by `msbnet` to create a [`SecretsHandler`](super::SecretsHandler).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Secret entries with placeholders and allowed hosts.
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,

    /// Action when a secret placeholder is detected going to an unauthorized host.
    #[serde(default)]
    pub on_violation: SecretViolationAction,

    /// Never substitute secrets for TLS-bypassed domains (default: true).
    ///
    /// When true, secrets are never substituted for domains in the TLS bypass
    /// list, even if they match `allowed_hosts`. This prevents exfiltration
    /// via unverified TLS connections.
    #[serde(default = "default_true")]
    pub block_on_tls_bypass: bool,
}

/// A single secret entry for `msbnet`.
///
/// Contains the placeholder (what the sandbox sees), the real value (what gets
/// substituted for allowed hosts), and the host allowlist.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// The placeholder string the sandbox uses (e.g., `$MSB_a8f3b2c1`).
    pub placeholder: String,

    /// The real secret value. Substituted into outbound plaintext only for
    /// allowed hosts.
    ///
    /// Redacted in `Debug` output. Must be cleared (via
    /// [`SecretsConfig::redacted`]) before persisting `SandboxConfig` to the
    /// database — only present in the transient `NetworkConfig` JSON sent to
    /// `msbnet`.
    pub value: String,

    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,

    /// Which parts of the plaintext to scan for substitution.
    #[serde(default)]
    pub injection: SecretInjection,

    /// Require verified TLS identity before substitution (default: true).
    ///
    /// When enabled, the secret is only substituted if the connection goes
    /// through TLS interception (not bypass) and SNI matches an allowed host.
    #[serde(default = "default_true")]
    pub require_tls_identity: bool,
}

/// Host pattern for secret allowlist matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostPattern {
    /// Exact domain match (case-insensitive).
    Exact(String),

    /// Wildcard suffix match (e.g., `*.github.com`).
    /// Matches `foo.github.com` but not `github.com` itself.
    Wildcard(String),

    /// Any host. Only constructible via `SecretBuilder::allow_any_host_dangerous()`.
    Any,
}

/// Secret injection points — controls which parts of TLS plaintext are scanned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInjection {
    /// Substitute in HTTP headers (default: true).
    #[serde(default = "default_true")]
    pub headers: bool,

    /// Substitute in HTTP Basic Auth (default: true).
    #[serde(default = "default_true")]
    pub basic_auth: bool,

    /// Substitute in URL query parameters (default: false).
    #[serde(default)]
    pub query_params: bool,

    /// Substitute in request body (default: false).
    #[serde(default)]
    pub body: bool,
}

/// Action when a secret violation is detected.
///
/// A violation occurs when a placeholder appears in outbound traffic to a
/// host that is not in the secret's allowlist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum SecretViolationAction {
    /// Block the request silently.
    Block,

    /// Block and log the violation (default — recommended for visibility).
    #[default]
    BlockAndLog,

    /// Block, log, and terminate the sandbox (exits msbnet, which triggers
    /// supervisor shutdown).
    BlockAndTerminate,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SecretsConfig {
    /// Returns a copy with all secret values cleared.
    ///
    /// Used before persisting `SandboxConfig` to the database so that real
    /// secret values never reach disk. The structure (placeholders, hosts,
    /// injection config) is preserved for diagnostics.
    pub fn redacted(&self) -> Self {
        Self {
            secrets: self
                .secrets
                .iter()
                .map(|entry| SecretEntry {
                    value: String::new(),
                    ..entry.clone()
                })
                .collect(),
            on_violation: self.on_violation.clone(),
            block_on_tls_bypass: self.block_on_tls_bypass,
        }
    }
}

impl HostPattern {
    /// Returns `true` if the given SNI domain matches this pattern.
    pub fn matches(&self, sni: &str) -> bool {
        let lower = sni.to_ascii_lowercase();
        match self {
            Self::Exact(domain) => lower == domain.to_ascii_lowercase(),
            Self::Wildcard(pattern) => {
                let suffix = pattern
                    .strip_prefix("*.")
                    .unwrap_or(pattern)
                    .to_ascii_lowercase();
                lower.ends_with(&suffix)
                    && lower.len() > suffix.len()
                    && lower.as_bytes()[lower.len() - suffix.len() - 1] == b'.'
            }
            Self::Any => true,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEntry")
            .field("placeholder", &self.placeholder)
            .field("value", &"[REDACTED]")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("injection", &self.injection)
            .field("require_tls_identity", &self.require_tls_identity)
            .finish()
    }
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            secrets: Vec::new(),
            on_violation: SecretViolationAction::default(),
            block_on_tls_bypass: true,
        }
    }
}

impl Default for SecretInjection {
    fn default() -> Self {
        Self {
            headers: true,
            basic_auth: true,
            query_params: false,
            body: false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_pattern_exact_match() {
        let pattern = HostPattern::Exact("api.openai.com".into());
        assert!(pattern.matches("api.openai.com"));
        assert!(pattern.matches("API.OPENAI.COM"));
        assert!(!pattern.matches("evil.api.openai.com"));
        assert!(!pattern.matches("openai.com"));
    }

    #[test]
    fn test_host_pattern_wildcard_match() {
        let pattern = HostPattern::Wildcard("*.github.com".into());
        assert!(pattern.matches("api.github.com"));
        assert!(pattern.matches("raw.githubusercontent.github.com"));
        assert!(pattern.matches("API.GITHUB.COM"));
        assert!(!pattern.matches("github.com"));
        assert!(!pattern.matches("notgithub.com"));
    }

    #[test]
    fn test_host_pattern_any_match() {
        let pattern = HostPattern::Any;
        assert!(pattern.matches("anything.com"));
        assert!(pattern.matches("evil.attacker.net"));
    }

    #[test]
    fn test_secrets_config_default_serde_roundtrip() {
        let config = SecretsConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: SecretsConfig = serde_json::from_str(&json).unwrap();
        assert!(decoded.secrets.is_empty());
        assert!(decoded.block_on_tls_bypass);
    }

    #[test]
    fn test_secret_entry_serde_roundtrip() {
        let entry = SecretEntry {
            placeholder: "$MSB_a8f3b2c1".into(),
            value: "sk-secret-key".into(),
            allowed_hosts: vec![
                HostPattern::Exact("api.openai.com".into()),
                HostPattern::Wildcard("*.github.com".into()),
            ],
            injection: SecretInjection::default(),
            require_tls_identity: true,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let decoded: SecretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.placeholder, "$MSB_a8f3b2c1");
        assert_eq!(decoded.value, "sk-secret-key");
        assert_eq!(decoded.allowed_hosts.len(), 2);
        assert!(decoded.require_tls_identity);
    }

    #[test]
    fn test_secret_injection_default() {
        let injection = SecretInjection::default();
        assert!(injection.headers);
        assert!(injection.basic_auth);
        assert!(!injection.query_params);
        assert!(!injection.body);
    }
}
