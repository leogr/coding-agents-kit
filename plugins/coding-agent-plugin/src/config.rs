use falco_plugin::schemars::JsonSchema;
use falco_plugin::serde::Deserialize;

/// Plugin configuration, received from falco.yaml `init_config`.
#[derive(Deserialize, JsonSchema, Clone)]
#[schemars(crate = "falco_plugin::schemars")]
#[serde(crate = "falco_plugin::serde")]
pub struct CodingAgentConfig {
    /// Operational mode: "enforcement" (default) or "monitor".
    /// In monitor mode, rules are evaluated and logged but all verdicts resolve as allow.
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Broker listen address. On Unix, a Unix domain socket path.
    /// On Windows, a TCP address (e.g. "127.0.0.1:2803").
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Port for the HTTP alert receiver.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Tags that indicate a deny verdict.
    #[serde(default = "default_deny_tags")]
    pub deny_tags: Vec<String>,

    /// Tags that indicate an ask verdict.
    #[serde(default = "default_ask_tags")]
    pub ask_tags: Vec<String>,

    /// Tags that indicate evaluation is complete (seen).
    #[serde(default = "default_seen_tags")]
    pub seen_tags: Vec<String>,
}

fn default_mode() -> String {
    "enforcement".to_string()
}

fn default_socket_path() -> String {
    #[cfg(unix)]
    {
        if let Ok(home) = std::env::var("HOME") {
            format!("{home}/.coding-agents-kit/run/broker.sock")
        } else {
            "/tmp/coding-agents-kit-broker.sock".to_string()
        }
    }
    #[cfg(windows)]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            format!("{}/.coding-agents-kit/run/broker.sock", profile.replace('\\', "/"))
        } else {
            "C:/coding-agents-kit-broker.sock".to_string()
        }
    }
}

fn default_http_port() -> u16 {
    2802
}

fn default_deny_tags() -> Vec<String> {
    vec!["coding_agent_deny".to_string()]
}

fn default_ask_tags() -> Vec<String> {
    vec!["coding_agent_ask".to_string()]
}

fn default_seen_tags() -> Vec<String> {
    vec!["coding_agent_seen".to_string()]
}
