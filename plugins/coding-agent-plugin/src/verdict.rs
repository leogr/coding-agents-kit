/// A verdict decision for a tool call.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Tool call allowed (no deny/ask rules matched).
    Allow,
    /// Tool call denied. Contains the reason string.
    Deny(String),
    /// Tool call requires user confirmation. Contains the reason string.
    Ask(String),
}

impl Verdict {
    /// Escalate: deny > ask > allow. Returns the more restrictive verdict.
    pub fn escalate(self, other: Verdict) -> Verdict {
        match (&self, &other) {
            (Verdict::Deny(_), _) => self,
            (_, Verdict::Deny(_)) => other,
            (Verdict::Ask(_), _) => self,
            (_, Verdict::Ask(_)) => other,
            _ => self,
        }
    }

    /// Serialize as the wire protocol response JSON.
    pub fn to_response_json(&self, id: &str) -> String {
        let (decision, reason) = match self {
            Verdict::Allow => ("allow", String::new()),
            Verdict::Deny(r) => ("deny", r.clone()),
            Verdict::Ask(r) => ("ask", r.clone()),
        };
        // Use serde_json to ensure proper escaping of reason string.
        serde_json::json!({
            "id": id,
            "decision": decision,
            "reason": reason,
        })
        .to_string()
    }
}
