use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 统一 hook 事件：Suricata 插件 / Zeek 插件都发这个 JSON 形状。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HookEvent {
    #[serde(default)]
    pub source: String, // suricata | zeek
    #[serde(default)]
    pub kind: String, // alert | event

    #[serde(default)]
    pub ts: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub community_id: Option<String>,
    #[serde(default)]
    pub uid: Option<String>,

    #[serde(default, alias = "src_ip")]
    pub src: Option<String>,
    #[serde(default, alias = "dest_ip")]
    pub dst: Option<String>,
    #[serde(default, alias = "src_port")]
    pub sport: Option<u64>,
    #[serde(default, alias = "dest_port")]
    pub dport: Option<u64>,
    #[serde(default)]
    pub proto: Option<String>,

    #[serde(default, alias = "signature_id")]
    pub sid: Option<u64>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub desc: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub status: Option<u64>,
    #[serde(default)]
    pub alert_kind: Option<String>,
    #[serde(default)]
    pub alert_name: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub flow_id: Option<String>,
    #[serde(default)]
    pub tx_id: Option<u64>,

    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// 规则文件中的一条规则。匹配条件全部为可选，未填写的条件不参与过滤。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub proto: Option<String>,
    #[serde(default)]
    pub signature_contains: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub desc_contains: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub group_by: Option<String>, // community_id | src | uid
    #[serde(default)]
    pub require_context: bool,
    #[serde(default)]
    pub benign_uri_contains: Vec<String>,
    #[serde(default)]
    pub benign_host_contains: Vec<String>,
    #[serde(default)]
    pub min_confidence: Option<u64>,
    #[serde(default)]
    pub alert_kind: Option<String>,
    #[serde(default = "one")]
    pub score: u64,
    #[serde(default = "one")]
    pub threshold: u64,
    #[serde(default)]
    pub reason: Option<String>,
}

fn one() -> u64 {
    1
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_lowercase().contains(&needle.to_lowercase())
}

impl Rule {
    pub fn matches(&self, ev: &HookEvent) -> bool {
        if let Some(v) = &self.source {
            if !v.is_empty() && !ev.source.eq_ignore_ascii_case(v) {
                return false;
            }
        }
        if let Some(v) = &self.kind {
            if !v.is_empty() && !ev.kind.eq_ignore_ascii_case(v) {
                return false;
            }
        }
        if let Some(v) = &self.proto {
            if !v.is_empty() && !ev.proto.as_deref().unwrap_or("").eq_ignore_ascii_case(v) {
                return false;
            }
        }
        if let Some(v) = &self.signature_contains {
            if !contains_ci(ev.signature.as_deref().unwrap_or(""), v) {
                return false;
            }
        }
        if let Some(v) = &self.event {
            if !ev.event.as_deref().unwrap_or("").eq_ignore_ascii_case(v) {
                return false;
            }
        }
        if let Some(v) = &self.desc_contains {
            if !contains_ci(ev.desc.as_deref().unwrap_or(""), v) {
                return false;
            }
        }
        if let Some(v) = &self.method {
            if !ev.method.as_deref().unwrap_or("").eq_ignore_ascii_case(v) {
                return false;
            }
        }
        if let Some(v) = &self.alert_kind {
            if !v.is_empty()
                && !ev
                    .alert_kind
                    .as_deref()
                    .unwrap_or("")
                    .eq_ignore_ascii_case(v)
            {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> HookEvent {
        HookEvent {
            source: "suricata".into(),
            kind: "alert".into(),
            signature: Some("[Web漏洞利用] SQL 注入".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            sport: Some(40001),
            dport: Some(80),
            proto: Some("TCP".into()),
            sid: Some(9103001),
            ..Default::default()
        }
    }

    #[test]
    fn rule_matches_signature_and_source() {
        let rule: Rule = serde_json::from_str(
            r#"{"id":"r1","name":"sql","source":"suricata","signature_contains":"SQL","score":20,"threshold":20}"#,
        )
        .expect("rule");
        assert!(rule.matches(&base_event()));
    }

    #[test]
    fn rule_rejects_wrong_source() {
        let rule: Rule = serde_json::from_str(
            r#"{"id":"r1","name":"sql","source":"suricata","signature_contains":"SQL"}"#,
        )
        .expect("rule");
        let mut ev = base_event();
        ev.source = "zeek".into();
        assert!(!rule.matches(&ev));
    }
}
