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
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub payload_printable: Option<String>,
    #[serde(default)]
    pub request_body: Option<String>,
    #[serde(default)]
    pub response_body: Option<String>,
    #[serde(default)]
    pub dns_query: Option<String>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default, alias = "buffer")]
    pub match_context_buffer: Option<String>,
    #[serde(default, alias = "buffer_b64")]
    pub match_context_value: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub app_proto: Option<String>,

    // ---- 文件转存 / 静态 triage 相关 ----
    /// 转存文件的 SHA256（Suricata file-store v2 以其命名 / 分桶）。
    #[serde(default, alias = "sha256")]
    pub file_sha256: Option<String>,
    #[serde(default)]
    pub file_sha1: Option<String>,
    #[serde(default)]
    pub file_md5: Option<String>,
    /// 原始文件名（可能来自 HTTP 文件名 / Content-Disposition）。
    #[serde(default, alias = "filename")]
    pub file_name: Option<String>,
    /// 魔数/类型描述（EVE fileinfo.magic）。
    #[serde(default)]
    pub file_magic: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    /// Suricata 是否真正把文件写盘（fileinfo.stored）。
    #[serde(default)]
    pub file_stored: Option<bool>,
    /// 文件在磁盘上的绝对路径（可选；缺省时由 --file-spool-dir + sha256 推导）。
    #[serde(default, alias = "filepath")]
    pub file_path: Option<String>,

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
    pub sid_in: Vec<u64>,
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
    /// 输出置信度门槛（真正的过滤器）：`confidence` 只由上下文证据 + 威胁情报加分算出，
    /// 低于该值直接丢弃；门槛**不会**反向抬高 `confidence`（见 engine.rs，V-09）。
    #[serde(default)]
    pub min_confidence: Option<u64>,
    #[serde(default)]
    pub alert_kind: Option<String>,
    #[serde(default = "one")]
    pub score: u64,
    #[serde(default = "one")]
    pub threshold: u64,
    /// 累计分窗口（秒），按规则声明；未设置时用引擎默认窗口（与事件 TTL 相同，默认 60s）。
    ///
    /// `threshold > score` 的慢速累积规则**必须显式声明足够长的窗口**：窗口内同一 `group_by`
    /// 的命中累计分达到 `threshold` 才输出；窗口过期后累计分从 0 重新开始（窗口语义见
    /// engine.rs 的 `score_for`/`prune_at`，R4-2）。
    #[serde(default)]
    pub score_window_sec: Option<u64>,
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
        if !self.sid_in.is_empty() {
            match ev.sid {
                Some(sid) if self.sid_in.contains(&sid) => {}
                _ => return false,
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
