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

/// 规则加载期校验（R5-4 / R15-4）：`threshold > score` 的慢速累积规则**必须**显式声明
/// 一个**正整数** `score_window_sec`。否则默认窗口（引擎事件 TTL，60s）会在两次命中之间
/// 把累计分清掉，规则永远无法达标——这类误配以前只能靠运行时的 `scores_expired` 间接察觉。
///
/// R15-4：`score_window_sec: 0` 是非法值（运行时窗口为 0 秒，累计分立即过期），但它曾能
/// 绕过"未声明"判定。这里把 0 视为"未声明/非法"一律拒绝：要么删掉该字段用默认 TTL，
/// 要么给正整数秒。
///
/// 返回 `Err` 时由调用方 fail-fast（`main.rs` 的 `load_rules` 转成非零退出），
/// 错误信息点名 rule id 与相关数值，便于直接定位规则文件中的条目。
impl Rule {
    pub fn validate(&self) -> Result<(), String> {
        if self.score_window_sec == Some(0) {
            return Err(format!(
                "rule id={} name={}: score_window_sec=0 is not allowed (a zero-second window \
                 expires the accumulated score immediately; delete the field to use the default \
                 TTL, or give a positive number of seconds)",
                self.id, self.name
            ));
        }
        if self.threshold > self.score && self.score_window_sec.is_none() {
            return Err(format!(
                "rule id={} name={}: threshold={} > score={} but score_window_sec is not declared; \
                 the default window would reset the accumulated score between hits and the rule \
                 could never reach its threshold (set a positive \"score_window_sec\" or make threshold <= score)",
                self.id, self.name, self.threshold, self.score
            ));
        }
        Ok(())
    }
}

/// 批量加载期校验（R5-4）：任一条规则非法即整体失败，不做"跳过坏规则继续跑"的静默降级。
pub fn validate_rules(rules: &[Rule]) -> Result<(), String> {
    for rule in rules {
        rule.validate()?;
    }
    Ok(())
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

    #[test]
    fn validate_accepts_threshold_at_or_below_score() {
        // 单事件即可达标（threshold <= score）无需窗口；默认 score/threshold = 1 同样合法。
        let rules: Vec<Rule> = serde_json::from_str(
            r#"[
                {"id":"r-eq","name":"eq","score":20,"threshold":20},
                {"id":"r-below","name":"below","score":30,"threshold":10},
                {"id":"r-default","name":"default"}
            ]"#,
        )
        .expect("rules");
        assert_eq!(validate_rules(&rules), Ok(()));
        for rule in &rules {
            assert_eq!(rule.validate(), Ok(()));
        }
    }

    #[test]
    fn validate_rejects_threshold_above_score_without_window() {
        // R5-4：threshold > score 且未声明 score_window_sec → 加载期必须报错，
        // 且错误信息点名 rule id 与两个数值（否则运维只能靠 scores_expired 猜）。
        let rule: Rule = serde_json::from_str(
            r#"{"id":"r-slow","name":"slow","score":20,"threshold":100}"#,
        )
        .expect("rule");
        let err = rule.validate().expect_err("must reject");
        assert!(err.contains("r-slow"), "错误必须点名 rule id: {err}");
        assert!(err.contains("threshold=100"), "错误必须带 threshold: {err}");
        assert!(err.contains("score=20"), "错误必须带 score: {err}");
        assert!(err.contains("score_window_sec"), "错误必须指出缺失字段: {err}");

        // 批量入口同样 fail-fast（第一条非法即返回，不静默跳过）。
        let valid: Rule = serde_json::from_str(
            r#"{"id":"r-ok","name":"ok","score":20,"threshold":20}"#,
        )
        .expect("rule");
        let err = validate_rules(&[valid, rule]).expect_err("batch must reject");
        assert!(err.contains("r-slow"), "{err}");
    }

    #[test]
    fn validate_accepts_threshold_above_score_with_explicit_window() {
        // 显式声明窗口 = 慢速累积规则，合法（窗口语义见 engine.rs score_for）。
        let rule: Rule = serde_json::from_str(
            r#"{"id":"r-slow","name":"slow","score":20,"threshold":100,"score_window_sec":3600}"#,
        )
        .expect("rule");
        assert_eq!(rule.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_zero_score_window() {
        // R15-4：`score_window_sec: 0` 曾能绕过“未声明”校验（运行时窗口 0 秒、累计分立即过期）。
        let slow_zero: Rule = serde_json::from_str(
            r#"{"id":"r-zero-slow","name":"zero-slow","score":20,"threshold":100,"score_window_sec":0}"#,
        )
        .expect("rule");
        let err = slow_zero.validate().expect_err("zero window must be rejected");
        assert!(err.contains("r-zero-slow"), "错误必须点名 rule id: {err}");
        assert!(err.contains("score_window_sec=0"), "错误必须指出 0 非法: {err}");
        assert!(err.contains("positive"), "错误必须给出修法: {err}");

        // 即使 threshold <= score，0 也是非法值（不是合法窗口）。
        let eq_zero: Rule = serde_json::from_str(
            r#"{"id":"r-zero-eq","name":"zero-eq","score":20,"threshold":20,"score_window_sec":0}"#,
        )
        .expect("rule");
        assert!(eq_zero.validate().is_err(), "0 秒窗口在任何规则上都非法");

        // 正整数窗口（哪怕 1 秒）合法。
        let positive: Rule = serde_json::from_str(
            r#"{"id":"r-pos","name":"pos","score":20,"threshold":100,"score_window_sec":1}"#,
        )
        .expect("rule");
        assert_eq!(positive.validate(), Ok(()));
    }
}
