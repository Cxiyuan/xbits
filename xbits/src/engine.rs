use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::intel::EventIntelAnnotations;
use crate::model::{HookEvent, Rule};

/// 威胁情报命中对 `score` 的增量：直接参与 `threshold` 的累计分判定，
/// 使"命中已知 C2 的告警"比同一规则下的未知告警更早越过阈值。
pub const INTEL_THREAT_SCORE_BONUS: u64 = 20;

/// 威胁情报命中对 `confidence` 的增量：在 `min_confidence` 门槛判定**之前**加到 confidence，
/// 因此可以帮助证据不足的告警达到门槛，但不会让它们绕过门槛（门槛仍是过滤器，V-09）。
pub const INTEL_THREAT_CONFIDENCE_BONUS: u64 = 15;

/// 白名单命中对 `confidence` 的扣减（白方向只降级）：降低输出置信度并写
/// `intel_decision=allowlist-downgraded`，不新增"情报驱动的静默丢弃"路径。
pub const INTEL_ALLOWLIST_CONFIDENCE_PENALTY: u64 = 25;

/// Central-engine output. Fields remain Xbits::Alert compatible; analysis
/// metadata is appended for evidence/confidence consumers.
///
/// 构造入口只有 [`Engine::make_alert`]：`Default` 是给测试/结构体更新语法用的，
/// 新增字段时靠 `..Default::default()` 自动跟随，避免再次出现"测试构造器漏字段"。
#[derive(Debug, Clone, Default, Serialize)]
pub struct EngineAlert {
    pub timestamp: String,
    pub signature_id: u64,
    pub signature: String,
    pub community_id: String,
    pub src: String,
    pub dst: String,
    pub sport: u64,
    pub dport: u64,
    pub proto: String,
    pub flow_id: String,
    pub score: u64,
    pub confidence: u64,
    pub evidence: String,
    pub reason: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
    /// 威胁情报命中（threat-intel/ 子模块：ip/domain/hash）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel: Option<serde_json::Value>,
    /// 白名单命中（allowlist/ 子模块：domain/ip）与 DNS 基线提示
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<serde_json::Value>,
    /// 情报决策标签：threat-hit / threat-overrides-allowlist / allowlist-downgraded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intel_decision: Option<String>,
}

#[derive(Debug, Clone)]
struct ContextEntry {
    event: HookEvent,
    at: Instant,
}

#[derive(Debug, Clone)]
struct PendingAlert {
    rule: Rule,
    event: HookEvent,
    key: String,
    at: Instant,
}

/// Stateful central analysis engine:
///   * buffers Zeek metadata contexts by connection;
///   * buffers Suricata alerts whose rules require context;
///   * emits only when context arrives, with confidence/evidence;
///   * suppresses benign contexts and context-missing alerts;
///   * enforces `min_confidence` as a real filter (confidence is never lifted to the threshold).
pub struct Engine {
    rules: Vec<Rule>,
    scores: HashMap<String, u64>,
    cid_uid: HashMap<String, String>,
    contexts: HashMap<String, ContextEntry>,
    pending: Vec<PendingAlert>,
    ttl: Duration,
    intel: Option<std::sync::Arc<crate::intel::IntelService>>,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            scores: HashMap::new(),
            cid_uid: HashMap::new(),
            contexts: HashMap::new(),
            pending: Vec::new(),
            ttl: Duration::from_secs(60),
            intel: None,
        }
    }

    /// 挂载统一情报服务（threat-intel + allowlist）；未挂载时告警不带情报标注。
    pub fn with_intel(mut self, intel: std::sync::Arc<crate::intel::IntelService>) -> Self {
        self.intel = Some(intel);
        self
    }

    /// 事件的情报标注（未挂载情报服务时 None）。上下文到达后把告警事件与合并后的
    /// 上下文一起查询，覆盖上下文里的 host/dns_query 等字段。
    fn annotations(&self, ev: &HookEvent, ctx: Option<&HookEvent>) -> Option<EventIntelAnnotations> {
        let svc = self.intel.as_ref()?;
        let ann = match ctx {
            Some(ctx) => svc.annotate_events(&[ev, ctx]),
            None => svc.annotate_event(ev),
        };
        (!ann.is_empty()).then_some(ann)
    }

    /// 对单个事件产出情报标注（文件事件在进入 triage 前调用；与告警路径共用同一套查询语义）。
    pub fn intel_annotations(&self, ev: &HookEvent) -> Option<EventIntelAnnotations> {
        self.annotations(ev, None)
    }

    pub fn rules_len(&self) -> usize {
        self.rules.len()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn key_for(ev: &HookEvent) -> String {
        // Use the 5-tuple first: Zeek does not export community_id, while
        // Suricata alerts normally do.  Preferring cid would break correlation.
        if let (Some(src), Some(dst)) = (ev.src.as_deref(), ev.dst.as_deref()) {
            if !src.is_empty() && !dst.is_empty() {
                let mut a = (src.to_string(), ev.sport.unwrap_or(0));
                let mut b = (dst.to_string(), ev.dport.unwrap_or(0));
                if a > b {
                    std::mem::swap(&mut a, &mut b);
                }
                return format!("tuple:{}:{}|{}:{}", a.0, a.1, b.0, b.1);
            }
        }
        if let Some(cid) = ev.community_id.as_deref().filter(|v| !v.is_empty()) {
            return format!("cid:{cid}");
        }
        if let Some(uid) = ev.uid.as_deref().filter(|v| !v.is_empty()) {
            return format!("uid:{uid}");
        }
        "unknown".into()
    }

    fn group_key(&self, ev: &HookEvent, rule: &Rule) -> String {
        let by = rule.group_by.as_deref().unwrap_or("community_id");
        match by {
            "src" => ev.src.clone().unwrap_or_else(|| "unknown".into()),
            "uid" => ev.uid.clone().unwrap_or_else(|| "unknown".into()),
            "host" => ev.host.clone().unwrap_or_else(|| "unknown".into()),
            _ => ev
                .community_id
                .clone()
                .or_else(|| ev.src.clone())
                .or_else(|| ev.uid.clone())
                .unwrap_or_else(|| "unknown".into()),
        }
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.contexts.retain(|_, c| now.duration_since(c.at) <= self.ttl);
        self.pending
            .retain(|p| now.duration_since(p.at) <= self.ttl);
    }

    fn merge_context(&mut self, ev: &HookEvent) {
        let key = Self::key_for(ev);
        let entry = self.contexts.entry(key).or_insert_with(|| ContextEntry {
            event: ev.clone(),
            at: Instant::now(),
        });
        entry.at = Instant::now();
        let dst = &mut entry.event;
        for (src, dst_field) in [
            (ev.uid.as_ref(), &mut dst.uid),
            (ev.src.as_ref(), &mut dst.src),
            (ev.dst.as_ref(), &mut dst.dst),
            (ev.proto.as_ref(), &mut dst.proto),
            (ev.host.as_ref(), &mut dst.host),
            (ev.user_agent.as_ref(), &mut dst.user_agent),
            (ev.method.as_ref(), &mut dst.method),
            (ev.uri.as_ref(), &mut dst.uri),
            (ev.community_id.as_ref(), &mut dst.community_id),
            (ev.event.as_ref(), &mut dst.event),
        ] {
            if src.is_some() {
                *dst_field = src.cloned();
            }
        }
        if ev.sport.is_some() {
            dst.sport = ev.sport;
        }
        if ev.dport.is_some() {
            dst.dport = ev.dport;
        }
        if ev.status.is_some() {
            dst.status = ev.status;
        }
    }

    fn benign(rule: &Rule, ctx: Option<&HookEvent>) -> bool {
        let Some(ctx) = ctx else { return false };
        let uri = ctx.uri.as_deref().unwrap_or("").to_lowercase();
        let host = ctx.host.as_deref().unwrap_or("").to_lowercase();
        rule.benign_uri_contains
            .iter()
            .any(|v| !v.is_empty() && uri.contains(&v.to_lowercase()))
            || rule
                .benign_host_contains
                .iter()
                .any(|v| !v.is_empty() && host.contains(&v.to_lowercase()))
    }

    /// 置信度只由上下文证据计算：无上下文 50，有上下文 70，再按 host/uri/status/ua 证据加分，
    /// 上限 100。**这里不应用 `min_confidence`**——门槛是过滤器（见 `make_alert`），
    /// 不能被门槛反向抬升，否则 `if confidence < minimum` 恒假（V-09）。
    fn confidence(ctx: Option<&HookEvent>) -> u64 {
        let mut confidence = if ctx.is_some() { 70 } else { 50 };
        if let Some(c) = ctx {
            if c.host.as_deref().is_some_and(|v| !v.is_empty()) {
                confidence += 10;
            }
            if c.uri.as_deref().is_some_and(|v| !v.is_empty()) {
                confidence += 10;
            }
            if c.status.is_some() {
                confidence += 5;
            }
            if c.user_agent.as_deref().is_some_and(|v| !v.is_empty()) {
                confidence += 5;
            }
        }
        confidence.min(100)
    }

    fn make_alert(
        ev: &HookEvent,
        rule: &Rule,
        ctx: Option<&HookEvent>,
        intel: Option<&EventIntelAnnotations>,
    ) -> Option<EngineAlert> {
        if rule.require_context && ctx.is_none() {
            return None;
        }
        if Self::benign(rule, ctx) {
            return None;
        }
        let mut confidence = Self::confidence(ctx);
        let mut score = rule.score.max(1);
        let mut intel_decision: Option<&'static str> = None;
        if let Some(ann) = intel {
            if ann.threat_hit() {
                // 威胁命中：score 参与 threshold 累计；confidence 在门槛判定前加分，
                // 因此"帮助达到" min_confidence，但不能让低于门槛的证据绕过门槛。
                score = score.saturating_add(INTEL_THREAT_SCORE_BONUS);
                confidence = confidence
                    .saturating_add(INTEL_THREAT_CONFIDENCE_BONUS)
                    .min(100);
                intel_decision = ann.decision();
            }
        }
        // min_confidence 是真正的过滤门槛：confidence 只由上下文证据 + 情报加分算出（不含门槛抬升），
        // 低于门槛即丢弃。白名单降级在门槛之后执行，保证"白方向只降级、不因门槛丢弃"。
        if let Some(minimum) = rule.min_confidence {
            if confidence < minimum {
                return None;
            }
        }
        if let Some(ann) = intel {
            if ann.decision() == Some("allowlist-downgraded") {
                // 白名单命中：只降级（扣置信度），输出照常，不在这里丢弃。
                confidence = confidence.saturating_sub(INTEL_ALLOWLIST_CONFIDENCE_PENALTY);
                intel_decision = Some("allowlist-downgraded");
            }
        }
        let signature = ev
            .signature
            .clone()
            .or_else(|| ev.event.clone())
            .or_else(|| ev.desc.clone())
            .unwrap_or_default();
        let mut evidence = rule.reason.clone().unwrap_or_else(|| rule.name.clone());
        if let Some(c) = ctx {
            let fields = [
                c.uid.as_ref().map(|v| format!("uid={v}")),
                c.host.as_ref().map(|v| format!("host={v}")),
                c.method.as_ref().map(|v| format!("method={v}")),
                c.uri.as_ref().map(|v| format!("uri={v}")),
                c.status.map(|v| format!("status={v}")),
                c.user_agent.as_ref().map(|v| format!("ua={v}")),
            ];
            let parts: Vec<String> = fields.into_iter().flatten().collect();
            if !parts.is_empty() {
                evidence = format!("{evidence}; {}", parts.join(" "));
            }
        }
        if let Some(decision) = intel_decision {
            evidence = format!("{evidence}; intel_decision={decision}");
        }
        Some(EngineAlert {
            timestamp: ev.timestamp.clone().or_else(|| ev.ts.clone()).unwrap_or_default(),
            signature_id: ev.sid.unwrap_or(0),
            signature,
            community_id: ev.community_id.clone().unwrap_or_default(),
            src: ev.src.clone().unwrap_or_default(),
            dst: ev.dst.clone().unwrap_or_default(),
            sport: ev.sport.unwrap_or(0),
            dport: ev.dport.unwrap_or(0),
            proto: ev.proto.clone().unwrap_or_default(),
            flow_id: ev.flow_id.clone().unwrap_or_default(),
            score,
            confidence,
            evidence,
            reason: rule.reason.clone().unwrap_or_else(|| rule.name.clone()),
            rule_id: rule.id.clone(),
            event: ev.event.clone(),
            alert_kind: ev.alert_kind.clone(),
            alert_name: ev.alert_name.clone().or_else(|| ev.signature.clone()),
            severity: ev.severity.clone(),
            uid: ev.uid.clone(),
            context: ctx.and_then(|c| serde_json::to_value(c).ok()),
            intel: intel.and_then(|ann| ann.threat.clone()),
            allowlist: intel.and_then(EventIntelAnnotations::allowlist_document),
            intel_decision: intel_decision.map(str::to_string),
        })
    }

    /// 累计分：规则分 + 情报威胁加分（情报因此真实参与 threshold 判定）。
    fn score_for(&mut self, ev: &HookEvent, rule: &Rule, intel_bonus: u64) -> u64 {
        let key = self.group_key(ev, rule);
        let entry = self.scores.entry(key).or_insert(0);
        *entry = entry.saturating_add(rule.score.max(1).saturating_add(intel_bonus));
        *entry
    }

    pub fn process(&mut self, ev: &HookEvent) -> Vec<EngineAlert> {
        if ev.kind.eq_ignore_ascii_case("match_context") {
            return Vec::new();
        }
        self.prune();
        if let (Some(cid), Some(uid)) = (&ev.community_id, &ev.uid) {
            if !cid.is_empty() && !uid.is_empty() {
                self.cid_uid.insert(cid.clone(), uid.clone());
            }
        }

        let is_zeek_context = ev.source.eq_ignore_ascii_case("zeek")
            && ev.kind.eq_ignore_ascii_case("event");
        let key = Self::key_for(ev);
        if is_zeek_context {
            self.merge_context(ev);
        }

        let mut out = Vec::new();
        if is_zeek_context {
            let context = self.contexts.get(&key).map(|c| c.event.clone());
            let pending_all = std::mem::take(&mut self.pending);
            let mut remaining = Vec::new();
            for pending in pending_all {
                if pending.key != key {
                    remaining.push(pending);
                    continue;
                }
                if let Some(ctx) = &context {
                    // 情报标注在决策点计算（合并上下文后），因此上下文里的 host/dns 也参与评分。
                    let ann = self.annotations(&pending.event, Some(ctx));
                    if let Some(alert) =
                        Self::make_alert(&pending.event, &pending.rule, Some(ctx), ann.as_ref())
                    {
                        out.push(alert);
                    }
                }
                // Rejected benign/confidence cases are dropped.
            }
            self.pending = remaining;
        }

        let context = if ev.source.eq_ignore_ascii_case("suricata") {
            self.contexts.get(&key).map(|c| c.event.clone())
        } else {
            None
        };
        let annotations = self.annotations(ev, context.as_ref());
        let intel_score_bonus = if annotations.as_ref().is_some_and(|a| a.threat_hit()) {
            INTEL_THREAT_SCORE_BONUS
        } else {
            0
        };

        for rule in self.rules.clone() {
            if !rule.matches(ev) {
                continue;
            }
            let accumulated = self.score_for(ev, &rule, intel_score_bonus);
            // 累计分（含情报加分）未达到规则阈值时不输出；避免 ignored threshold 导致规则洪泛
            if accumulated < rule.threshold.max(1) {
                continue;
            }
            if ev.source.eq_ignore_ascii_case("suricata") && rule.require_context && context.is_none()
            {
                self.pending.push(PendingAlert {
                    rule,
                    event: ev.clone(),
                    key: key.clone(),
                    at: Instant::now(),
                });
                continue;
            }
            if let Some(alert) =
                Self::make_alert(ev, &rule, context.as_ref(), annotations.as_ref())
            {
                out.push(alert);
            }
        }
        out
    }

    pub fn flush_pending(&mut self) -> Vec<EngineAlert> {
        self.pending.clear();
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> Rule {
        serde_json::from_str::<Rule>(
            r#"{"id":"r-sql","name":"web-sqli","source":"suricata","kind":"alert","signature_contains":"SQL","score":20,"threshold":20,"reason":"suricata-web-sqli"}"#,
        )
        .expect("rule")
    }

    fn alert_event() -> HookEvent {
        HookEvent {
            source: "suricata".into(),
            kind: "alert".into(),
            timestamp: Some("2026-01-01T00:00:00Z".into()),
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
    fn alert_triggers_rule_and_score() {
        let mut eng = Engine::new(vec![rule()]);
        let alerts = eng.process(&alert_event());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].signature_id, 9103001);
        assert_eq!(alerts[0].score, 20);
        assert_eq!(alerts[0].rule_id, "r-sql");
    }

    #[test]
    fn non_matching_event_is_ignored() {
        let mut eng = Engine::new(vec![rule()]);
        let ev = HookEvent {
            source: "zeek".into(),
            kind: "event".into(),
            event: Some("http_request".into()),
            ..Default::default()
        };
        assert!(eng.process(&ev).is_empty());
    }

    #[test]
    fn context_required_alert_waits_for_zeek_context() {
        let mut r = rule();
        r.require_context = true;
        r.benign_uri_contains = vec!["/healthz".into()];
        let mut eng = Engine::new(vec![r]);
        assert!(eng.process(&alert_event()).is_empty());
        assert_eq!(eng.pending_len(), 1);
        let context = HookEvent {
            source: "zeek".into(),
            kind: "event".into(),
            event: Some("http_request".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            sport: Some(40001),
            dport: Some(80),
            host: Some("app.example.test".into()),
            method: Some("GET".into()),
            uri: Some("/search?q=1%27%20UNION%20SELECT".into()),
            status: Some(200),
            ..Default::default()
        };
        let alerts = eng.process(&context);
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].confidence >= 80);
        assert!(alerts[0].evidence.contains("host=app.example.test"));
        assert_eq!(eng.pending_len(), 0);
    }

    #[test]
    fn benign_context_suppresses_alert() {
        let mut r = rule();
        r.require_context = true;
        r.benign_uri_contains = vec!["/healthz".into()];
        let mut eng = Engine::new(vec![r]);
        assert!(eng.process(&alert_event()).is_empty());
        let context = HookEvent {
            source: "zeek".into(),
            kind: "event".into(),
            event: Some("http_request".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            sport: Some(40001),
            dport: Some(80),
            uri: Some("/healthz".into()),
            ..Default::default()
        };
        assert!(eng.process(&context).is_empty());
    }

    // ---- 情报进入决策链（V-02/V-03）----

    fn tmpdir(prefix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("xbits-engine-{prefix}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn intel(
        threat: Option<&std::path::PathBuf>,
        allow: Option<&std::path::PathBuf>,
    ) -> std::sync::Arc<crate::intel::IntelService> {
        std::sync::Arc::new(crate::intel::IntelService::load(threat, allow))
    }

    #[test]
    fn alert_default_covers_intel_fields() {
        // 单一构造入口不变式：新增字段必须有 Default，测试用 ..Default::default() 跟随。
        let alert = EngineAlert::default();
        assert!(alert.intel.is_none());
        assert!(alert.allowlist.is_none());
        assert!(alert.intel_decision.is_none());
    }

    #[test]
    fn threat_intel_boosts_score_and_confidence() {
        let dir = tmpdir("threat");
        std::fs::write(dir.join("ip.txt"), "203.0.113.9\n").unwrap();
        let mut eng = Engine::new(vec![rule()]).with_intel(intel(Some(&dir), None));
        let alerts = eng.process(&alert_event());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].score, 20 + INTEL_THREAT_SCORE_BONUS);
        assert_eq!(alerts[0].confidence, 50 + INTEL_THREAT_CONFIDENCE_BONUS);
        assert_eq!(alerts[0].intel_decision.as_deref(), Some("threat-hit"));
        assert!(alerts[0].intel.is_some());
        assert!(alerts[0].evidence.contains("intel_decision=threat-hit"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_downgrades_and_marks_decision() {
        let dir = tmpdir("allow");
        std::fs::write(dir.join("ip.txt"), "10.0.0.80\n").unwrap();
        let mut eng = Engine::new(vec![rule()]).with_intel(intel(None, Some(&dir)));
        let alerts = eng.process(&alert_event());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].score, 20);
        assert_eq!(alerts[0].confidence, 50 - INTEL_ALLOWLIST_CONFIDENCE_PENALTY);
        assert_eq!(
            alerts[0].intel_decision.as_deref(),
            Some("allowlist-downgraded")
        );
        assert!(alerts[0].allowlist.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn threat_overrides_allowlist() {
        let threat = tmpdir("conflict-threat");
        let allow = tmpdir("conflict-allow");
        std::fs::write(threat.join("ip.txt"), "203.0.113.9\n").unwrap();
        std::fs::write(allow.join("ip.txt"), "10.0.0.80\n").unwrap();
        let mut eng = Engine::new(vec![rule()])
            .with_intel(intel(Some(&threat), Some(&allow)));
        let alerts = eng.process(&alert_event());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].score, 20 + INTEL_THREAT_SCORE_BONUS);
        assert_eq!(
            alerts[0].intel_decision.as_deref(),
            Some("threat-overrides-allowlist")
        );
        let _ = std::fs::remove_dir_all(&threat);
        let _ = std::fs::remove_dir_all(&allow);
    }

    #[test]
    fn threat_intel_from_context_applies_to_deferred_alert() {
        // 文件/域名情报在"挂起告警 + 上下文到达"路径上同样参与决策。
        let dir = tmpdir("threat-context");
        std::fs::write(dir.join("domain.txt"), "evil.example\n").unwrap();
        let mut r = rule();
        r.require_context = true;
        let mut eng = Engine::new(vec![r]).with_intel(intel(Some(&dir), None));
        assert!(eng.process(&alert_event()).is_empty());
        assert_eq!(eng.pending_len(), 1);
        let context = HookEvent {
            source: "zeek".into(),
            kind: "event".into(),
            event: Some("http_request".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            sport: Some(40001),
            dport: Some(80),
            host: Some("evil.example".into()),
            uri: Some("/login".into()),
            ..Default::default()
        };
        let alerts = eng.process(&context);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].intel_decision.as_deref(), Some("threat-hit"));
        assert_eq!(alerts[0].score, 20 + INTEL_THREAT_SCORE_BONUS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_event_intel_annotations_are_reachable() {
        // 文件事件在 hook 层进入 triage 前，先由引擎给出同一套情报标注（V-03）。
        let dir = tmpdir("file-hash");
        std::fs::write(dir.join("md5.txt"), "aa".repeat(16).as_str()).unwrap();
        let eng = Engine::new(Vec::new()).with_intel(intel(Some(&dir), None));
        let ev = HookEvent {
            source: "suricata".into(),
            kind: "file_stored".into(),
            file_md5: Some("aa".repeat(16)),
            ..Default::default()
        };
        let ann = eng.intel_annotations(&ev).expect("md5 intel hit");
        assert_eq!(ann.decision(), Some("threat-hit"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- min_confidence 必须是真的过滤器（V-09）----

    fn weak_http_context() -> HookEvent {
        // 只有 status 证据 → confidence = 70 + 5 = 75。
        HookEvent {
            source: "zeek".into(),
            kind: "event".into(),
            event: Some("http_request".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            sport: Some(40001),
            dport: Some(80),
            status: Some(200),
            ..Default::default()
        }
    }

    #[test]
    fn min_confidence_filters_low_confidence_and_strong_evidence_still_emits() {
        let mut r = rule();
        r.min_confidence = Some(90);
        let mut eng = Engine::new(vec![r]);
        // 无上下文：confidence = 50 < 90，必须不输出。
        // 旧实现 `.max(min_confidence)` 会把它抬到 90，过滤条件恒假（V-09）。
        assert!(eng.process(&alert_event()).is_empty());

        // 强证据：host+uri+status+ua → 100 ≥ 90，仍必须输出。
        let ctx = HookEvent {
            source: "zeek".into(),
            kind: "event".into(),
            event: Some("http_request".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            sport: Some(40001),
            dport: Some(80),
            host: Some("app.example.test".into()),
            uri: Some("/search?q=1".into()),
            status: Some(200),
            user_agent: Some("sqlmap/1.7".into()),
            ..Default::default()
        };
        assert!(eng.process(&ctx).is_empty(), "zeek 上下文不应触发 suricata 规则");
        let alerts = eng.process(&alert_event());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].confidence, 100);
    }

    #[test]
    fn min_confidence_interacts_correctly_with_intel_bonus() {
        let dir = tmpdir("minconf");
        std::fs::write(dir.join("ip.txt"), "203.0.113.9\n").unwrap();

        // 弱上下文 75 + min_confidence=90 + 无情报 → 丢弃。
        let mut r = rule();
        r.min_confidence = Some(90);
        r.require_context = true;
        let mut eng = Engine::new(vec![r]);
        assert!(eng.process(&alert_event()).is_empty());
        assert_eq!(eng.pending_len(), 1);
        assert!(
            eng.process(&weak_http_context()).is_empty(),
            "75 < 90 必须被门槛过滤"
        );
        assert_eq!(eng.pending_len(), 0);

        // 同样的弱上下文 + 威胁情报 +15 = 90 → 刚好达到门槛，输出。
        let mut r2 = rule();
        r2.min_confidence = Some(90);
        r2.require_context = true;
        let mut eng2 = Engine::new(vec![r2]).with_intel(intel(Some(&dir), None));
        assert!(eng2.process(&alert_event()).is_empty());
        let alerts = eng2.process(&weak_http_context());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].confidence, 75 + INTEL_THREAT_CONFIDENCE_BONUS);
        assert_eq!(alerts[0].intel_decision.as_deref(), Some("threat-hit"));

        // 情报加分不能绕过过滤器：min_confidence=100 时 90 仍被丢弃。
        let mut r3 = rule();
        r3.min_confidence = Some(100);
        r3.require_context = true;
        let mut eng3 = Engine::new(vec![r3]).with_intel(intel(Some(&dir), None));
        assert!(eng3.process(&alert_event()).is_empty());
        assert!(
            eng3.process(&weak_http_context()).is_empty(),
            "情报加分不得绕过 min_confidence=100"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
