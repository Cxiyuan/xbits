use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::model::{HookEvent, Rule};

/// Central-engine output. Fields remain Xbits::Alert compatible; analysis
/// metadata is appended for evidence/confidence consumers.
#[derive(Debug, Clone, Serialize)]
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
///   * suppresses benign contexts and context-missing alerts.
pub struct Engine {
    rules: Vec<Rule>,
    scores: HashMap<String, u64>,
    cid_uid: HashMap<String, String>,
    contexts: HashMap<String, ContextEntry>,
    pending: Vec<PendingAlert>,
    ttl: Duration,
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
        }
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
                *dst_field = src.clone();
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

    fn confidence(rule: &Rule, ctx: Option<&HookEvent>) -> u64 {
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
        confidence.min(100).max(rule.min_confidence.unwrap_or(0))
    }

    fn make_alert(ev: &HookEvent, rule: &Rule, ctx: Option<&HookEvent>) -> Option<EngineAlert> {
        if rule.require_context && ctx.is_none() {
            return None;
        }
        if Self::benign(rule, ctx) {
            return None;
        }
        let confidence = Self::confidence(rule, ctx);
        if let Some(minimum) = rule.min_confidence {
            if confidence < minimum {
                return None;
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
            score: rule.score.max(1),
            confidence,
            evidence,
            reason: rule.reason.clone().unwrap_or_else(|| rule.name.clone()),
            rule_id: rule.id.clone(),
            event: ev.event.clone(),
            alert_kind: ev.alert_kind.clone(),
            alert_name: ev.alert_name.clone().or_else(|| ev.signature.clone()),
            severity: ev.severity.clone(),
            uid: ev.uid.clone(),
        })
    }

    fn score_for(&mut self, ev: &HookEvent, rule: &Rule) -> u64 {
        let key = self.group_key(ev, rule);
        let entry = self.scores.entry(key).or_insert(0);
        *entry += rule.score.max(1);
        *entry
    }

    pub fn process(&mut self, ev: &HookEvent) -> Vec<EngineAlert> {
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
            let mut remaining = Vec::new();
            for pending in self.pending.drain(..) {
                if pending.key == key {
                    if let Some(ref ctx) = context {
                        if let Some(alert) = Self::make_alert(&pending.event, &pending.rule, Some(ctx)) {
                            out.push(alert);
                        }
                    }
                    // Rejected benign/confidence cases are dropped.
                } else {
                    remaining.push(pending);
                }
            }
            self.pending = remaining;
        }

        for rule in self.rules.clone() {
            if !rule.matches(ev) {
                continue;
            }
            let _score = self.score_for(ev, &rule);
            let context = if ev.source.eq_ignore_ascii_case("suricata") {
                self.contexts.get(&key).map(|c| c.event.clone())
            } else {
                None
            };
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
            if let Some(alert) = Self::make_alert(ev, &rule, context.as_ref()) {
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
}
