use std::collections::HashMap;

use serde::Serialize;

use crate::model::{HookEvent, Rule};

/// 引擎输出的告警消息。字段名与现有 Zeek `Xbits::Alert` 兼容，便于直接复用
/// `xbits/zeek/xbits_suricata.zeek` 的 `from_json`。
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
    pub reason: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
}

/// 中央分析引擎：维护跨事件的上下文状态，并按规则文件做匹配/评分。
pub struct Engine {
    rules: Vec<Rule>,
    scores: HashMap<String, u64>,
    cid_uid: HashMap<String, String>,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            scores: HashMap::new(),
            cid_uid: HashMap::new(),
        }
    }

    pub fn rules_len(&self) -> usize {
        self.rules.len()
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

    /// 处理一个 hook 事件，返回本事件触发的引擎告警（可能为空）。
    pub fn process(&mut self, ev: &HookEvent) -> Vec<EngineAlert> {
        if let (Some(cid), Some(uid)) = (&ev.community_id, &ev.uid) {
            if !cid.is_empty() && !uid.is_empty() {
                self.cid_uid.insert(cid.clone(), uid.clone());
            }
        }

        let mut out = Vec::new();
        for rule in self.rules.clone() {
            if !rule.matches(ev) {
                continue;
            }
            let key = self.group_key(ev, &rule);
            let entry = self.scores.entry(key).or_insert(0);
            *entry += rule.score.max(1);
            let score = *entry;
            if score < rule.threshold.max(1) {
                continue;
            }

            let signature = ev
                .signature
                .clone()
                .or_else(|| ev.event.clone())
                .or_else(|| ev.desc.clone())
                .unwrap_or_default();
            out.push(EngineAlert {
                timestamp: ev
                    .timestamp
                    .clone()
                    .or_else(|| ev.ts.clone())
                    .unwrap_or_default(),
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
                reason: rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| rule.name.clone()),
                rule_id: rule.id.clone(),
                event: ev.event.clone(),
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> Rule {
        serde_json::from_str::<Rule>(
            r#"{"id":"r-sql","name":"web-sqli","source":"suricata","signature_contains":"SQL","score":20,"threshold":20,"reason":"suricata-web-sqli"}"#,
        )
        .expect("rule")
    }

    #[test]
    fn alert_triggers_rule_and_score() {
        let mut eng = Engine::new(vec![rule()]);
        let ev = HookEvent {
            source: "suricata".into(),
            kind: "alert".into(),
            timestamp: Some("2026-01-01T00:00:00Z".into()),
            signature: Some("[Web漏洞利用] SQL 注入".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            dport: Some(80),
            proto: Some("TCP".into()),
            sid: Some(9103001),
            ..Default::default()
        };
        let alerts = eng.process(&ev);
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
}
