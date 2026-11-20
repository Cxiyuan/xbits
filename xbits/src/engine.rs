use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

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

/// 请求→响应关联成立（V-14 方案①）对 `confidence` 的增量：与情报加分同一通道——
/// 在 `min_confidence` 门槛判定**之前**加入，帮助证据不足的关联告警达到门槛，
/// 但不会让它们绕过门槛。值写入 README §8.2。
pub const CORRELATION_CONFIDENCE_BONUS: u64 = 15;

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
    /// 降级告警标签（R4-1）：目前只有 `context-missing`——`require_context` 规则等不到上下文、
    /// 挂起超时后按 fail-closed 产出的可见判定结果（不再是"丢弃且无输出"）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<String>,
    /// 请求→响应关联标记（V-14/方案①）：success_rules 声明的响应侧规则命中且与
    /// 先前请求侧告警同 community_id 时置 Some（值为配对到的请求侧 SID 文本）。
    /// 告警仍走现有输出通道，这只是可见的结构化标记；同时 confidence 获
    /// [`CORRELATION_CONFIDENCE_BONUS`] 加成（在门槛判定前，与情报加分同一通道）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlated: Option<String>,
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

/// 引擎累计分表容量上限：超过后**淘汰最旧条目**（只丢最旧的一部分，不再整表重置）并计数
/// `scores_evicted`，避免高基数下无界增长又不至于一次丢掉全部累计分（R4-2）。
const MAX_SCORES: usize = 100_000;
/// 引擎 pending 容量上限：超过后按 FIFO 丢弃最旧一条并计数（`pending_overflow`），不再无界增长。
const MAX_PENDING: usize = 4096;

/// 累计分条目：带最近更新时间与本条目生效的窗口，供 TTL 清理（V-06/R4-2：
/// scores 不再只增不减；窗口可被规则 `score_window_sec` 拉长）。
#[derive(Debug, Clone)]
struct ScoreEntry {
    score: u64,
    at: Instant,
    /// 该条目当前生效的累计窗口（最近一次命中的规则声明；未声明则用引擎默认窗口）。
    window: Duration,
}

/// success_rules.json 的一条请求→响应关联（V-14 方案①）。
///
/// 文件由 `规则检测/convert_probe_rules.py` 生成，结构：
/// `[{"sid": <响应侧>, "depends": [<请求侧>...], "scopes": [...], ...}]`。
/// 语义：请求侧规则（depends）命中后，同一 `community_id`（5 元组回退）上
/// 响应侧规则（sid）命中 → 响应侧告警标记 `correlated=<请求侧 SID>`。
#[derive(Debug, Clone, Deserialize)]
pub struct SuccessPair {
    pub sid: u64,
    #[serde(default)]
    pub depends: Vec<u64>,
    #[serde(default)]
    pub scopes: Vec<u64>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
}

/// success_rules 关联表：响应侧 SID → 请求侧 SID 列表（加载时展开，查询 O(1)）。
#[derive(Debug, Clone, Default)]
pub struct SuccessRules {
    response_to_requests: HashMap<u64, Vec<u64>>,
}

impl SuccessRules {
    /// 从 JSON（数组形态）解析；解析失败由调用方转成明确错误（不静默降级）。
    pub fn parse(json: &str) -> Result<Self, String> {
        let entries: Vec<SuccessPair> =
            serde_json::from_str(json).map_err(|err| format!("bad success_rules json: {err}"))?;
        let mut map: HashMap<u64, Vec<u64>> = HashMap::new();
        for entry in entries {
            if entry.depends.is_empty() {
                continue;
            }
            map.entry(entry.sid).or_default().extend(entry.depends);
        }
        Ok(Self {
            response_to_requests: map,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.response_to_requests.is_empty()
    }

    pub fn len(&self) -> usize {
        self.response_to_requests.len()
    }

    /// 该响应侧 SID 声明的请求侧 SID 列表。
    pub fn requests_for(&self, response_sid: u64) -> Option<&[u64]> {
        self.response_to_requests
            .get(&response_sid)
            .map(|v| v.as_slice())
    }

    /// 这批 sid 中是否有任一是任何响应规则的 depends（请求侧命中判定）。
    pub fn is_request_sid_of(&self, sids: &[u64]) -> bool {
        sids.iter()
            .any(|sid| self.response_to_requests.values().any(|deps| deps.contains(sid)))
    }

    /// 请求侧 SID 是否是任何响应规则的 depends（单值便捷判定）。
    pub fn is_request_sid(&self, sid: u64) -> bool {
        self.response_to_requests.values().any(|deps| deps.contains(&sid))
    }
}

/// 请求→响应关联的等待条目：请求侧告警命中后登记，等待同 cid 的响应侧命中。
#[derive(Debug, Clone)]
struct CorrelationWait {
    /// 同一 key 上可有多个请求侧 SID（探测序列常连续命中多条规则）；
    /// 只留第一个会让后续请求的响应关联丢失且无计数（R12-3）。
    request_sids: Vec<u64>,
    at: Instant,
}

/// 请求→响应关联等待 TTL：取引擎事件 TTL（60s）的 2 倍——响应通常紧随请求，
/// 但 PVS 探测类流量可能跨多个请求周期；120s 足够覆盖绝大多数握手-响应往返，
/// 又不会让表无限增长（容量另有 `MAX_CORRELATIONS` 保护）。
const CORRELATION_TTL: Duration = Duration::from_secs(120);

/// 请求→响应关联等待表容量上限：超过后 FIFO 挤掉最旧条目并计数 `correlation_overflow`，
/// 复用 pending 的治理思路（V-06：有界 + 可见，不做无界缓存）。
const MAX_CORRELATIONS: usize = 4096;

/// Stateful central analysis engine:
///   * buffers Zeek metadata contexts by connection;
///   * buffers Suricata alerts whose rules require context;
///   * emits only when context arrives, with confidence/evidence;
///   * suppresses benign contexts and context-missing alerts;
///   * enforces `min_confidence` as a real filter (confidence is never lifted to the threshold);
///   * owns TTL/capacity governance for its state tables and reports what it drops (V-06).
pub struct Engine {
    rules: Vec<Rule>,
    /// 累计分表：按 group_key 累计，带 TTL 与容量上限（超限重置并计数）。
    scores: HashMap<String, ScoreEntry>,
    contexts: HashMap<String, ContextEntry>,
    pending: Vec<PendingAlert>,
    ttl: Duration,
    intel: Option<std::sync::Arc<crate::intel::IntelService>>,
    /// 请求→响应关联（V-14 方案①）：success_rules 表 + 等待表 + 计数。
    success_rules: SuccessRules,
    correlations: HashMap<String, CorrelationWait>,
    correlation_overflow: u64,
    correlation_timeouts: u64,
    correlation_pairs: u64,
    /// TTL/容量治理的可观测计数：过期清理不再静默（V-06）。
    pending_expired: u64,
    pending_overflow: u64,
    contexts_expired: u64,
    scores_expired: u64,
    scores_evicted: u64,
    /// 测试可下调容量上限（生产用上面的常量）。
    max_pending: usize,
    max_scores: usize,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            scores: HashMap::new(),
            contexts: HashMap::new(),
            pending: Vec::new(),
            ttl: Duration::from_secs(60),
            intel: None,
            success_rules: SuccessRules::default(),
            correlations: HashMap::new(),
            correlation_overflow: 0,
            correlation_timeouts: 0,
            correlation_pairs: 0,
            pending_expired: 0,
            pending_overflow: 0,
            contexts_expired: 0,
            scores_expired: 0,
            scores_evicted: 0,
            max_pending: MAX_PENDING,
            max_scores: MAX_SCORES,
        }
    }

    /// 挂载 success_rules 关联表（V-14 方案①）；未挂载时关联功能整体关闭。
    pub fn with_success_rules(mut self, rules: SuccessRules) -> Self {
        self.success_rules = rules;
        self
    }

    /// TTL 过期被清理的关联等待条目数（等待响应超时未配对）。
    pub fn correlation_timeouts(&self) -> u64 {
        self.correlation_timeouts
    }

    /// 成功配对的请求→响应关联数。
    pub fn correlation_pairs(&self) -> u64 {
        self.correlation_pairs
    }

    /// 关联等待表溢出（挤掉最旧）计数。
    pub fn correlation_overflow(&self) -> u64 {
        self.correlation_overflow
    }

    /// 当前等待中的关联条目数（测试/诊断用）。
    pub fn correlations_len(&self) -> usize {
        self.correlations.len()
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

    /// 上下文缓存条目数（TTL 清理的可观测入口）。
    pub fn contexts_len(&self) -> usize {
        self.contexts.len()
    }

    /// 累计分表条目数。
    pub fn scores_len(&self) -> usize {
        self.scores.len()
    }

    /// TTL 过期被清理的挂起告警数（`prune` 每次累加，V-06：不再静默丢弃）。
    pub fn pending_expired(&self) -> u64 {
        self.pending_expired
    }

    /// pending 达到容量上限后被 FIFO 挤掉的最旧告警数。
    pub fn pending_overflow(&self) -> u64 {
        self.pending_overflow
    }

    /// TTL 过期被清理的上下文条目数。
    pub fn contexts_expired(&self) -> u64 {
        self.contexts_expired
    }

    /// TTL 过期被清理的累计分条目数。
    pub fn scores_expired(&self) -> u64 {
        self.scores_expired
    }

    /// 累计分表因超过容量上限被淘汰的条目总数（只淘汰最旧条目，不再整表重置）。
    pub fn scores_evicted(&self) -> u64 {
        self.scores_evicted
    }

    fn key_for(ev: &HookEvent) -> String {
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

    /// 关联专用 key：community_id 是流身份，必须参与配对——只按 5 元组会让
    /// 同一端点上不同会话（不同 cid）的请求/响应误配（CI correlation_requires_same_cid）。
    /// Zeek 侧没有 cid 时退回 5 元组，保持跨引擎关联可用。
    fn correlation_key(ev: &HookEvent) -> String {
        let tuple = Self::key_for(ev);
        match ev.community_id.as_deref().filter(|v| !v.is_empty()) {
            Some(cid) => format!("cid:{cid}|{tuple}"),
            None => tuple,
        }
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

    /// 引擎维护：按当前时刻清理 TTL/容量，并返回过期挂起告警的降级输出。
    ///
    /// R5-1：hook listener 用 read_timeout/accept tick **定时**调用它，不再依赖"下一条事件到达"
    /// 才触发维护——否则挂起后流量停止，降级告警/计数会无限期推迟。
    pub fn maintenance(&mut self) -> Vec<(HookEvent, EngineAlert)> {
        self.prune_at(Instant::now())
    }

    fn prune(&mut self) -> Vec<(HookEvent, EngineAlert)> {
        self.prune_at(Instant::now())
    }

    /// 按给定时刻清理 TTL 过期状态（测试可传入推进后的时刻），并返回过期挂起告警的**降级输出**
    /// （连同其原始事件，供调用方按事件投递给分析流水线）。
    ///
    /// V-06 / R4-1：
    /// - `retain` 清理必须**可见**：contexts/pending/scores 的过期分别累加到对应计数并打日志；
    /// - 引擎 pending 过期**不再丢弃**：按 fail-closed 产出一条带 `degraded=context-missing`
    ///   的 `EngineAlert`（reason 也是 `context-missing`、evidence 里写明"上下文始终没到"），
    ///   由 `process()`/`maintenance()` 返回，hook 因此能写 stdout 并送进分析流水线；
    /// - 累计分表超容量上限**不再整表清空**：只淘汰最旧条目并计数 `scores_evicted`（R4-2）。
    fn prune_at(&mut self, now: Instant) -> Vec<(HookEvent, EngineAlert)> {
        let contexts_before = self.contexts.len();
        self.contexts
            .retain(|_, c| now.duration_since(c.at) <= self.ttl);
        let contexts_dropped = contexts_before - self.contexts.len();

        // pending 逐条判定：过期者收集起来产出降级告警（不静默丢）。
        let mut expired: Vec<PendingAlert> = Vec::new();
        let mut remaining: Vec<PendingAlert> = Vec::new();
        for pending in self.pending.drain(..) {
            if now.duration_since(pending.at) > self.ttl {
                expired.push(pending);
            } else {
                remaining.push(pending);
            }
        }
        self.pending = remaining;

        // 累计分按条目自身窗口过期（规则可用 `score_window_sec` 拉长窗口，R4-2）。
        let scores_before = self.scores.len();
        self.scores.retain(|_, s| now.duration_since(s.at) <= s.window);
        let scores_dropped = scores_before - self.scores.len();

        // 请求→响应关联等待表（V-14）：TTL 过期 = 未等到响应侧命中，计数 + 清理。
        // 关联本身是"增强信号"而不是判定：过期不需要产出降级告警（请求侧告警已正常
        // 判定过），但必须计数 `correlation_timeouts` 保持可见。
        let correlations_before = self.correlations.len();
        self.correlations
            .retain(|_, w| now.duration_since(w.at) <= CORRELATION_TTL);
        let correlations_dropped = correlations_before - self.correlations.len();
        if correlations_dropped > 0 {
            self.correlation_timeouts += correlations_dropped as u64;
            eprintln!(
                "xbits: engine expired {correlations_dropped} correlation wait(s) without a matching response alert (total={})",
                self.correlation_timeouts
            );
        }

        if contexts_dropped > 0 {
            self.contexts_expired += contexts_dropped as u64;
            eprintln!(
                "xbits: engine expired {contexts_dropped} context(s) after ttl {:?} (total={})",
                self.ttl, self.contexts_expired
            );
        }
        if !expired.is_empty() {
            self.pending_expired += expired.len() as u64;
            eprintln!(
                "xbits: engine degraded {} pending alert(s): context never arrived within ttl {:?} (emitting fail-closed alerts with degraded=context-missing; total={})",
                expired.len(),
                self.ttl,
                self.pending_expired
            );
        }
        if scores_dropped > 0 {
            self.scores_expired += scores_dropped as u64;
            eprintln!(
                "xbits: engine expired {scores_dropped} score entries after their window (total={})",
                self.scores_expired
            );
        }
        self.enforce_score_cap();

        // 过期 pending → 可见的降级告警（连同原始事件返回；情报标注仍按单一数据源重新查一遍）。
        let mut out = Vec::new();
        for pending in expired {
            let ann = self.annotations(&pending.event, None);
            if let Some(alert) = Self::make_alert_with(
                &pending.event,
                &pending.rule,
                None,
                ann.as_ref(),
                Some("context-missing"),
            ) {
                out.push((pending.event, alert));
            }
        }
        out
    }

    /// 累计分表容量保护：超过上限时淘汰最旧条目（不是整表清空），并计数 `scores_evicted`。
    fn enforce_score_cap(&mut self) {
        let cap = self.max_scores.max(1);
        if self.scores.len() <= cap {
            return;
        }
        let mut by_age: Vec<(String, Instant)> = self
            .scores
            .iter()
            .map(|(key, entry)| (key.clone(), entry.at))
            .collect();
        by_age.sort_by_key(|(_, at)| *at);
        let excess = self.scores.len() - cap;
        let mut evicted = 0u64;
        for (key, _) in by_age.into_iter().take(excess) {
            if self.scores.remove(&key).is_some() {
                evicted += 1;
            }
        }
        if evicted > 0 {
            self.scores_evicted += evicted;
            eprintln!(
                "xbits: engine score table over cap ({cap}); evicted {evicted} oldest entr(ies) to bound memory (total evicted={})",
                self.scores_evicted
            );
        }
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
        Self::make_alert_with(ev, rule, ctx, intel, None)
    }

    /// 构造告警。`degraded=Some(label)` 表示这是"上下文始终没到"的 fail-closed 降级告警：
    /// 允许在没有 ctx 时产出（`require_context` 不再直接返回 None），并且**不套用规则的
    /// `min_confidence`**——降级告警不是"证据不足的检测"，而是"无法判定"的可见事实，
    /// 被门槛吞掉就失去可见性；它始终带 `degraded` 标记，下游可以据此分流。
    fn make_alert_with(
        ev: &HookEvent,
        rule: &Rule,
        ctx: Option<&HookEvent>,
        intel: Option<&EventIntelAnnotations>,
        degraded: Option<&str>,
    ) -> Option<EngineAlert> {
        Self::make_alert_full(ev, rule, ctx, intel, degraded, None)
    }

    /// 带 `correlated` 配对信息的构造（V-14 方案①）：`correlated=Some(request_sid 文本)` 时
    /// confidence 获 [`CORRELATION_CONFIDENCE_BONUS`] 加成（门槛判定**之前**，与情报加分
    /// 同一通道；不会让低于门槛的证据绕过门槛），evidence 追加 `correlated=<sid>`。
    fn make_alert_full(
        ev: &HookEvent,
        rule: &Rule,
        ctx: Option<&HookEvent>,
        intel: Option<&EventIntelAnnotations>,
        degraded: Option<&str>,
        correlated: Option<u64>,
    ) -> Option<EngineAlert> {
        if rule.require_context && ctx.is_none() && degraded.is_none() {
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
        if correlated.is_some() {
            // 关联成立：confidence 加成在门槛判定之前（与情报加分同一通道）。
            confidence = confidence
                .saturating_add(CORRELATION_CONFIDENCE_BONUS)
                .min(100);
        }
        // min_confidence 是真正的过滤门槛：confidence 只由上下文证据 + 情报加分算出（不含门槛抬升），
        // 低于门槛即丢弃。白名单降级在门槛之后执行，保证"白方向只降级、不因门槛丢弃"。
        // 降级告警（degraded）例外：它标记的是"无法判定"，必须可见（见 make_alert_with 文档）。
        if degraded.is_none() {
            if let Some(minimum) = rule.min_confidence {
                if confidence < minimum {
                    return None;
                }
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
        if let Some(label) = degraded {
            evidence = format!(
                "{evidence}; degraded={label}: require_context rule waited out its ttl without context (fail-closed, no suppression key)"
            );
        }
        if let Some(request_sid) = correlated {
            evidence = format!(
                "{evidence}; correlated={request_sid}: response-side success_rule matched on the same community_id (V-14)"
            );
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
            reason: degraded
                .map(str::to_string)
                .unwrap_or_else(|| rule.reason.clone().unwrap_or_else(|| rule.name.clone())),
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
            degraded: degraded.map(str::to_string),
            correlated: correlated.map(|sid| sid.to_string()),
        })
    }

    /// 累计分：规则分 + 情报威胁加分（情报因此真实参与 threshold 判定）。
    ///
    /// 窗口语义（R4-2）：每条累计分带一个窗口，取**最近一次命中规则**的 `score_window_sec`
    /// （未声明则用引擎默认窗口 = 事件 TTL，默认 60s）；窗口从最近一次命中开始滑动，
    /// 窗口内同一 `group_by` 的命中持续累计。`threshold > score` 的规则必须显式声明足够长的
    /// 窗口，否则事件间隔超过窗口时累计分会被清掉、永远不达标（见 README §8.2 与单测）。
    fn score_for(&mut self, ev: &HookEvent, rule: &Rule, intel_bonus: u64) -> u64 {
        let key = self.group_key(ev, rule);
        let now = Instant::now();
        let window = rule
            .score_window_sec
            .map(Duration::from_secs)
            .unwrap_or(self.ttl);
        let entry = self.scores.entry(key).or_insert(ScoreEntry {
            score: 0,
            at: now,
            window,
        });
        entry.score = entry
            .score
            .saturating_add(rule.score.max(1).saturating_add(intel_bonus));
        entry.at = now;
        // R5-3：window 取**单调 max**——同一 group_key 可能被多条规则共享累计分，
        // 短窗口规则不得把长窗口规则已经累积的分提前清掉（长窗口优先）。
        entry.window = entry.window.max(window);
        let accumulated = entry.score;
        // 容量保护：插入后若超上限，淘汰最旧条目（不是整表清空），并计数。
        self.enforce_score_cap();
        accumulated
    }

    /// 处理一条事件，返回 `(原始事件, 告警)` 对（R6-1）。
    ///
    /// 每条告警都与**产生它的那条事件**配对，而不是统一配当前事件：
    /// - 本轮事件命中的规则 → 当前事件；
    /// - 挂起随后被上下文结算的告警 → 该挂起告警自己的事件；
    /// - 过期/溢出降级告警 → 被降级的挂起告警自己的事件。
    /// hook 用这个事件投递给分析流水线，保证事件驱动路径与定时维护路径拿到同一份 payload/sid。
    pub fn process(&mut self, ev: &HookEvent) -> Vec<(HookEvent, EngineAlert)> {
        if ev.kind.eq_ignore_ascii_case("match_context") {
            return Vec::new();
        }
        // prune 会返回"挂起超时"的降级告警（R4-1），与本次事件的告警一起输出。
        // R5-1 的定时维护走 `Engine::maintenance()`（同样返回原始事件 + 告警）。
        let mut out: Vec<(HookEvent, EngineAlert)> = self.prune();

        let is_zeek_context = ev.source.eq_ignore_ascii_case("zeek")
            && ev.kind.eq_ignore_ascii_case("event");
        let key = Self::key_for(ev);
        if is_zeek_context {
            self.merge_context(ev);
        }

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
                        // 用挂起告警自己的事件（而不是触发结算的这条 zeek 上下文事件）。
                        out.push((pending.event, alert));
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

        // V-14 方案①：关联只在"本事件确实产出了告警"之后登记/消费。
        // 先判一次是否有规则达门槛，避免未达门槛的噪声事件污染等待表（R12-3）。
        let correlation_key = Self::correlation_key(ev);
        let emits_alert = self.rules.iter().any(|rule| {
            if !rule.matches(ev) {
                return false;
            }
            // 与 make_alert_full 同口径：benign 与 min_confidence 也会让告警被丢弃，
            // 这些事件不得登记关联等待（R13-2）。
            if Self::benign(rule, context.as_ref()) {
                return false;
            }
            let key = self.group_key(ev, rule);
            let now = Instant::now();
            let accumulated = match self.scores.get(&key) {
                Some(entry) if now.saturating_duration_since(entry.at) <= entry.window => entry.score,
                _ => 0,
            }
            .saturating_add(rule.score.max(1).saturating_add(intel_score_bonus));
            if accumulated < rule.threshold.max(1) {
                return false;
            }
            if let Some(minimum) = rule.min_confidence {
                // 采用最有把握的上界（情报加分 + 可能的关联加分）；上界都达不到门槛
                // 才确定不会产出告警，避免误登记。
                let mut best = Self::confidence(context.as_ref()).saturating_add(intel_score_bonus);
                if ev
                    .sid
                    .and_then(|sid| self.success_rules.requests_for(sid))
                    .is_some()
                {
                    best = best.saturating_add(CORRELATION_CONFIDENCE_BONUS);
                }
                if best.min(100) < minimum {
                    return false;
                }
            }
            !(ev.source.eq_ignore_ascii_case("suricata")
                && rule.require_context
                && context.is_none())
        });
        let mut correlated_sid: Option<u64> = None;
        if emits_alert {
            match ev.sid {
                Some(sid) if self.success_rules.requests_for(sid).is_some() => {
                    correlated_sid = self.consume_correlation(&correlation_key, sid);
                }
                Some(sid) if self.success_rules.is_request_sid(sid) => {
                    self.record_correlation_wait(&correlation_key, &[sid]);
                }
                _ => {}
            }
        }

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
                // 容量上限（R5-2）：不再只计数——把被挤掉的最旧挂起告警按 fail-closed
                // 产出 `degraded=pending-overflow` 的可见告警（与 context-missing 同一条降级通道）。
                let limit = self.max_pending.max(1);
                if self.pending.len() >= limit {
                    let evicted = if self.pending.is_empty() {
                        None
                    } else {
                        Some(self.pending.remove(0))
                    };
                    self.pending_overflow += 1;
                    if self.pending_overflow <= 5 || self.pending_overflow % 1000 == 0 {
                        eprintln!(
                            "xbits: engine pending queue full (limit={limit}); degrading oldest pending alert (degraded=pending-overflow; total={})",
                            self.pending_overflow
                        );
                    }
                    if let Some(evicted) = evicted {
                        let ann = self.annotations(&evicted.event, None);
                        if let Some(alert) = Self::make_alert_with(
                            &evicted.event,
                            &evicted.rule,
                            None,
                            ann.as_ref(),
                            Some("pending-overflow"),
                        ) {
                            // 降级告警同样携带被挤掉告警自己的事件（R6-1）。
                            out.push((evicted.event, alert));
                        }
                    }
                }
                self.pending.push(PendingAlert {
                    rule,
                    event: ev.clone(),
                    key: key.clone(),
                    at: Instant::now(),
                });
                continue;
            }
            if let Some(alert) = Self::make_alert_full(
                ev,
                &rule,
                context.as_ref(),
                annotations.as_ref(),
                None,
                correlated_sid,
            ) {
                out.push((ev.clone(), alert));
            }
        }
        out
    }

    /// 请求侧命中 → 登记关联等待（同 key 已有等待则刷新时间戳；容量超限 FIFO 挤最旧）。
    fn record_correlation_wait(&mut self, key: &str, request_sids: &[u64]) {
        let now = Instant::now();
        if let Some(wait) = self.correlations.get_mut(key) {
            // 同一连接上多次请求命中：刷新时间并补全请求 sid 集合（R12-3：
            // 只留第一个会让后续探测的响应关联丢失且无计数）。
            wait.at = now;
            for sid in request_sids {
                if !wait.request_sids.contains(sid) {
                    wait.request_sids.push(*sid);
                }
            }
            return;
        }
        let request_sids = request_sids.to_vec();
        // 容量保护：FIFO 挤掉最旧（HashMap 无序，改用最旧 at）。
        if self.correlations.len() >= MAX_CORRELATIONS {
            if let Some(oldest_key) = self
                .correlations
                .iter()
                .min_by_key(|(_, w)| w.at)
                .map(|(k, _)| k.clone())
            {
                self.correlations.remove(&oldest_key);
                self.correlation_overflow += 1;
                if self.correlation_overflow <= 5 || self.correlation_overflow % 1000 == 0 {
                    eprintln!(
                        "xbits: engine correlation table full (limit={MAX_CORRELATIONS}); evicted oldest wait (total={})",
                        self.correlation_overflow
                    );
                }
            }
        }
        self.correlations.insert(
            key.to_string(),
            CorrelationWait {
                request_sids,
                at: now,
            },
        );
    }

    /// 响应侧命中 → 若等待表有同 key 且请求侧在 depends 里，消费配对并计数。
    fn consume_correlation(&mut self, key: &str, response_sid: u64) -> Option<u64> {
        let deps = self.success_rules.requests_for(response_sid)?;
        let wait = self.correlations.get(key)?;
        let matched = deps
            .iter()
            .find(|d| wait.request_sids.contains(*d))
            .copied()?;
        self.correlations.remove(key);
        self.correlation_pairs += 1;
        Some(matched)
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

    /// t23/R6-1：多数断言只关心告警本身，这里把 `(原始事件, 告警)` 对折成告警。
    /// 需要验证配对事件的测试直接用 `Engine::process` 返回的对。
    fn collect_alerts(engine: &mut Engine, ev: &HookEvent) -> Vec<EngineAlert> {
        engine
            .process(ev)
            .into_iter()
            .map(|(_, alert)| alert)
            .collect()
    }

    /// 让测试继续用 `eng.process_alerts(ev)` 写法（内部转调 collect_alerts）。
    trait ProcessAlertsExt {
        fn process_alerts(&mut self, ev: &HookEvent) -> Vec<EngineAlert>;
    }
    impl ProcessAlertsExt for Engine {
        fn process_alerts(&mut self, ev: &HookEvent) -> Vec<EngineAlert> {
            collect_alerts(self, ev)
        }
    }

    #[test]
    fn alert_triggers_rule_and_score() {
        let mut eng = Engine::new(vec![rule()]);
        let alerts = eng.process_alerts(&alert_event());
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
        assert!(eng.process_alerts(&ev).is_empty());
    }

    #[test]
    fn context_required_alert_waits_for_zeek_context() {
        let mut r = rule();
        r.require_context = true;
        r.benign_uri_contains = vec!["/healthz".into()];
        let mut eng = Engine::new(vec![r]);
        assert!(eng.process_alerts(&alert_event()).is_empty());
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
        let alerts = eng.process_alerts(&context);
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
        assert!(eng.process_alerts(&alert_event()).is_empty());
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
        assert!(eng.process_alerts(&context).is_empty());
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
        let alerts = eng.process_alerts(&alert_event());
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
        let alerts = eng.process_alerts(&alert_event());
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
        let alerts = eng.process_alerts(&alert_event());
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
        assert!(eng.process_alerts(&alert_event()).is_empty());
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
        let alerts = eng.process_alerts(&context);
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
        assert!(eng.process_alerts(&alert_event()).is_empty());

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
        assert!(eng.process_alerts(&ctx).is_empty(), "zeek 上下文不应触发 suricata 规则");
        let alerts = eng.process_alerts(&alert_event());
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
        assert!(eng.process_alerts(&alert_event()).is_empty());
        assert_eq!(eng.pending_len(), 1);
        assert!(
            eng.process_alerts(&weak_http_context()).is_empty(),
            "75 < 90 必须被门槛过滤"
        );
        assert_eq!(eng.pending_len(), 0);

        // 同样的弱上下文 + 威胁情报 +15 = 90 → 刚好达到门槛，输出。
        let mut r2 = rule();
        r2.min_confidence = Some(90);
        r2.require_context = true;
        let mut eng2 = Engine::new(vec![r2]).with_intel(intel(Some(&dir), None));
        assert!(eng2.process_alerts(&alert_event()).is_empty());
        let alerts = eng2.process_alerts(&weak_http_context());
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].confidence, 75 + INTEL_THREAT_CONFIDENCE_BONUS);
        assert_eq!(alerts[0].intel_decision.as_deref(), Some("threat-hit"));

        // 情报加分不能绕过过滤器：min_confidence=100 时 90 仍被丢弃。
        let mut r3 = rule();
        r3.min_confidence = Some(100);
        r3.require_context = true;
        let mut eng3 = Engine::new(vec![r3]).with_intel(intel(Some(&dir), None));
        assert!(eng3.process_alerts(&alert_event()).is_empty());
        assert!(
            eng3.process_alerts(&weak_http_context()).is_empty(),
            "情报加分不得绕过 min_confidence=100"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- TTL / 容量治理可见性（V-06）----

    #[test]
    fn ttl_prune_reports_expired_state_instead_of_silent_retain() {
        let mut r = rule();
        r.require_context = true;
        let mut eng = Engine::new(vec![r]);

        // 一条挂起告警（require_context 且无上下文）
        assert!(eng.process_alerts(&alert_event()).is_empty());
        assert_eq!(eng.pending_len(), 1);
        assert_eq!(eng.scores_len(), 1);

        // 另一条 5-tuple 的上下文条目
        let ctx = HookEvent {
            source: "zeek".into(),
            kind: "event".into(),
            event: Some("http_request".into()),
            src: Some("198.51.100.7".into()),
            dst: Some("10.0.0.9".into()),
            sport: Some(12345),
            dport: Some(443),
            ..Default::default()
        };
        assert!(eng.process_alerts(&ctx).is_empty());
        assert_eq!(eng.contexts_len(), 1);

        // 未过期：什么都不清
        assert!(eng.prune().is_empty());
        assert_eq!(eng.pending_len(), 1);
        assert_eq!(eng.contexts_len(), 1);
        assert_eq!(eng.scores_len(), 1);

        // 时间推进过 TTL：三类状态都被清理，且过期 pending 产出可见的降级告警（R4-1）
        let future = Instant::now() + eng.ttl + Duration::from_millis(1);
        let degraded = eng.prune_at(future);
        assert_eq!(eng.pending_len(), 0);
        assert_eq!(eng.pending_expired(), 1);
        assert_eq!(eng.contexts_len(), 0);
        assert_eq!(eng.contexts_expired(), 1);
        assert_eq!(eng.scores_len(), 0);
        assert!(eng.scores_expired() >= 1);
        assert_eq!(degraded.len(), 1, "过期 pending 必须产出可见的降级告警");
        assert_eq!(
            degraded[0].1.degraded.as_deref(),
            Some("context-missing")
        );
        assert_eq!(degraded[0].1.reason, "context-missing");
        assert!(
            degraded[0].1.evidence.contains("context-missing"),
            "evidence 必须写明 context-missing: {}",
            degraded[0].1.evidence
        );
        // 原始事件随降级告警一起返回（hook 据此投递给分析流水线）
        assert_eq!(degraded[0].0.sid, Some(9103001));
    }

    #[test]
    fn engine_pending_overflow_emits_degraded_alert() {
        // R5-2：溢出不是"只计数"——被挤掉的最旧挂起告警必须产出 degraded=pending-overflow。
        let mut r = rule();
        r.require_context = true;
        let mut eng = Engine::new(vec![r]);
        eng.max_pending = 2;
        let mut degraded = Vec::new();
        for _ in 0..4 {
            for alert in eng.process_alerts(&alert_event()) {
                degraded.push(alert);
            }
        }
        assert_eq!(eng.pending_len(), 2, "引擎 pending 必须有界");
        assert_eq!(eng.pending_overflow(), 2, "挤掉的最旧 pending 必须计数");
        assert_eq!(degraded.len(), 2, "溢出必须产出可见降级告警");
        assert!(degraded
            .iter()
            .all(|a| a.degraded.as_deref() == Some("pending-overflow")));
        assert!(
            degraded[0].evidence.contains("pending-overflow"),
            "evidence 必须写明 pending-overflow: {}",
            degraded[0].evidence
        );
    }

    #[test]
    fn engine_score_table_evicts_oldest_when_over_cap() {
        let mut eng = Engine::new(vec![rule()]);
        eng.max_scores = 2;
        for i in 0..4u64 {
            let mut ev = alert_event();
            ev.community_id = Some(format!("cid-{i}"));
            let _ = eng.process_alerts(&ev);
        }
        assert_eq!(eng.scores_len(), 2, "超上限只淘汰最旧条目，表必须有界");
        assert!(eng.scores_evicted() >= 1, "淘汰必须计数（不得静默丢弃）");
    }

    fn slow_rule(window_sec: Option<u64>) -> Rule {
        let json = match window_sec {
            Some(w) => format!(
                r#"{{"id":"r-slow","name":"slow","source":"suricata","kind":"alert","signature_contains":"SQL","score":20,"threshold":100,"reason":"slow","score_window_sec":{w}}}"#
            ),
            None => r#"{"id":"r-slow","name":"slow","source":"suricata","kind":"alert","signature_contains":"SQL","score":20,"threshold":100,"reason":"slow"}"#.to_string(),
        };
        serde_json::from_str::<Rule>(&json).expect("slow rule")
    }

    #[test]
    fn slow_accumulating_rule_needs_explicit_score_window() {
        // 默认窗口（60s）：每次命中后跨 90s，累计分被窗口清掉 —— 明确断言"永不达标"，
        // 而不是靠 60s 巧合（R4-2）。
        let mut eng = Engine::new(vec![slow_rule(None)]);
        let mut fired = 0;
        for _ in 0..5 {
            fired += eng.process_alerts(&alert_event()).len();
            eng.prune_at(Instant::now() + Duration::from_secs(90));
        }
        assert_eq!(fired, 0, "默认 60s 窗口下跨窗口的慢速累积不得靠巧合达标");
        assert!(eng.scores_expired() >= 5, "每次过期都必须计数");

        // 规则显式声明 1h 窗口：同样的跨 90s 命中能累计到 threshold=100 并输出。
        let mut eng = Engine::new(vec![slow_rule(Some(3600))]);
        let mut fired = 0;
        for _ in 0..5 {
            fired += eng.process_alerts(&alert_event()).len();
            eng.prune_at(Instant::now() + Duration::from_secs(90));
        }
        assert_eq!(fired, 1, "显式窗口内第 5 次命中必须达标并输出");
        assert_eq!(eng.scores_expired(), 0, "窗口内不得发生过期");
    }

    #[test]
    fn expired_pending_emits_degraded_alert_even_below_min_confidence() {
        // 降级告警是"无法判定"的可见事实，不能被规则门槛吞掉（普通告警仍受门槛约束）。
        let mut r = rule();
        r.require_context = true;
        r.min_confidence = Some(99);
        let mut eng = Engine::new(vec![r]);
        assert!(eng.process_alerts(&alert_event()).is_empty());
        let alerts = eng.prune_at(Instant::now() + eng.ttl + Duration::from_millis(1));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].1.degraded.as_deref(), Some("context-missing"));
        assert_eq!(alerts[0].1.reason, "context-missing");
        // 普通路径（有上下文但证据不足）仍被 min_confidence 过滤 —— 见 min_confidence_* 测试。
    }

    #[test]
    fn score_window_is_monotonic_max_across_rules_sharing_a_key() {
        // R5-3：同一 group_key 先被短窗口规则命中、后被长窗口规则命中时，
        // 窗口必须取 max（长窗口），不能被短窗口改写导致长窗口累积提前过期。
        let mut short = slow_rule(Some(60));
        short.id = "r-short".into();
        short.threshold = 20; // 短规则单事件就输出，不影响窗口断言
        let mut long = slow_rule(Some(3600));
        long.id = "r-long".into();
        long.threshold = 20;
        let mut eng = Engine::new(vec![long, short]);
        // 两条规则都命中同一 community_id → 同一个累计分条目；规则顺序 = long 先、short 后，
        // 若 window 用"后写覆盖"，长窗口会被 short 的 60s 改写并在 120s 处提前过期。
        let mut ev = alert_event();
        ev.community_id = Some("shared-key".into());
        let _ = eng.process_alerts(&ev);
        assert_eq!(eng.scores_len(), 1);
        // 时间推进超过短窗口（60s）但仍远小于长窗口（3600s）：条目必须存活
        eng.prune_at(Instant::now() + Duration::from_secs(120));
        assert_eq!(eng.scores_expired(), 0, "长窗口累积不得被短窗口提前清掉");
        assert_eq!(eng.scores_len(), 1);
    }

    #[test]
    fn maintenance_runs_without_new_events_and_returns_degraded_alerts() {
        // R5-1：维护接口与"事件到达"解耦——不调用 process() 也能触发过期判定与降级输出。
        let mut r = rule();
        r.require_context = true;
        let mut eng = Engine::new(vec![r]);
        eng.ttl = Duration::from_millis(0);
        assert!(eng.process_alerts(&alert_event()).is_empty());
        assert_eq!(eng.pending_len(), 1);
        std::thread::sleep(Duration::from_millis(2));
        let degraded = eng.maintenance();
        assert_eq!(degraded.len(), 1, "无新事件也必须按时触发过期降级");
        assert_eq!(degraded[0].1.degraded.as_deref(), Some("context-missing"));
        assert_eq!(eng.pending_len(), 0);
        assert!(eng.pending_expired() >= 1);
    }

    #[test]
    fn event_driven_degraded_alert_carries_its_own_event() {
        // R6-1：事件驱动路径上 prune 产出的 context-missing 降级告警必须配对它**自己的原事件**，
        // 而不是触发本次 prune 的那条事件（否则 analysis.decide 会拿到别的事件的 payload/sid）。
        let mut r = rule();
        r.require_context = true;
        let mut eng = Engine::new(vec![r]);
        eng.ttl = Duration::from_millis(0);
        let mut first = alert_event();
        first.payload = Some("first-payload".into());
        assert!(eng.process(&first).is_empty());
        std::thread::sleep(Duration::from_millis(2));

        let mut later = alert_event();
        later.sid = Some(9999001);
        later.payload = Some("later-payload".into());
        later.community_id = Some("later-cid".into());
        let pairs = eng.process(&later);
        assert_eq!(pairs.len(), 1, "本次事件只应输出过期降级告警");
        let (event, alert) = &pairs[0];
        assert_eq!(
            event.sid,
            Some(9103001),
            "降级告警必须配对它自己的 sid（不是后续事件的 sid）"
        );
        assert_eq!(
            event.payload.as_deref(),
            Some("first-payload"),
            "payload 也必须是降级告警自己的"
        );
        assert_ne!(event.sid, later.sid);
        assert_eq!(alert.degraded.as_deref(), Some("context-missing"));
    }

    // ---- V-14 方案①：success_rules 请求→响应关联 ----

    fn success_json() -> &'static str {
        // 响应侧 14030020 的 depends 是请求侧 14030019（与生产 success_rules.json 同构）。
        r#"[{"sid":14030020,"depends":[14030019],"msg":"OS Command(touch) Injection Risk Detected on Target Website","source":"etc_fw/pvs/rules/cmd.rules"}]"#
    }

    fn corr_event(sid: u64, cid: &str) -> HookEvent {
        HookEvent {
            source: "suricata".into(),
            kind: "alert".into(),
            signature: Some("[PVS] correlation probe".into()),
            src: Some("203.0.113.9".into()),
            dst: Some("10.0.0.80".into()),
            sport: Some(40001),
            dport: Some(80),
            proto: Some("TCP".into()),
            sid: Some(sid),
            community_id: Some(cid.into()),
            ..Default::default()
        }
    }

    fn correlation_rule_for(sid: u64) -> Rule {
        serde_json::from_str::<Rule>(&format!(
            r#"{{"id":"r-corr-{sid}","name":"corr-{sid}","source":"suricata","kind":"alert","sid_in":[{sid}],"score":20,"threshold":20,"reason":"corr-{sid}"}}"#
        ))
        .expect("correlation rule")
    }

    #[test]
    fn success_rules_parse_and_request_sid_detection() {
        let rules = SuccessRules::parse(success_json()).expect("parse");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules.requests_for(14030020), Some(&[14030019][..]));
        assert!(rules.is_request_sid(14030019));
        assert!(!rules.is_request_sid(14030020));
        assert!(rules.requests_for(9999999).is_none());
        // 坏 JSON 必须显式报错（不静默空表）
        assert!(SuccessRules::parse("{ this is not json").is_err());
    }

    #[test]
    fn correlation_pairs_when_response_matches_request_on_same_cid() {
        let rules = SuccessRules::parse(success_json()).unwrap();
        let mut eng = Engine::new(vec![
            correlation_rule_for(14030019),
            correlation_rule_for(14030020),
        ])
        .with_success_rules(rules);

        // 请求侧命中：告警正常输出，同时登记等待（不 correlated）。
        let alerts = eng.process_alerts(&corr_event(14030019, "1:cidA="));
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].correlated.is_none());
        assert_eq!(eng.correlations_len(), 1, "请求侧命中必须登记等待条目");
        assert_eq!(eng.correlation_pairs(), 0);

        // 响应侧同 cid 命中：配对成立 → correlated=<请求侧 sid> + confidence 加成。
        let alerts = eng.process_alerts(&corr_event(14030020, "1:cidA="));
        assert_eq!(alerts.len(), 1);
        assert_eq!(
            alerts[0].correlated.as_deref(),
            Some("14030019"),
            "响应侧告警必须携带配对到的请求侧 SID"
        );
        assert!(
            alerts[0].evidence.contains("correlated=14030019"),
            "evidence 必须写明关联: {}",
            alerts[0].evidence
        );
        assert_eq!(eng.correlation_pairs(), 1);
        assert_eq!(eng.correlations_len(), 0, "配对后等待条目必须被消费");

        // 对照组：无关联表的引擎产出相同规则告警 → correlated 为 None、confidence 少 15。
        let mut plain = Engine::new(vec![
            correlation_rule_for(14030019),
            correlation_rule_for(14030020),
        ]);
        let _ = plain.process_alerts(&corr_event(14030019, "1:cidA="));
        let baseline = plain.process_alerts(&corr_event(14030020, "1:cidA="));
        assert!(baseline[0].correlated.is_none());
        assert_eq!(
            baseline[0].confidence + CORRELATION_CONFIDENCE_BONUS,
            alerts[0].confidence
        );
    }

    #[test]
    fn correlation_requires_same_cid() {
        let rules = SuccessRules::parse(success_json()).unwrap();
        let mut eng = Engine::new(vec![
            correlation_rule_for(14030019),
            correlation_rule_for(14030020),
        ])
        .with_success_rules(rules);
        let _ = eng.process_alerts(&corr_event(14030019, "1:cidA="));
        // 不同 cid 的响应侧命中：不配对（等待条目仍保留，等它自己的响应）。
        let alerts = eng.process_alerts(&corr_event(14030020, "1:cidB="));
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].correlated.is_none());
        assert_eq!(eng.correlation_pairs(), 0);
        assert_eq!(eng.correlations_len(), 1);
    }

    #[test]
    fn correlation_wait_not_registered_for_benign_or_below_min_confidence() {
        let rules = SuccessRules::parse(success_json()).unwrap();
        let mut benign_rule = correlation_rule_for(14030019);
        benign_rule.benign_uri_contains = vec!["/healthz".into()];
        let mut eng = Engine::new(vec![benign_rule]).with_success_rules(rules);

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
        let _ = eng.process_alerts(&context);
        let request = corr_event(14030019, "1:cidBenign=");
        let alerts = eng.process_alerts(&request);
        assert!(alerts.is_empty(), "benign 上下文必须丢弃告警");
        assert_eq!(
            eng.correlations_len(),
            0,
            "被 benign 过滤的事件不得登记关联等待（R13-2）"
        );

        let mut strict_rule = correlation_rule_for(14030019);
        strict_rule.min_confidence = Some(101);
        let mut eng2 = Engine::new(vec![strict_rule])
            .with_success_rules(SuccessRules::parse(success_json()).unwrap());
        assert!(eng2.process_alerts(&corr_event(14030019, "1:cidMin=")).is_empty());
        assert_eq!(
            eng2.correlations_len(),
            0,
            "低于 min_confidence 的事件不得登记关联等待（R13-2）"
        );
    }

    #[test]
    fn correlation_times_out_when_response_never_arrives() {
        let rules = SuccessRules::parse(success_json()).unwrap();
        let mut eng = Engine::new(vec![correlation_rule_for(14030019)])
            .with_success_rules(rules);
        let _ = eng.process_alerts(&corr_event(14030019, "1:cidT="));
        assert_eq!(eng.correlations_len(), 1);

        // 时间推进过关联 TTL：等待条目被清理并计数（请求侧告警此前已正常判定，
        // 超时不产出降级告警——关联是增强信号，不是判定本体）。
        let future = Instant::now() + CORRELATION_TTL + Duration::from_millis(1);
        let degraded = eng.prune_at(future);
        assert!(degraded.is_empty(), "关联超时不应产出降级告警");
        assert_eq!(eng.correlations_len(), 0);
        assert_eq!(eng.correlation_timeouts(), 1);
    }

    #[test]
    fn correlation_table_is_bounded_and_counted() {
        let rules = SuccessRules::parse(success_json()).unwrap();
        let mut eng = Engine::new(vec![correlation_rule_for(14030019)])
            .with_success_rules(rules);
        // MAX_CORRELATIONS 是常量；这里通过灌入超过容量的不同 cid 请求侧命中触发淘汰。
        for i in 0..(MAX_CORRELATIONS + 8) {
            let mut ev = corr_event(14030019, &format!("1:cid{i}="));
            ev.community_id = Some(format!("1:cid{i}="));
            let _ = eng.process_alerts(&ev);
        }
        assert!(
            eng.correlations_len() <= MAX_CORRELATIONS,
            "关联等待表必须有界: {}",
            eng.correlations_len()
        );
        assert!(eng.correlation_overflow() >= 1, "淘汰必须计数（不得静默丢弃）");
    }
}
