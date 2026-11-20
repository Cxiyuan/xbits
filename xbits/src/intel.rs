//! xbits 统一情报查询服务：威胁情报（threat-intel/）+ 白名单（allowlist/）。
//!
//! 两个子模块都在项目根目录，数据快照格式一致（一行一条，`#` 注释）：
//! - threat-intel/data/{ip,domain,md5,sha1,sha256}.txt —— 黑方向，**参与评分**；
//! - allowlist/data/{domain,ip,public_dns}.txt        —— 白方向，**参与降级**。
//!
//! 语义（决策增量见 `engine.rs` 的 `INTEL_*` 常量）：
//! - 威胁 IP / 域名 / 文件哈希（md5、sha1、sha256 按算法分派）命中 →
//!   `score += INTEL_THREAT_SCORE_BONUS`（参与 threshold 累计）、
//!   `confidence += INTEL_THREAT_CONFIDENCE_BONUS`（在 min_confidence 门槛判定前计入：可帮助达到门槛，
//!   但不会让证据不足的告警绕过门槛；confidence 本身不会被门槛抬高），
//!   告警写 `intel_decision=threat-hit`；
//!   威胁域名是**精确匹配**（与 `threat-intel/tools/query.py` 的集合语义一致）。
//! - 白名单 IP / 域名（域名按**最长后缀**匹配）命中且无威胁命中 →
//!   `confidence -= INTEL_ALLOWLIST_CONFIDENCE_PENALTY`（只降级、不在这里丢弃），
//!   告警写 `intel_decision=allowlist-downgraded`，分析层据此把 reason 记为 `intel-allowlist`；
//!   威胁与白名单同时命中时以威胁为准，写 `intel_decision=threat-overrides-allowlist`。
//! - 上述标注同时进入归一化文档（`analysis.rs` 的 `normalized_document` / `file_triage_document`）。
//!
//! 加载侧不做"看不见的降级"：每个数据集的条目数与读取失败原因都会记录在 `SetLoad` 里，
//! 由 `state()` 区分「未配置 / 读取失败 / 配置了但为空 / 已加载」，并可用 `report()` 逐项打印。

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::model::HookEvent;

/// 域名类数据里禁止出现的公共后缀。
///
/// 完整 PSL 不在本文件范围内：这里只拦住"拿公共后缀当黑/白名单"这类灾难性误用，
/// 例如 `threat-intel/data/domain.txt` 里曾出现的 `co.kr`——后缀语义会命中所有 `*.co.kr`。
const PUBLIC_SUFFIXES: &[&str] = &[
    "com", "net", "org", "info", "biz", "cn", "com.cn", "net.cn", "org.cn", "co.kr", "or.kr",
    "ne.kr", "co.jp", "ne.jp", "or.jp", "co.uk", "org.uk", "ac.uk", "com.tw", "com.hk", "com.sg",
    "com.my", "com.br", "net.br", "org.br", "com.au", "net.au", "co.nz", "co.in", "co.za",
    "com.tr", "com.ru", "com.mx", "com.ar", "com.co", "com.vn", "co.th", "com.id", "com.ph",
    "com.pk", "com.eg", "com.sa",
];

/// 单标签条目与公共后缀不适合作为精确/后缀名单条目（加载期拒绝并记录）。
fn is_public_suffix(domain: &str) -> bool {
    !domain.contains('.') || PUBLIC_SUFFIXES.contains(&domain)
}

/// 文件哈希算法：md5/sha1/sha256 各查各的集合，不做"长度像就算"的猜测。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgo {
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlgo::Md5 => "md5",
            HashAlgo::Sha1 => "sha1",
            HashAlgo::Sha256 => "sha256",
        }
    }

    /// 按十六进制长度判定算法；非法长度返回 None（调用方不查询）。
    pub fn from_hex_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(HashAlgo::Md5),
            40 => Some(HashAlgo::Sha1),
            64 => Some(HashAlgo::Sha256),
            _ => None,
        }
    }
}

/// 单个数据集的加载结果（条目数 + 读取失败原因 + 被拒绝的公共后缀条目）。
#[derive(Debug, Clone)]
pub struct SetLoad {
    /// 逻辑名，例如 `threat/ip.txt` / `allowlist/public_dns.txt`。
    pub name: &'static str,
    pub entries: usize,
    /// 读取失败原因；None 表示文件读取成功（内容可能为空）。
    pub error: Option<String>,
    /// 因是公共后缀/单标签而被拒绝的条目数。
    pub rejected_public_suffixes: usize,
    /// 被拒绝条目的样本（最多 5 条，便于排查）。
    pub rejected_sample: Vec<String>,
}

/// 情报服务状态：让"未配置 / 配置了但读不到 / 配置了但为空 / 已加载"可区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntelState {
    /// 两个目录都未指定：情报功能未启用（不是"加载为空"）。
    NotConfigured,
    /// 已指定目录，但至少一个数据集读取失败（路径错/权限/IO）：配置有问题。
    Misconfigured,
    /// 目录可读但所有集合都没有条目。
    Empty,
    /// 至少一个集合有条目。
    Loaded,
}

impl IntelState {
    pub fn as_str(self) -> &'static str {
        match self {
            IntelState::NotConfigured => "unconfigured",
            IntelState::Misconfigured => "misconfigured",
            IntelState::Empty => "empty",
            IntelState::Loaded => "loaded",
        }
    }
}

#[derive(Debug, Default)]
pub struct ThreatIntel {
    ips: HashSet<String>,
    /// 恶意域名：**精确匹配**（与 `threat-intel/tools/query.py` 的集合语义一致）。
    domains: HashSet<String>,
    md5: HashSet<String>,
    sha1: HashSet<String>,
    sha256: HashSet<String>,
}

#[derive(Debug, Default)]
pub struct Allowlist {
    /// 域名后缀名单：按长度降序排列，首个命中即**最长后缀**。
    domains: Vec<String>,
    ips: HashSet<String>,
    public_dns: HashSet<String>,
}

/// 情报查询服务：轻量内存集合，启动时一次性加载（数据由子模块工具刷新，
/// xbits 重启/重载后生效）。
#[derive(Debug, Default)]
pub struct IntelService {
    threat: ThreatIntel,
    allowlist: Allowlist,
    stats: Vec<SetLoad>,
    threat_dir: Option<PathBuf>,
    allowlist_dir: Option<PathBuf>,
}

/// 从单列文本文件加载小写化集合；返回 `(集合, 失败原因)`。
///
/// 读取失败不再静默成"空集合"：失败原因会进 `SetLoad.error`，由启动日志逐项打印。
fn load_set(path: &Path) -> (HashSet<String>, Option<String>) {
    let mut out = HashSet::new();
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => return (out, Some(err.to_string())),
    };
    for line in text.lines() {
        let v = line.split('#').next().unwrap_or("").trim().to_ascii_lowercase();
        if !v.is_empty() {
            out.insert(v);
        }
    }
    (out, None)
}

/// 加载一个数据集，并把条目数/失败原因/被拒绝条目记入 `stats`。
fn load_dataset(
    dir: &Path,
    file: &str,
    label: &'static str,
    reject_public_suffix: bool,
    stats: &mut Vec<SetLoad>,
) -> HashSet<String> {
    let path = dir.join(format!("{file}.txt"));
    let (mut set, error) = load_set(&path);
    let mut rejected_public_suffixes = 0usize;
    let mut rejected_sample = Vec::new();
    if reject_public_suffix {
        set.retain(|value| {
            if is_public_suffix(value) {
                rejected_public_suffixes += 1;
                if rejected_sample.len() < 5 {
                    rejected_sample.push(value.clone());
                }
                false
            } else {
                true
            }
        });
    }
    stats.push(SetLoad {
        name: label,
        entries: set.len(),
        error,
        rejected_public_suffixes,
        rejected_sample,
    });
    set
}

/// 白名单域名：加载为按长度降序的后缀列表（最长后缀优先命中）。
fn load_suffix_list(
    dir: &Path,
    file: &str,
    label: &'static str,
    stats: &mut Vec<SetLoad>,
) -> Vec<String> {
    let mut set = load_dataset(dir, file, label, true, stats);
    let mut v: Vec<String> = set.drain().collect();
    v.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    v
}

/// `value` 是否以 `suffix` 为**整段**后缀（避免 `notbaidu.com` 命中 `baidu.com`）。
fn domain_suffix_match(value: &str, suffix: &str) -> bool {
    value.len() > suffix.len()
        && value.ends_with(suffix)
        && value.as_bytes()[value.len() - suffix.len() - 1] == b'.'
}

/// 后缀名单查询：返回命中的最长后缀（列表已按长度降序，首个命中即最长）。
fn longest_suffix_hit(suffixes: &[String], value: &str) -> Option<String> {
    let v = value.trim().to_ascii_lowercase();
    if v.is_empty() {
        return None;
    }
    for w in suffixes {
        if v == *w || domain_suffix_match(&v, w) {
            return Some(w.clone());
        }
    }
    None
}

fn push_unique(list: &mut Vec<Value>, item: Value) {
    if !list.iter().any(|existing| existing == &item) {
        list.push(item);
    }
}

impl IntelService {
    /// 从两个数据目录构建。目录缺失/文件读取失败都会记录到 `stats`（不静默），
    /// 由 [`IntelService::state`] 与 [`IntelService::report`] 对外呈现。
    pub fn load(threat_dir: Option<&PathBuf>, allowlist_dir: Option<&PathBuf>) -> Self {
        let mut stats: Vec<SetLoad> = Vec::new();
        let mut threat = ThreatIntel::default();
        let mut allowlist = Allowlist::default();

        if let Some(dir) = threat_dir {
            threat.ips = load_dataset(dir, "ip", "threat/ip.txt", false, &mut stats);
            threat.domains = load_dataset(dir, "domain", "threat/domain.txt", true, &mut stats);
            threat.md5 = load_dataset(dir, "md5", "threat/md5.txt", false, &mut stats);
            threat.sha1 = load_dataset(dir, "sha1", "threat/sha1.txt", false, &mut stats);
            threat.sha256 = load_dataset(dir, "sha256", "threat/sha256.txt", false, &mut stats);
        }
        if let Some(dir) = allowlist_dir {
            allowlist.domains = load_suffix_list(dir, "domain", "allowlist/domain.txt", &mut stats);
            allowlist.ips = load_dataset(dir, "ip", "allowlist/ip.txt", false, &mut stats);
            allowlist.public_dns =
                load_dataset(dir, "public_dns", "allowlist/public_dns.txt", false, &mut stats);
        }

        Self {
            threat,
            allowlist,
            stats,
            threat_dir: threat_dir.cloned(),
            allowlist_dir: allowlist_dir.cloned(),
        }
    }

    /// 未配置 / 读取失败 / 空 / 已加载 四态（配置错不再伪装成"加载为空"）。
    pub fn state(&self) -> IntelState {
        if self.threat_dir.is_none() && self.allowlist_dir.is_none() {
            return IntelState::NotConfigured;
        }
        if self.stats.iter().any(|s| s.error.is_some()) {
            return IntelState::Misconfigured;
        }
        if self.total_entries() == 0 {
            IntelState::Empty
        } else {
            IntelState::Loaded
        }
    }

    /// 启动时逐项打印用的报告行（状态 + 每个数据集的条目数/失败原因）。
    pub fn report(&self) -> Vec<String> {
        let mut lines = vec![format!("intel={}", self.state().as_str())];
        if self.threat_dir.is_none() {
            lines.push(
                "threat: 未配置（--threat-intel-dir 未指定，威胁情报不参与评分）".to_string(),
            );
        }
        if self.allowlist_dir.is_none() {
            lines.push(
                "allowlist: 未配置（--allowlist-dir 未指定，白名单不参与降级）".to_string(),
            );
        }
        for stat in &self.stats {
            let mut line = match &stat.error {
                Some(err) => format!("{}: 读取失败: {err}", stat.name),
                None => format!("{}: {} 条", stat.name, stat.entries),
            };
            if stat.rejected_public_suffixes > 0 {
                line.push_str(&format!(
                    "（拒绝公共后缀条目 {} 条: {}）",
                    stat.rejected_public_suffixes,
                    stat.rejected_sample.join(", ")
                ));
            }
            lines.push(line);
        }
        lines
    }

    /// 所有集合是否都为空（覆盖 threat ip/domain/md5/sha1/sha256 与 allowlist domain/ip/public_dns）。
    pub fn is_empty(&self) -> bool {
        self.threat.ips.is_empty()
            && self.threat.domains.is_empty()
            && self.threat.md5.is_empty()
            && self.threat.sha1.is_empty()
            && self.threat.sha256.is_empty()
            && self.allowlist.domains.is_empty()
            && self.allowlist.ips.is_empty()
            && self.allowlist.public_dns.is_empty()
    }

    pub fn total_entries(&self) -> usize {
        self.stats.iter().map(|s| s.entries).sum()
    }

    // ---- 威胁情报（黑）----
    pub fn threat_ip(&self, ip: &str) -> bool {
        self.threat.ips.contains(&ip.trim().to_ascii_lowercase())
    }

    /// 威胁域名：精确匹配（与 `threat-intel/tools/query.py` 的集合语义一致，不做后缀推断）。
    pub fn threat_domain(&self, domain: &str) -> bool {
        self.threat.domains.contains(&domain.trim().to_ascii_lowercase())
    }

    /// 威胁文件哈希：按算法分派到 md5/sha1/sha256 各自的集合。
    pub fn threat_hash(&self, algo: HashAlgo, value: &str) -> bool {
        let v = value.trim().to_ascii_lowercase();
        match algo {
            HashAlgo::Md5 => self.threat.md5.contains(&v),
            HashAlgo::Sha1 => self.threat.sha1.contains(&v),
            HashAlgo::Sha256 => self.threat.sha256.contains(&v),
        }
    }

    // ---- 白名单（白）----
    /// 白名单域名：仅此处做后缀匹配，返回命中的**最长**后缀。
    pub fn allowlisted_domain(&self, domain: &str) -> Option<String> {
        longest_suffix_hit(&self.allowlist.domains, domain)
    }

    pub fn allowlisted_ip(&self, ip: &str) -> bool {
        self.allowlist.ips.contains(&ip.trim().to_ascii_lowercase())
    }

    pub fn is_public_dns(&self, ip: &str) -> bool {
        self.allowlist.public_dns.contains(&ip.trim().to_ascii_lowercase())
    }

    /// 单个事件的情报标注（兼容入口，等价于 `annotate_events(&[ev])`）。
    pub fn annotate_event(&self, ev: &HookEvent) -> EventIntelAnnotations {
        self.annotate_events(&[ev])
    }

    /// 多个事件的情报标注（告警事件 + 合并后的上下文一起查询，覆盖 IP/域名/文件哈希）。
    pub fn annotate_events(&self, events: &[&HookEvent]) -> EventIntelAnnotations {
        let mut threat_hits: Vec<Value> = Vec::new();
        let mut allow_hits: Vec<Value> = Vec::new();
        let mut public_dns_off_baseline = false;

        for ev in events {
            for ip in [ev.src.as_deref(), ev.dst.as_deref()].into_iter().flatten() {
                let ip = ip.trim();
                if ip.is_empty() {
                    continue;
                }
                if self.threat_ip(ip) {
                    push_unique(&mut threat_hits, json!({"type": "ip", "value": ip}));
                }
                if self.allowlisted_ip(ip) {
                    push_unique(&mut allow_hits, json!({"type": "ip", "value": ip}));
                }
            }
            // 域名类字段：dns_query / sni（Suricata dns、tls）与 host（HTTP Host）
            for domain in [
                ev.dns_query.as_deref(),
                ev.sni.as_deref(),
                ev.host.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                let domain = domain.trim();
                if domain.is_empty() {
                    continue;
                }
                if self.threat_domain(domain) {
                    push_unique(&mut threat_hits, json!({"type": "domain", "value": domain}));
                }
                if let Some(list) = self.allowlisted_domain(domain) {
                    push_unique(
                        &mut allow_hits,
                        json!({"type": "domain", "value": domain, "list": list}),
                    );
                }
            }
            // 文件 hash（fileinfo / triage 事件）：md5、sha1、sha256 各查各的集合
            for (algo, value) in [
                (HashAlgo::Md5, ev.file_md5.as_deref()),
                (HashAlgo::Sha1, ev.file_sha1.as_deref()),
                (HashAlgo::Sha256, ev.file_sha256.as_deref()),
            ] {
                if let Some(value) = value {
                    if self.threat_hash(algo, value) {
                        push_unique(&mut threat_hits, json!({"type": algo.as_str(), "value": value}));
                    }
                }
            }
            // DNS 行为基线：目标是对端但不在公共 DNS 基线与白名单内（仅提示，不参与加权）
            if ev.dns_query.is_some() {
                if let Some(dst) = ev.dst.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
                    if !self.is_public_dns(dst) && !self.allowlisted_ip(dst) {
                        public_dns_off_baseline = true;
                    }
                }
            }
        }

        EventIntelAnnotations {
            threat: (!threat_hits.is_empty()).then(|| json!(threat_hits)),
            allowlist: (!allow_hits.is_empty()).then(|| json!(allow_hits)),
            public_dns_off_baseline,
        }
    }
}

/// 事件情报标注结果：进入引擎决策点（评分/降级），并写入告警与归一化文档。
#[derive(Debug, Default, Clone)]
pub struct EventIntelAnnotations {
    pub threat: Option<Value>,
    pub allowlist: Option<Value>,
    pub public_dns_off_baseline: bool,
}

impl EventIntelAnnotations {
    pub fn is_empty(&self) -> bool {
        self.threat.is_none() && self.allowlist.is_none() && !self.public_dns_off_baseline
    }

    pub fn threat_hit(&self) -> bool {
        self.threat.is_some()
    }

    pub fn allowlist_hit(&self) -> bool {
        self.allowlist.is_some()
    }

    /// 决策标签（引擎告警与文件 triage 文档共用）：
    /// - `threat-hit`：威胁命中，score/confidence 已加权；
    /// - `threat-overrides-allowlist`：威胁与白名单同时命中，以威胁为准；
    /// - `allowlist-downgraded`：仅白名单命中，confidence 已扣减。
    pub fn decision(&self) -> Option<&'static str> {
        if self.threat_hit() {
            if self.allowlist_hit() {
                Some("threat-overrides-allowlist")
            } else {
                Some("threat-hit")
            }
        } else if self.allowlist_hit() {
            Some("allowlist-downgraded")
        } else {
            None
        }
    }

    /// `allowlist` 字段的文档形状（告警与文件 triage 共用）：
    /// `{"hits": [...], "public_dns_off_baseline": true}`。
    pub fn allowlist_document(&self) -> Option<Value> {
        if self.allowlist.is_none() && !self.public_dns_off_baseline {
            return None;
        }
        let mut obj = serde_json::Map::new();
        if let Some(v) = self.allowlist.clone() {
            obj.insert("hits".into(), v);
        }
        if self.public_dns_off_baseline {
            obj.insert("public_dns_off_baseline".into(), json!(true));
        }
        Some(Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("xbits-intel-{}-{nanos}", prefix));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, text: &str) {
        fs::write(path, text).unwrap();
    }

    #[test]
    fn loads_and_queries_threat_and_allowlist() {
        let threat = tmpdir("threat");
        let allow = tmpdir("allow");
        write(&threat.join("ip.txt"), "203.0.113.9\n198.51.100.7 # c2\n");
        write(&threat.join("domain.txt"), "evil.example\n");
        write(&threat.join("md5.txt"), "aa".repeat(16).as_str());
        write(&threat.join("sha1.txt"), "bb".repeat(20).as_str());
        write(&threat.join("sha256.txt"), "cc".repeat(32).as_str());
        write(&allow.join("domain.txt"), "baidu.com\n");
        write(&allow.join("ip.txt"), "10.0.0.1\n");
        write(&allow.join("public_dns.txt"), "8.8.8.8\n");

        let svc = IntelService::load(Some(&threat), Some(&allow));
        assert_eq!(svc.state(), IntelState::Loaded);
        assert!(svc.threat_ip("203.0.113.9"));
        assert!(svc.threat_ip("198.51.100.7"));
        assert!(!svc.threat_ip("8.8.8.8"));
        assert!(svc.threat_domain("evil.example"));
        // 威胁域名精确匹配：子域名不命中（与 threat-intel/tools/query.py 一致）
        assert!(!svc.threat_domain("a.evil.example"));
        // 哈希按算法分派
        assert!(svc.threat_hash(HashAlgo::Md5, &"aa".repeat(16)));
        assert!(svc.threat_hash(HashAlgo::Sha1, &"bb".repeat(20)));
        assert!(svc.threat_hash(HashAlgo::Sha256, &"cc".repeat(32)));
        assert!(!svc.threat_hash(HashAlgo::Md5, &"cc".repeat(32)));
        assert!(!svc.threat_hash(HashAlgo::Sha256, "nothex"));

        assert!(svc.allowlisted_domain("baidu.com").is_some());
        assert!(svc.allowlisted_domain("Map.BAIDU.com").is_some()); // 大小写归一
        assert!(svc.allowlisted_domain("map.baidu.com").is_some()); // 子域名
        assert!(svc.allowlisted_domain("notbaidu.com.evil.example").is_none());
        assert!(svc.allowlisted_ip("10.0.0.1"));
        assert!(svc.is_public_dns("8.8.8.8"));
        assert!(!svc.is_public_dns("1.2.3.4"));

        let _ = fs::remove_dir_all(&threat);
        let _ = fs::remove_dir_all(&allow);
    }

    #[test]
    fn missing_dirs_yield_unconfigured_state() {
        let svc = IntelService::load(None, None);
        assert_eq!(svc.state(), IntelState::NotConfigured);
        assert!(svc.is_empty());
        assert!(!svc.threat_ip("203.0.113.9"));
        assert!(svc.allowlisted_domain("baidu.com").is_none());
        // 未配置不是"读取失败"：report 明确写出未配置，而不是撒谎成 empty
        let report = svc.report().join("\n");
        assert!(report.contains("intel=unconfigured"));
        assert!(report.contains("threat: 未配置"));
    }

    #[test]
    fn unreadable_dataset_is_misconfigured_not_empty() {
        let threat = tmpdir("broken");
        // 目录存在但文件缺失 → 读取失败必须被记录，状态为 misconfigured
        write(&threat.join("ip.txt"), "203.0.113.9\n");
        let svc = IntelService::load(Some(&threat), None);
        assert_eq!(svc.state(), IntelState::Misconfigured);
        let report = svc.report().join("\n");
        assert!(report.contains("intel=misconfigured"));
        assert!(report.contains("threat/domain.txt: 读取失败"));
        assert!(report.contains("threat/ip.txt: 1 条"));
        let _ = fs::remove_dir_all(&threat);
    }

    #[test]
    fn configured_but_empty_dataset_is_empty_state() {
        let threat = tmpdir("empty");
        for name in ["ip", "domain", "md5", "sha1", "sha256"] {
            write(&threat.join(format!("{name}.txt")), "# no data\n");
        }
        let svc = IntelService::load(Some(&threat), None);
        assert_eq!(svc.state(), IntelState::Empty);
        assert!(svc.is_empty());
        let _ = fs::remove_dir_all(&threat);
    }

    #[test]
    fn rejects_public_suffix_entries() {
        let threat = tmpdir("pubsuffix");
        let allow = tmpdir("pubsuffix-allow");
        write(&threat.join("domain.txt"), "co.kr\nevil.example\n");
        write(&allow.join("domain.txt"), "com\nbaidu.com\n");
        let svc = IntelService::load(Some(&threat), Some(&allow));
        // co.kr 被加载期拒绝，且不会把 *.co.kr 整片判成威胁（威胁域名本来就是精确匹配）
        assert!(!svc.threat_domain("co.kr"));
        assert!(!svc.threat_domain("naver.co.kr"));
        assert!(svc.threat_domain("evil.example"));
        // 白名单拒绝单标签公共后缀，避免 "com" 把全世界加入白名单
        assert!(svc.allowlisted_domain("any.example").is_none());
        assert!(svc.allowlisted_domain("map.baidu.com").is_some());
        let report = svc.report().join("\n");
        assert!(report.contains("拒绝公共后缀条目 1 条: co.kr"));
        let _ = fs::remove_dir_all(&threat);
        let _ = fs::remove_dir_all(&allow);
    }

    #[test]
    fn allowlist_returns_longest_suffix() {
        let allow = tmpdir("longest");
        write(&allow.join("domain.txt"), "baidu.com\nmap.baidu.com\n");
        let svc = IntelService::load(None, Some(&allow));
        assert_eq!(
            svc.allowlisted_domain("x.map.baidu.com").as_deref(),
            Some("map.baidu.com")
        );
        assert_eq!(
            svc.allowlisted_domain("x.baidu.com").as_deref(),
            Some("baidu.com")
        );
        let _ = fs::remove_dir_all(&allow);
    }

    #[test]
    fn annotates_event_from_fields() {
        let threat = tmpdir("threat2");
        let allow = tmpdir("allow2");
        write(&threat.join("ip.txt"), "203.0.113.9\n");
        write(&threat.join("domain.txt"), "evil.example\n");
        write(&allow.join("domain.txt"), "baidu.com\n");
        write(&allow.join("public_dns.txt"), "8.8.8.8\n");

        let svc = IntelService::load(Some(&threat), Some(&allow));
        let ev = HookEvent {
            source: "suricata".into(),
            kind: "event".into(),
            src: Some("203.0.113.9".into()),
            dst: Some("8.8.8.8".into()),
            dns_query: Some("map.baidu.com".into()),
            ..HookEvent::default()
        };
        let ann = svc.annotate_event(&ev);
        assert!(ann.threat.is_some());
        assert!(ann.allowlist.is_some());
        assert_eq!(ann.decision(), Some("threat-overrides-allowlist"));
        // 8.8.8.8 是公共 DNS，不在基线外
        assert!(!ann.public_dns_off_baseline);

        let ev2 = HookEvent {
            dst: Some("9.9.9.10".into()),
            dns_query: Some("tunnel.suspect".into()),
            ..ev.clone()
        };
        let ann2 = svc.annotate_event(&ev2);
        assert!(ann2.public_dns_off_baseline);
        assert_eq!(ann2.decision(), Some("threat-hit"));

        // 未命中任何情报的事件不产生标注
        let ev3 = HookEvent {
            src: Some("198.51.100.1".into()),
            dst: Some("8.8.8.8".into()),
            dns_query: Some("ok.example".into()),
            ..HookEvent::default()
        };
        let ann3 = svc.annotate_event(&ev3);
        assert!(ann3.is_empty());
        assert_eq!(ann3.decision(), None);

        let _ = fs::remove_dir_all(&threat);
        let _ = fs::remove_dir_all(&allow);
    }

    #[test]
    fn annotates_file_hashes_by_algorithm() {
        let threat = tmpdir("hashes");
        write(&threat.join("md5.txt"), "aa".repeat(16).as_str());
        write(&threat.join("sha1.txt"), "bb".repeat(20).as_str());
        write(&threat.join("sha256.txt"), "cc".repeat(32).as_str());
        let svc = IntelService::load(Some(&threat), None);

        for (field, value, kind) in [
            ("md5", "aa".repeat(16), "md5"),
            ("sha1", "bb".repeat(20), "sha1"),
            ("sha256", "cc".repeat(32), "sha256"),
        ] {
            let mut ev = HookEvent::default();
            match field {
                "md5" => ev.file_md5 = Some(value.clone()),
                "sha1" => ev.file_sha1 = Some(value.clone()),
                _ => ev.file_sha256 = Some(value.clone()),
            }
            let ann = svc.annotate_event(&ev);
            let hits = ann.threat.expect("hash hit").to_string();
            assert!(hits.contains(&format!("\"type\":\"{kind}\"")), "{hits}");
            assert_eq!(ann.decision(), Some("threat-hit"));
        }
        let _ = fs::remove_dir_all(&threat);
    }

    #[test]
    fn annotate_events_merges_alert_and_context() {
        let threat = tmpdir("merge");
        write(&threat.join("ip.txt"), "203.0.113.9\n");
        write(&threat.join("domain.txt"), "evil.example\n");
        let svc = IntelService::load(Some(&threat), None);

        let alert = HookEvent {
            src: Some("203.0.113.9".into()),
            ..HookEvent::default()
        };
        let context = HookEvent {
            host: Some("evil.example".into()),
            ..HookEvent::default()
        };
        let ann = svc.annotate_events(&[&alert, &context]);
        let text = ann.threat.expect("threat hits").to_string();
        assert!(text.contains("203.0.113.9"));
        assert!(text.contains("evil.example"));
        let _ = fs::remove_dir_all(&threat);
    }
}
