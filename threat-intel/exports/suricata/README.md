# Suricata 接入 threat-intel（由 tools/collect.py 自动生成的消费物）

本目录为**生成物**（勿手改），由 `threat-intel/tools/collect.py` 每次刷新覆盖：

| 文件 | 内容 | Suricata 消费方式 |
|---|---|---|
| `iprep.list` | `<IP>,1,100`（类别 1 = ti-malicious） | `iprep` IP 信誉 |
| `iprep-categories.txt` | `1,ti-malicious` | iprep 类别定义 |
| `datasets/md5.txt` / `sha1.txt` / `sha256.txt` | 文件哈希（一行一个） | `datasets` + `file.md5/sha256` 规则 |
| `datasets/domain.txt` | 恶意域名 | `datasets` + `dns.query`/`tls.sni` 规则 |

## suricata.yaml 配置片段（示例，以所用 Suricata 版本文档为准）
```yaml
iprep:
  categories-file: /opt/threat-intel/exports/suricata/iprep-categories.txt
  default-reputation-file: /opt/threat-intel/exports/suricata/iprep.list
  reputation-files:
    - /opt/threat-intel/exports/suricata/iprep.list

datasets:
  - name: ti-malware-md5
    type: md5
    load: /opt/threat-intel/exports/suricata/datasets/md5.txt
    state: /var/lib/suricata/datasets/ti-malware-md5.lst
  - name: ti-malware-sha256
    type: sha256
    load: /opt/threat-intel/exports/suricata/datasets/sha256.txt
    state: /var/lib/suricata/datasets/ti-malware-sha256.lst
  - name: ti-malware-domain
    type: string
    load: /opt/threat-intel/exports/suricata/datasets/domain.txt
    state: /var/lib/suricata/datasets/ti-malware-domain.lst
```

## 示例规则（接入 `规则检测/suricata/威胁情报/` 场景前需用 `suricata -T` 校验并跑场景工作流）
```
# 落地文件 md5 命中恶意情报（配合文件抽取）
alert http any any -> any any (flow:established,to_client; file.md5; dataset:isset,ti-malware-md5; classtype:trojan-activity; sid:9600001; rev:1;)
# 落地文件 sha256 命中
alert http any any -> any any (flow:established,to_client; file.sha256; dataset:isset,ti-malware-sha256; classtype:trojan-activity; sid:9600002; rev:1;)
# 恶意 IP（信誉 > 50）
alert ip any any -> any any (iprep:both,ti-malicious,>,50; classtype:trojan-activity; sid:9600003; rev:1;)
# 恶意域名（DNS 查询）
alert dns any any -> any any (dns.query; dataset:isset,ti-malware-domain; classtype:trojan-activity; sid:9600004; rev:1;)
```

> 注意：dataset 内容更新后 Suricata 需重载（`state` 会缓存；可删除 state 文件后重启，或按部署方式热重载）。
