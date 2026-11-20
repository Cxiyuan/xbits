#!/usr/bin/env bash
# 拉取社区开源 YARA 规则到 triage/rules/vendor/（可选，需联网；仅开发/部署期运行）
# 说明：仓库不内置第三方规则语料，避免体积与授权/陈旧问题；按需拉取。
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vendor
clone_or_pull() {
  local repo="$1" dest="$2"
  if [ -d "$dest/.git" ]; then
    git -C "$dest" pull --ff-only
  else
    git clone --depth 1 "$repo" "$dest"
  fi
}
clone_or_pull https://github.com/Neo23x0/signature-base.git vendor/signature-base
clone_or_pull https://github.com/Yara-Rules/rules.git vendor/yara-rules
echo "已拉取社区规则到 triage/rules/vendor/（注意各自 LICENSE，商用需自行确认）"
echo "triage.py 默认只加载 triage/rules/*.yar（不含 vendor/子目录），"
echo "如需启用社区规则，可显式 --rules-dir triage/rules/vendor/signature-base/yara 等。"
