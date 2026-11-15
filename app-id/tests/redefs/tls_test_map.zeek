# 测试专用：把“TLS ClientHello 版本+密码套件序列”指纹映射到测试工具名，
# 用于验证 scan.zeek 的 TLS JA3-lite 机制（默认表为空，生产由运维按实测填充）。
redef XbitsScan::tls_fp_to_tool += {
	["v771|4865-4866-4867"] = "go-tls",
	["v769|4865-4866-4867"] = "go-tls",
};
