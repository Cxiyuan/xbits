##! xbits_alert.zeek —— 统一告警接口（禁用 Zeek 默认告警输出，告警只经本接口）
##!
##! 目的：
##!   1) 关闭 Zeek 默认“告警类”日志输出：notice.log / notice_alarm.log / signatures.log / weird.log / intel.log；
##!   2) 所有告警输出统一走 XbitsAlert 接口：只有被 register 注册的 kind 才输出；
##!   3) 下游可在自己的脚本里 `event XbitsAlert::alert(info)` 订阅，或读 `xbits_alert.log`。
##!
##! 用法：
##!   redef XbitsAlert::registered += { "scanner" };     # 注册允许输出的告警类别
##!   XbitsAlert::emit("scanner", "gobuster", "high", 1.2.3.4, "dir_brute ...");
##!
##! 状态：待 Zeek 9.0.1 编译验证。

module XbitsAlert;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:       time   &log;
		kind:     string &log &default="-";     # 告警类别（需 register）
		name:     string &log &default="-";     # 具体名称/工具
		severity: string &log &default="info";  # info/low/medium/high
		src:      addr   &log &default=0.0.0.0;
		evidence: string &log &default="-";
	};

	## 日志流策略 hook
	global log_policy: Log::PolicyHook;

	## 总开关
	global enabled: bool = T &redef;
	## 若为 T 则不校验 registered（不推荐）
	global allow_all: bool = F &redef;

	## 只输出被注册的 kind（redef 添加，如 {"scanner"}）
	global registered: set[string] &redef;

	## 注册允许输出的告警类别
	global register: function(kind: string);

	## 统一告警输出入口（唯一告警出口）
	global emit: function(kind: string, name: string, severity: string, src: addr, evidence: string);

	## 可供下游脚本订阅的告警事件
	global alert: event(info: Info);
}

function register(kind: string)
	{
	add registered[kind];
	}

function emit(kind: string, name: string, severity: string, src: addr, evidence: string)
	{
	if ( ! enabled )
		return;
	if ( ! ( allow_all || kind in registered ) )
		return;

	local i = Info($ts=network_time(), $kind=kind, $name=name,
	               $severity=severity, $src=src, $evidence=evidence);
	Log::write(XbitsAlert::LOG, i);
	event XbitsAlert::alert(i);
	}

event zeek_init() &priority=5
	{
	Log::create_stream(XbitsAlert::LOG, [$columns=Info, $path="xbits_alert", $policy=log_policy]);
	}

# 关闭默认告警输出（在 base 各 zeek_init(priority=5/0) 创建流之后执行）
event zeek_init() &priority=-100
	{
	Log::disable_stream(Notice::LOG);
	Log::disable_stream(Notice::ALARM_LOG);
	Log::disable_stream(Signatures::LOG);
	Log::disable_stream(Weird::LOG);
	Log::disable_stream(Intel::LOG);
	}

# 兜底：清除 Notice 的默认动作（ACTION_LOG/EMAIL/ALARM），即使流被重新开启也不外发
hook Notice::policy(n: Notice::Info)
	{
	delete n$actions[Notice::ACTION_LOG];
	delete n$actions[Notice::ACTION_EMAIL];
	delete n$actions[Notice::ACTION_ALARM];
	delete n$actions[Notice::ACTION_DROP];
@ifdef ( Notice::ACTION_PAGE )
	delete n$actions[Notice::ACTION_PAGE];
@endif
	}
