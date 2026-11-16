# QA 探针：主动产生一条 Notice，用于验证默认告警输出已被彻底禁用。
# 若 xbits_alert.zeek 的禁用失效，本探针会让 notice.log / notice_alarm.log 出现内容，CI 将判定 ALERT-LEAK。
redef enum Notice::Type += { XbitsQA_NoticeLeakProbe };

event connection_state_remove(c: connection)
	{
	NOTICE(Notice::Info($note=XbitsQA_NoticeLeakProbe, $msg="qa-notice-leak-probe", $src=c$id$orig_h));
	}
