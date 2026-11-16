# 测试用：注册 "scanner" 告警类别，使 XbitsAlert::emit 真正输出 xbits_alert.log
redef XbitsAlert::registered += { "scanner" };
