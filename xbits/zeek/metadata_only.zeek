##! xbits Zeek metadata-only logging policy.
##!
##! Keep normal metadata streams (conn/http/dns/ssl/app_identity/scan_report)
##! and suppress every framework alert stream.  Alert output is handled by
##! xbits central engine after XbitsAlert::alert reaches the thin hook.
##!
##! Load after base scripts:
##!   zeek -Cr pcap /opt/xbits/zeek/metadata_only.zeek ...

event zeek_init() &priority=-100
	{
	Log::disable_stream(Notice::LOG);
	Log::disable_stream(Notice::ALARM_LOG);
	Log::disable_stream(Signatures::LOG);
	Log::disable_stream(Weird::LOG);
	Log::disable_stream(Intel::LOG);
	}
