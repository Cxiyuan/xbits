// 自动生成（勿手改）：由 triage/tools/build_rules_from_traffic_rules.py 从流量检测规则库（明文规则）抽取。
// 类别: trojan | 规则数: 81 | 仅收录：文件内容型 & 不与 Suricata/Zeek 重复。

rule xb_trojan_10041258
{
    meta:
        description = "TROJAN CryptoWall Ransomware Checkin"
        sid = "10041258"
        category = "trojan"
        source = "etc_fw/sf_snort/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 63 72 70 74 }
    condition:
        all of them
}

rule xb_trojan_10040003
{
    meta:
        description = "Trojan Huigezi FuShe Remote Control"
        sid = "10040003"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0a 0b 0c 00 00 01 30 30 30 0e }
    condition:
        $s1
}

rule xb_trojan_10040004
{
    meta:
        description = "Trojan Shangxing 2008/2009 Remote Control"
        sid = "10040004"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 3c 47 52 3e 41 d7 e9 3c 2f 47 52 3e 3c 49 4d 3e 32 35 3c 2f 49 4d 3e 3c 4e 41 3e }
    condition:
        $s1
}

rule xb_trojan_10040005
{
    meta:
        description = "Trojan Shangxing 2010 Remote Control"
        sid = "10040005"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 3e 47 53 3e 43 d7 e8 3c 2d 47 53 3e 3e 49 4c 3e 30 35 3d 2f 4b 4d 3f 3c 4c 41 3f }
    condition:
        $s1
}

rule xb_trojan_10040006
{
    meta:
        description = "Trojan Netbull Remote Control"
        sid = "10040006"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 05 00 00 00 01 00 00 00 01 01 00 00 00 cc 00 00 00 }
    condition:
        $s1
}

rule xb_trojan_10040013
{
    meta:
        description = "Trojan Huigezi 2009 Remote Control"
        sid = "10040013"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 5b c3 e2 b7 d1 b7 a2 b2 bc b0 e6 5d }
    condition:
        $s1
}

rule xb_trojan_10040016
{
    meta:
        description = "Trojan Heidong Remote Control"
        sid = "10040016"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "7e3b2c09992429da9766fe42565a35bd"
    condition:
        $s1
}

rule xb_trojan_10040017
{
    meta:
        description = "Trojan YuanKongRenWoXing Remote Control"
        sid = "10040017"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { b4 c5 c5 cc c4 bf c2 bc 0d 0a }
    condition:
        $s1
}

rule xb_trojan_10041009
{
    meta:
        description = "MALWARE-CNC Win32.Worm Dorkbot Traffic"
        sid = "10041009"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 50 41 53 53 20 73 70 0d 0a }
    condition:
        $s1
}

rule xb_trojan_10041010
{
    meta:
        description = "MALWARE-CNC Win32.Worm Dorkbot Traffic"
        sid = "10041010"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "KCIK n[CN[XPa["
        $s2 = { 0d 0a 53 44 52 52 20 }
        $s3 = " 0 0 :"
    condition:
        all of them
}

rule xb_trojan_10041011
{
    meta:
        description = "MALWARE-CNC Win32.Dogrobot Traffic"
        sid = "10041011"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "MYZDDZ:Shock HeroM2|"
        $s2 = " CPU "
        $s3 = "GHz|"
    condition:
        all of them
}

rule xb_trojan_10041012
{
    meta:
        description = "MALWARE-CNC Backdoor.Sdbot Traffic"
        sid = "10041012"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = ":irc-sinkhole.cert.pl "
        $s2 = { 27 20 3a 57 69 6c 6b 6f 6d 65 6e 0a }
    condition:
        all of them
}

rule xb_trojan_10041013
{
    meta:
        description = "MALWARE-CNC Backdoor.Sdbot Traffic"
        sid = "10041013"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = ":irc-sinkhole.cert.pl 376 '"
        $s2 = "' :End of MOTD command."
    condition:
        all of them
}

rule xb_trojan_10041029
{
    meta:
        description = "MALWARE-CNC BLEEDING-EDGE P2P Iroffer IRC Bot Help Message Traffic"
        sid = "10041029"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "To request a file type: \"/msg"
    condition:
        $s1
}

rule xb_trojan_10041030
{
    meta:
        description = "MALWARE-CNC BLEEDING-EDGE P2P Iroffer IRC Bot Offered Files Advertisement Traffic"
        sid = "10041030"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Total Offered:"
    condition:
        $s1
}

rule xb_trojan_10041055
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041055"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 05 6f 6e 69 6f 6e 04 6c 69 6e 6b 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041056
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041056"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 05 6f 6e 69 6f 6e 02 67 71 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041057
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041057"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 05 6f 6e 69 6f 6e 02 74 6f 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041058
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041058"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 05 6f 6e 69 6f 6e 04 63 69 74 79 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041059
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041059"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 05 6f 6e 69 6f 6e 03 63 61 62 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041060
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041060"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 05 6f 6e 69 6f 6e 06 64 69 72 65 63 74 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041061
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041061"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 05 6f 6e 69 6f 6e 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041062
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041062"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 07 64 65 65 70 77 65 62 02 74 6f 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041063
{
    meta:
        description = "DNS Query Dangerous Domain"
        sid = "10041063"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 07 74 6f 72 32 77 65 62 03 6f 72 67 00 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041064
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041064"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 94 51 6f 6f }
    condition:
        all of them
}

rule xb_trojan_10041065
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041065"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 5b e9 f4 6a }
    condition:
        all of them
}

rule xb_trojan_10041066
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041066"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 b0 1f 3e 4c }
    condition:
        all of them
}

rule xb_trojan_10041067
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041067"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 52 a5 19 a7 }
    condition:
        all of them
}

rule xb_trojan_10041068
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041068"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 52 a5 19 d2 }
    condition:
        all of them
}

rule xb_trojan_10041069
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041069"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 c6 3d e3 06 }
    condition:
        all of them
}

rule xb_trojan_10041070
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041070"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 32 3e 0c 67 }
    condition:
        all of them
}

rule xb_trojan_10041071
{
    meta:
        description = "DNS Reply Sinkhole"
        sid = "10041071"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 8e 00 24 ea }
    condition:
        all of them
}

rule xb_trojan_10041095
{
    meta:
        description = "MALWARE-CNC Mirai BotNet DNS"
        sid = "10041095"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 0d 73 61 6e 74 61 73 62 69 67 63 61 6e 64 79 63 61 6e 65 02 63 78 00 }
    condition:
        all of them
}

rule xb_trojan_10041099
{
    meta:
        description = "Cisco TclShell TFTP Read Request"
        sid = "10041099"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 74 63 6c 73 68 2e 74 63 6c }
    condition:
        $s1
}

rule xb_trojan_10041100
{
    meta:
        description = "Cisco TclShell TFTP Download"
        sid = "10041100"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "TclShell"
    condition:
        $s1
}

rule xb_trojan_10041115
{
    meta:
        description = "TROJAN Arucer Command Execution"
        sid = "10041115"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e dd a4 a3 d4 a6 d4 d3 d1 c8 a0 a7 a1 d3 c8 d1 87 d7 87 c8 a7 a6 d4 a3 c8 d3 d1 d3 d2 d1 a0 dc dd a4 d2 d4 d5 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041116
{
    meta:
        description = "TROJAN Arucer DIR Listing"
        sid = "10041116"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e d5 d4 d2 d1 a1 d7 a3 a6 c8 d2 a6 a7 d3 c8 d1 84 d7 d7 c8 dd d2 a6 d2 c8 d2 a7 a7 d2 d7 a4 d6 d7 a3 d4 dc a3 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041117
{
    meta:
        description = "TROJAN Arucer WRITE FILE command"
        sid = "10041117"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e dc dd a1 dc d0 dd a3 a6 c8 a1 d5 a4 d7 c8 d1 83 d4 86 c8 a7 dd d1 d4 c8 d7 d6 d7 a4 a7 d6 d0 d2 a0 d2 a6 dd 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041118
{
    meta:
        description = "TROJAN Arucer READ FILE Command"
        sid = "10041118"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e a3 d3 a6 d1 d6 a0 d4 a4 c8 d4 d0 d0 d4 c8 d1 d5 d5 d5 c8 a4 d1 dd d6 c8 a6 d6 d3 d4 dc d3 dc a4 a0 a6 d1 d4 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041119
{
    meta:
        description = "TROJAN Arucer NOP Command"
        sid = "10041119"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e d2 dd d6 a0 a4 a6 a7 a3 c8 a0 a3 dd a7 c8 d1 dc dd 80 c8 a4 d5 d0 dc c8 a3 d5 a7 d0 a7 a1 d4 d7 d3 d1 d4 a0 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041120
{
    meta:
        description = "TROJAN Arucer FIND FILE Command"
        sid = "10041120"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e a0 a4 d2 a4 d7 a0 a7 d2 c8 d4 a0 d1 dc c8 d1 81 d0 83 c8 a7 d1 a1 dd c8 a1 d3 d3 d1 d0 a7 d2 d1 d1 d5 a0 d6 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041121
{
    meta:
        description = "TROJAN Arucer YES Command"
        sid = "10041121"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e a0 d7 a4 a6 d0 d5 dd dc c8 d6 dd d7 d5 c8 d1 d6 83 80 c8 dd a4 d1 a1 c8 a4 d2 d5 d7 dd a3 a4 a1 dd a6 d7 dd 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041122
{
    meta:
        description = "TROJAN Arucer ADD RUN ONCE Command"
        sid = "10041122"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e d6 dd d1 a0 a7 a0 d7 a6 c8 a3 dc a0 a4 c8 d1 83 d3 87 c8 dc d1 a0 a3 c8 a6 dc a1 d7 a1 a4 d0 dd a3 a1 d4 d6 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041123
{
    meta:
        description = "TROJAN Arucer DEL FILE Command"
        sid = "10041123"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 e5 e5 e5 9e d1 a3 d1 a3 d5 a1 dd dd c8 a0 d2 d4 d0 c8 d1 87 d4 83 c8 a7 d6 d4 d4 c8 d3 d4 a0 d0 d6 d5 a6 d7 a6 dd a3 a6 98 e5 }
    condition:
        $s1
}

rule xb_trojan_10041146
{
    meta:
        description = "TROJAN CryptoLocker Proxy Domain"
        sid = "10041146"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 70 66 33 74 6c 67 6b 70 6b 73 37 70 75 37 79 72 }
    condition:
        all of them
}

rule xb_trojan_10041147
{
    meta:
        description = "TROJAN CryptoLocker Proxy Domain"
        sid = "10041147"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 76 37 6c 66 6f 67 61 6c 61 6c 7a 63 32 63 34 64 2e }
    condition:
        all of them
}

rule xb_trojan_10041148
{
    meta:
        description = "TROJAN CryptoLocker Proxy Domain"
        sid = "10041148"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 7a 6f 71 6f 77 6d 34 6b 7a 7a 34 63 76 76 76 6c }
    condition:
        all of them
}

rule xb_trojan_10041149
{
    meta:
        description = "TROJAN CryptoWall Proxy Domain"
        sid = "10041149"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 37 6f 71 6e 73 6e 7a 77 77 6e 6d 36 7a 62 37 79 }
    condition:
        all of them
}

rule xb_trojan_10041152
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041152"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 07 66 65 64 62 6f 6f 6b 03 6f 72 67 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041153
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041153"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 06 73 75 6e 73 61 79 03 62 69 7a 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041154
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041154"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 09 66 65 65 6c 6c 67 6f 6f 64 03 6f 72 67 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041155
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041155"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 07 6b 69 6e 6f 6d 69 78 03 6f 72 67 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041156
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041156"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 06 76 65 72 65 6b 74 03 62 69 7a 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041157
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041157"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 73 74 67 67 35 6a 76 36 6d 71 69 69 62 6d 61 78 }
    condition:
        all of them
}

rule xb_trojan_10041158
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041158"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 08 67 6f 6f 64 62 69 72 64 03 62 69 7a 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041160
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041160"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 08 62 69 67 64 6f 67 67 69 03 62 69 7a 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041161
{
    meta:
        description = "TROJAN PowerShell Loader Checkin"
        sid = "10041161"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 03 73 70 6c 04 6e 6f 69 70 02 6d 65 00 }
    condition:
        all of them
}

rule xb_trojan_10041162
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041162"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 07 62 61 72 72 6f 75 74 03 6f 72 67 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041163
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041163"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 07 62 65 6e 65 74 6f 6e 03 62 69 7a 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041167
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041167"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 61 6a 6a 33 61 37 67 66 6d 67 77 6d 68 68 6f 7a }
    condition:
        all of them
}

rule xb_trojan_10041172
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041172"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 62 64 64 61 64 65 76 6c 70 6b 77 72 72 6d 75 64 }
    condition:
        all of them
}

rule xb_trojan_10041180
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041180"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 6d 70 68 74 61 64 68 63 69 35 6d 72 64 6c 6a 75 }
    condition:
        all of them
}

rule xb_trojan_10041182
{
    meta:
        description = "TROJAN Ransomware Checkin"
        sid = "10041182"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 65 71 6c 63 37 35 65 75 6d 70 62 37 37 63 65 64 }
    condition:
        all of them
}

rule xb_trojan_10041183
{
    meta:
        description = "TROJAN Cryptolocker Ransomware Checkin"
        sid = "10041183"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 64 65 32 6e 75 76 77 65 67 6f 6f 33 32 6f 71 76 }
    condition:
        all of them
}

rule xb_trojan_10041184
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041184"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 0d 62 6a 6b 73 66 6f 68 73 65 61 67 75 75 03 6f 72 67 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041186
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041186"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 68 77 35 71 72 68 36 66 78 76 32 74 6e 61 71 6e }
    condition:
        all of them
}

rule xb_trojan_10041188
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041188"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 65 71 72 76 62 63 7a 69 72 35 75 61 32 65 6d 64 }
    condition:
        all of them
}

rule xb_trojan_10041189
{
    meta:
        description = "TROJAN Ransomware Checkin"
        sid = "10041189"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 0e 75 72 32 33 32 64 6b 6b 77 70 64 6b 77 70 03 78 79 7a 00 }
    condition:
        all of them
}

rule xb_trojan_10041190
{
    meta:
        description = "TROJAN TorrentLocker Ransomware Checkin"
        sid = "10041190"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 0a 63 6c 6f 73 65 64 6f 6f 72 73 03 6e 65 74 00 }
        $s3 = { 00 01 00 01 }
    condition:
        all of them
}

rule xb_trojan_10041191
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041191"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 69 33 65 7a 6c 76 6b 6f 69 37 66 77 79 6f 6f 64 }
    condition:
        all of them
}

rule xb_trojan_10041192
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041192"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 6c 70 68 6f 6c 66 6e 76 77 62 75 6b 71 77 79 65 }
    condition:
        all of them
}

rule xb_trojan_10041193
{
    meta:
        description = "TROJAN OSX/KeRanger Ransomware Checkin"
        sid = "10041193"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 6c 63 6c 65 62 62 36 6b 76 6f 68 6c 6b 63 6d 6c }
    condition:
        all of them
}

rule xb_trojan_10041194
{
    meta:
        description = "TROJAN OSX/KeRanger Ransomware Checkin"
        sid = "10041194"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 62 6d 61 63 79 7a 6d 65 61 37 32 33 78 79 61 7a }
    condition:
        all of them
}

rule xb_trojan_10041195
{
    meta:
        description = "TROJAN OSX/KeRanger Ransomware Checkin"
        sid = "10041195"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 6e 65 6a 64 74 6b 6f 6b 37 6f 7a 35 6b 6a 6f 63 }
    condition:
        all of them
}

rule xb_trojan_10041196
{
    meta:
        description = "TROJAN OSX/KeRanger Ransomware Checkin"
        sid = "10041196"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 66 69 77 66 34 6b 77 79 73 6d 34 64 70 77 35 6c }
    condition:
        all of them
}

rule xb_trojan_10041200
{
    meta:
        description = "TROJAN Locky Ransomware Checkin"
        sid = "10041200"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 01 00 00 00 00 00 00 }
        $s2 = { 10 74 77 62 65 72 73 34 68 6d 69 36 64 78 36 35 66 }
    condition:
        all of them
}

rule xb_trojan_10041350
{
    meta:
        description = "Trojan Sinkhole DNS Reply CnC Beacon"
        sid = "10041350"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 00 00 00 00 00 }
        $s2 = { 0f 74 6f 72 70 69 67 2d 73 69 6e 6b 68 6f 6c 65 03 6f 72 67 00 }
    condition:
        all of them
}

rule xb_trojan_10041357
{
    meta:
        description = "Trojan Sinkhole DNS Reply CnC Beacon"
        sid = "10041357"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 a1 45 0d 2c }
    condition:
        all of them
}

rule xb_trojan_10041361
{
    meta:
        description = "Trojan Sinkhole DNS Reply CnC Beacon"
        sid = "10041361"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 2e f4 15 04 }
    condition:
        all of them
}

rule xb_trojan_10041362
{
    meta:
        description = "Trojan Sinkhole DNS Reply CnC Beacon"
        sid = "10041362"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 5f d3 ac 8f }
    condition:
        all of them
}

rule xb_trojan_10041363
{
    meta:
        description = "Trojan Sinkhole DNS Reply CnC Beacon"
        sid = "10041363"
        category = "trojan"
        source = "lib_ips_feature/rules/trojan.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 01 00 01 }
        $s2 = { 00 04 17 fd 2e 40 }
    condition:
        all of them
}
