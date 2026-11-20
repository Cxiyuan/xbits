// 自动生成（勿手改）：由 triage/tools/build_rules_from_traffic_rules.py 从流量检测规则库（明文规则）抽取。
// 类别: backdoor | 规则数: 58 | 仅收录：文件内容型 & 不与 Suricata/Zeek 重复。

rule xb_backdoor_115
{
    meta:
        description = "Backdoor NetBus Pro_2.0 Connection Established"
        sid = "115"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 42 4e 10 00 02 00 }
        $s2 = { 05 00 }
    condition:
        all of them
}

rule xb_backdoor_2124
{
    meta:
        description = "Backdoor Remote PC Access Connection Attempt"
        sid = "2124"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 28 00 01 00 04 00 00 00 00 00 00 00 }
    condition:
        $s1
}

rule xb_backdoor_6108
{
    meta:
        description = "Backdoor Dagger v1.1.40 Runtime Detection"
        sid = "6108"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0b 00 00 00 07 00 00 00 43 6f 6e 6e 65 63 74 }
    condition:
        $s1
}

rule xb_backdoor_6024
{
    meta:
        description = "Backdoor Nuclear Rat V6_21 Runtime Detection"
        sid = "6024"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c2 c5 cd c4 fd f9 ff 86 e4 9a f8 ff e5 9b 98 e5 fc e1 fd a9 fc c2 c5 99 c0 a9 }
    condition:
        $s1
}

rule xb_backdoor_6125
{
    meta:
        description = "Backdoor Dkangel Runtime Detection - Smtp"
        sid = "6125"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Subject:" nocase
        $s2 = { ba da b0 b5 cc ec ca b9 20 32 2e 34 31 20 }
    condition:
        all of them
}

rule xb_backdoor_6049
{
    meta:
        description = "Backdoor Fun Factory Runtime Detection - Upload"
        sid = "6049"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { ab 86 01 00 12 00 00 00 }
    condition:
        $s1
}

rule xb_backdoor_6110
{
    meta:
        description = "Backdoor Forced Entry V1.1 Beta Runtime Detection"
        sid = "6110"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "ForCed" nocase
        $s2 = "EnTrY" nocase
        $s3 = { 0d 0a 0d 0a 0d 0a 43 6f 6e 6e 65 63 74 69 6f 6e }
        $s4 = " Stable" nocase
    condition:
        all of them
}

rule xb_backdoor_6118
{
    meta:
        description = "Backdoor Net Runner Runtime Detection - Initial Connection Client-To-Server"
        sid = "6118"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0e 47 65 74 20 52 65 73 6f 6c 75 74 69 6f 6e }
    condition:
        $s1
}

rule xb_backdoor_6051
{
    meta:
        description = "Backdoor Fun Factory Runtime Detection - Set Volume"
        sid = "6051"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { b0 86 01 00 01 00 00 00 30 }
    condition:
        $s1
}

rule xb_backdoor_6055
{
    meta:
        description = "Backdoor Bifrose 1.1 Runtime Detection"
        sid = "6055"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 00 00 91 49 16 1b 65 1c }
    condition:
        $s1
}

rule xb_backdoor_6025
{
    meta:
        description = "Backdoor Tequila Bandita 1.2 Runtime Detection - Reverse Connection"
        sid = "6025"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 07 4c 41 4e 07 57 69 6e }
    condition:
        $s1
}

rule xb_backdoor_6120
{
    meta:
        description = "Backdoor Net Runner Runtime Detection - Download File"
        sid = "6120"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0d 44 6f 77 6e 6c 6f 61 64 20 46 69 6c 65 }
    condition:
        $s1
}

rule xb_backdoor_6161
{
    meta:
        description = "Backdoor Furax 1.0 B2 Runtime Detection"
        sid = "6161"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 03 00 1c 00 00 00 00 00 01 46 75 72 61 78 20 }
        $s2 = { 53 65 72 76 65 72 00 }
    condition:
        all of them
}

rule xb_backdoor_7087
{
    meta:
        description = "Backdoor Sinique 1.0 Runtime Detection - Initial Connection With Correct Password"
        sid = "7087"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { b8 9b 93 9d 9a a2 91 86 9d 92 8d 88 }
    condition:
        $s1
}

rule xb_backdoor_7660
{
    meta:
        description = "Backdoor Lan Filtrator 1.1 Runtime Detection - Initial Connection Request"
        sid = "7660"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { b4 af 29 ae 4c 41 4e 66 69 6c 74 72 61 74 6f 72 ae 28 af 60 }
    condition:
        $s1
}

rule xb_backdoor_7764
{
    meta:
        description = "Backdoor Nt Remote Controller 2000 Runtime Detection - Sysinfo"
        sid = "7764"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = ";SystemInfo" nocase
    condition:
        $s1
}

rule xb_backdoor_7734
{
    meta:
        description = "Backdoor Bionet 4.05 Runtime Detection - Initial Connection"
        sid = "7734"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 05 00 00 00 31 00 01 00 01 fd 12 00 }
    condition:
        $s1
}

rule xb_backdoor_7659
{
    meta:
        description = "Backdoor Lan Filtrator 1.1 Runtime Detection - Sin Notification"
        sid = "7659"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "pci"
        $s2 = { 08 08 08 08 08 08 08 08 }
    condition:
        all of them
}

rule xb_backdoor_7702
{
    meta:
        description = "Backdoor Roach 1.0 Runtime Detection - Remote Control Actions"
        sid = "7702"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { a2 d0 d4 d6 df c1 e1 d5 d6 dc bb dc ce d7 }
    condition:
        $s1
}

rule xb_backdoor_7680
{
    meta:
        description = "Backdoor Cool Remote Control 1.12 Runtime Detection - Download File"
        sid = "7680"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "|GETFILE|" nocase
    condition:
        $s1
}

rule xb_backdoor_7620
{
    meta:
        description = "Backdoor Remote Control 1.7 Runtime Detection - Connection Request"
        sid = "7620"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0c 00 18 00 01 02 03 04 05 06 07 08 01 02 03 04 05 06 07 08 01 02 03 04 05 06 07 08 }
    condition:
        $s1
}

rule xb_backdoor_7763
{
    meta:
        description = "Backdoor Nt Remote Controller 2000 Runtime Detection - Services"
        sid = "7763"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = ";ServicesStatus" nocase
    condition:
        $s1
}

rule xb_backdoor_7728
{
    meta:
        description = "Backdoor Radmin Runtime Detection"
        sid = "7728"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 00 01 00 00 00 08 08 }
    condition:
        $s1
}

rule xb_backdoor_7778
{
    meta:
        description = "Backdoor Elfrat Runtime Detection - Initial Connection"
        sid = "7778"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 65 6c 66 52 41 54 04 }
    condition:
        $s1
}

rule xb_backdoor_7766
{
    meta:
        description = "Backdoor Nt Remote Controller 2000 Runtime Detection - Foldermonitor"
        sid = "7766"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = ";FolderMonitor" nocase
    condition:
        $s1
}

rule xb_backdoor_7678
{
    meta:
        description = "Backdoor Cool Remote Control 1.12 Runtime Detection - Upload File"
        sid = "7678"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "|PUTFILE|" nocase
    condition:
        $s1
}

rule xb_backdoor_7814
{
    meta:
        description = "Backdoor Darkmoon Initial Connection Detection - Stc"
        sid = "7814"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "|Connected" nocase
        $s2 = "with:" nocase
    condition:
        all of them
}

rule xb_backdoor_7812
{
    meta:
        description = "Backdoor Abacab Runtime Detection - Banner"
        sid = "7812"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 20 20 23 23 23 20 20 20 20 23 23 23 20 20 20 20 20 20 20 20 20 23 20 20 20 5f 5f 2e 2e 2e 2d 2d 27 27 20 20 20 20 20 5f 5f 5f 2e 2e 2e 2d 2d 5f 2e 2e 27 20 20 2e 3b 2e 27 20 3b 0d 0a }
        $s2 = { 43 4f 4e 4e 45 43 54 49 4f 4e 3a 0d 0a 20 0d 0a 56 65 75 69 6c 6c 65 7a 20 65 6e 74 72 65 72 20 6c 65 20 6d 6f 74 20 64 65 20 70 61 73 73 65 0d 0a 00 }
    condition:
        all of them
}

rule xb_backdoor_8074
{
    meta:
        description = "Backdoor Mithril Runtime Detection - Init Connection"
        sid = "8074"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { ce de b7 a8 b4 f2 bf aa b5 bd d6 f7 bb fa b5 c4 c1 ac bd d3 20 d4 da b6 cb bf da 20 31 33 32 37 20 3a 20 c1 ac bd d3 ca a7 b0 dc }
    condition:
        $s1
}

rule xb_backdoor_8078
{
    meta:
        description = "Backdoor Mithril Runtime Detection - Get Process List"
        sid = "8078"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { bd f8 b3 cc 49 44 ba c5 a3 ba 20 20 20 20 20 20 20 20 20 20 }
    condition:
        $s1
}

rule xb_backdoor_8076
{
    meta:
        description = "Backdoor Mithril Runtime Detection - Get System Information"
        sid = "8076"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { bc c6 cb e3 bb fa c3 fb a3 ba }
    condition:
        $s1
}

rule xb_backdoor_8362
{
    meta:
        description = "Backdoor Black Curse 4.0 Runtime Detection - Normal Init Connection"
        sid = "8362"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "|48|0|0|" nocase
    condition:
        $s1
}

rule xb_backdoor_9838
{
    meta:
        description = "Backdoor Sun Shadow 1.70 Runtime Detection - Init Connection"
        sid = "9838"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { ff 01 01 03 00 00 00 00 }
    condition:
        $s1
}

rule xb_backdoor_9659
{
    meta:
        description = "Backdoor Bersek 1.0 Runtime Detection - File Manage"
        sid = "9659"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "#[showuni]" nocase
    condition:
        $s1
}

rule xb_backdoor_9661
{
    meta:
        description = "Backdoor Bersek 1.0 Runtime Detection - Show Processes"
        sid = "9661"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "#[shwproc]" nocase
    condition:
        $s1
}

rule xb_backdoor_10461
{
    meta:
        description = "Backdoor Winicabras 1.1 Runtime Detection - Get System Info"
        sid = "10461"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0d 0a 3d 3d 49 4e 46 4f 52 4d 41 43 49 4f 4e }
    condition:
        $s1
}

rule xb_backdoor_10449
{
    meta:
        description = "Backdoor Acid Shivers Runtime Detection - Init Telnet Connection"
        sid = "10449"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 1b 5b 32 4a 1b 5b 34 30 6d 1b 5b 33 37 6d 41 63 69 64 }
        $s2 = "Shiver" nocase
        $s3 = "System" nocase
        $s4 = "Release" nocase
    condition:
        all of them
}

rule xb_backdoor_10453
{
    meta:
        description = "Backdoor Zalivator 1.4.2 Pro Runtime Detection - Smtp Notification"
        sid = "10453"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Subject:" nocase
        $s2 = "()" nocase
        $s3 = "DivXProGainBundle" nocase
        $s4 = "Registration" nocase
    condition:
        all of them
}

rule xb_backdoor_11954
{
    meta:
        description = "Backdoor Supervisor Plus Runtime Detection"
        sid = "11954"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<A " nocase
        $s2 = ";\\\\" nocase
        $s3 = "\\SV$\\><" nocase
    condition:
        all of them
}

rule xb_backdoor_11952
{
    meta:
        description = "Backdoor Winshadow Runtime Detection - Udp Response"
        sid = "11952"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 03 00 00 00 01 00 02 00 00 00 00 00 }
    condition:
        $s1
}

rule xb_backdoor_12051
{
    meta:
        description = "Backdoor Ultimate Rat 2.1 Runtime Detection"
        sid = "12051"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 02 57 6f 72 64 55 50 }
    condition:
        $s1
}

rule xb_backdoor_12165
{
    meta:
        description = "Backdoor Lithium 1.02 Runtime Detection"
        sid = "12165"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 00 00 00 00 03 00 0d 00 00 00 }
    condition:
        $s1
}

rule xb_backdoor_12143
{
    meta:
        description = "Backdoor Access Remote Pc Runtime Detection - Init Connection"
        sid = "12143"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 99 f3 00 00 00 00 00 00 ff ff ff ff }
    condition:
        $s1
}

rule xb_backdoor_12240
{
    meta:
        description = "Backdoor Genie 1.7 Runtime Detection - Init Connection"
        sid = "12240"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 1b 5b 32 4a 0d 0a 20 }
        $s2 = "Hello" nocase
        $s3 = "my" nocase
        $s4 = "master" nocase
        $s5 = "waiting" nocase
        $s6 = "for" nocase
        $s7 = "your" nocase
        $s8 = "commands" nocase
    condition:
        all of them
}

rule xb_backdoor_12235
{
    meta:
        description = "Backdoor Theef 2.10 Runtime Detection - Connect With Password"
        sid = "12235"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { fa cb d9 d9 dd c5 d8 ce d6 }
    condition:
        $s1
}

rule xb_backdoor_12234
{
    meta:
        description = "Backdoor Theef 2.10 Runtime Detection - Connect With No Password"
        sid = "12234"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { fc cf d8 d6 98 84 9b 9a }
    condition:
        $s1
}

rule xb_backdoor_12245
{
    meta:
        description = "Backdoor Furax 1.0 B3 Runtime Detection"
        sid = "12245"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 03 00 1c 00 00 00 00 00 01 46 75 72 61 78 }
        $s2 = "1.0b3" nocase
        $s3 = { 53 65 72 76 65 72 00 }
    condition:
        all of them
}

rule xb_backdoor_12243
{
    meta:
        description = "Backdoor Hotmail Hacker Log Edition 5.0 Runtime Detection - Init Connection"
        sid = "12243"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { c0 53 54 41 54 55 53 c0 53 65 72 76 65 72 }
        $s2 = "Keylogging" nocase
        $s3 = "Started!" nocase
    condition:
        all of them
}

rule xb_backdoor_12298
{
    meta:
        description = "Backdoor Bifrost V1.2.1 Runtime Detection"
        sid = "12298"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 00 00 00 9b 4f b0 68 fe 6a 9a 1c }
    condition:
        $s1
}

rule xb_backdoor_12374
{
    meta:
        description = "Backdoor Radmin 3.0 Runtime Detection - Initial Connection"
        sid = "12374"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 01 00 00 00 25 00 00 02 12 08 02 00 00 0a 00 00 }
    condition:
        $s1
}

rule xb_backdoor_12699
{
    meta:
        description = "Backdoor Poison Ivy 2.3.0 Runtime Detection - Init Connection"
        sid = "12699"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { b9 e1 a5 7e c7 b7 82 6e 22 6e 0b cb fd 77 ed 49 }
    condition:
        $s1
}

rule xb_backdoor_12726
{
    meta:
        description = "Backdoor Bandook 1.35 Runtime Detection"
        sid = "12726"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { cf 8f 80 9b 9a 9d cf c9 ca c9 d9 8d c9 }
    condition:
        $s1
}

rule xb_backdoor_13506
{
    meta:
        description = "Backdoor Evilotus 1.3.2 Runtime Detection - Init Connection"
        sid = "13506"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0c 7e 7f d8 13 00 00 00 64 c8 00 00 0b 00 00 00 07 00 00 00 80 e7 03 0c 7e 7f d8 }
    condition:
        $s1
}

rule xb_backdoor_13655
{
    meta:
        description = "Backdoor Nuclear Rat 2.1 Runtime Detection - Init Connection"
        sid = "13655"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 1e 0d 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $s1
}

rule xb_backdoor_7758
{
    meta:
        description = "Backdoor Glacier Runtime Detection - Initial Connection And Directory Browse"
        sid = "7758"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { f5 cb c9 cf c6 f5 c8 c8 ce c7 f5 }
        $s2 = { f5 d5 d1 d5 f5 }
    condition:
        all of them
}

rule xb_backdoor_9663
{
    meta:
        description = "Backdoor Bersek 1.0 Runtime Detection - Start Remote Shell"
        sid = "9663"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "#[shellrs]" nocase
    condition:
        $s1
}

rule xb_backdoor_9839
{
    meta:
        description = "Backdoor Sun Shadow 1.70 Runtime Detection - Keep Alive"
        sid = "9839"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { ff 01 03 03 00 00 00 00 }
    condition:
        $s1
}

rule xb_backdoor_7759
{
    meta:
        description = "Backdoor Glacier Runtime Detection - Screen Capture"
        sid = "7759"
        category = "backdoor"
        source = "lib_ips_feature/rules/backdoor.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { f5 ca c7 c7 c6 f5 c8 c8 ce c7 f5 }
    condition:
        $s1
}
