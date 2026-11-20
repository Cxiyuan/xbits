// 自动生成（勿手改）：由 triage/tools/build_rules_from_traffic_rules.py 从流量检测规则库（明文规则）抽取。
// 类别: webshell | 规则数: 85 | 仅收录：文件内容型 & 不与 Suricata/Zeek 重复。

rule xb_webshell_17089967
{
    meta:
        description = "WebShell Detect chopper:request"
        sid = "17089967"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/commonwebshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "array_map(\"ass\".\"ert" nocase
    condition:
        $s1
}

rule xb_webshell_17073502
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073502"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Security House - Shell Center"
        $s2 = "<b> [Turkish Security Network] - Edited By KingDefacer"
    condition:
        all of them
}

rule xb_webshell_17073503
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073503"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>Shell - </title>"
    condition:
        $s1
}

rule xb_webshell_17073504
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073504"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "SpyGrup Safe Mod:"
        $s2 = "<h3>RFI Olarak Kullanilmaz .PHP Olarak Host'a Yukleyiniz</h3>"
    condition:
        all of them
}

rule xb_webshell_17073505
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073505"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e6 89 a7 e8 a1 8c 43 4d 44 }
    condition:
        $s1
}

rule xb_webshell_17073506
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073506"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "frmChangeMode"
    condition:
        $s1
}

rule xb_webshell_17073507
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073507"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Input command"
    condition:
        $s1
}

rule xb_webshell_17073508
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073508"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "cmd shell"
    condition:
        $s1
}

rule xb_webshell_17073509
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073509"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e7 81 ad e5 a4 a9 e8 bf 9c e7 a8 8b e7 ae a1 e7 90 86 3c 2f 74 69 74 6c 65 3e }
    condition:
        $s1
}

rule xb_webshell_17073510
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073510"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "PHANTASMA-"
    condition:
        $s1
}

rule xb_webshell_17073512
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073512"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "ADMINSTRATORS TOOLKIT"
    condition:
        $s1
}

rule xb_webshell_17073513
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073513"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>shell</title>"
    condition:
        $s1
}

rule xb_webshell_17073514
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073514"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<h1>You have been hack By Shany with Love To #worst.</h1>"
        $s2 = "<b>Execute command:</b>"
        $s3 = "<center><b>Command completed</b></center>"
    condition:
        all of them
}

rule xb_webshell_17073515
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073515"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 0d 0a 0d 0a 3c 70 72 65 3e }
    condition:
        $s1
}

rule xb_webshell_17073516
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073516"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<input type=\"text\" name=\"cmd\" size=45 value=\"\">"
        $s2 = "<b>The server's software:</b>"
    condition:
        all of them
}

rule xb_webshell_17073517
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073517"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Moroccan Spamers"
    condition:
        $s1
}

rule xb_webshell_17073518
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073518"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "AventGrup"
    condition:
        $s1
}

rule xb_webshell_17073519
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073519"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<!--    http://michaeldaw.org   2006    -->"
    condition:
        $s1
}

rule xb_webshell_17073520
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073520"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>[ Directory Listing ]</title>"
    condition:
        $s1
}

rule xb_webshell_17073521
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073521"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<!-- Simple PHP Backdoor By DK (One-Liner Version) -->"
        $s2 = "<!-- Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd -->"
    condition:
        all of them
}

rule xb_webshell_17073522
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073522"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Mode Shell"
        $s2 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>"
    condition:
        all of them
}

rule xb_webshell_17073524
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073524"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "ASPX one line"
    condition:
        $s1
}

rule xb_webshell_17073525
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073525"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<b>[ Defacing Tool Pro v ] <a href=\"mailto:revengans@gmail.com\">"
        $s2 = "<option>using shell_exec()"
        $s3 = "<option value=\"2\">use system()"
    condition:
        all of them
}

rule xb_webshell_17073526
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073526"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 53 51 4c 20 53 65 72 76 65 72 20 e6 95 b0 e6 8d ae e5 af bc e5 87 ba }
        $s2 = { 3c 61 20 68 72 65 66 3d 22 68 74 74 70 3a 2f 2f 68 69 2e 62 61 69 64 75 2e 63 6f 6d 2f e9 97 aa e7 94 b5 e5 b0 8f e5 ad 90 5f 74 79 73 61 6e 22 3e e9 97 aa e7 94 b5 e5 b0 8f e5 ad 90 3c 2f 61 3e }
        $s3 = { 3c 69 6e 70 75 74 20 74 79 70 65 3d 22 73 75 62 6d 69 74 22 20 6e 61 6d 65 3d 22 42 75 74 74 6f 6e 31 22 20 76 61 6c 75 65 3d 22 e5 bc 80 e5 a7 8b e5 af bc e5 87 ba 22 20 69 64 3d 22 42 75 74 74 6f 6e 31 22 20 2f 3e }
    condition:
        all of them
}

rule xb_webshell_17073527
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073527"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 3c 74 69 74 6c 65 3e 41 53 50 58 e5 b0 8f e9 a9 ac 20 2d 20 e9 bb 91 e5 85 b5 e7 a4 be e5 9b a2 3c 2f 74 69 74 6c 65 3e }
    condition:
        $s1
}

rule xb_webshell_17073528
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073528"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Bypass Exploit"
        $s2 = "/etc/passwd"
    condition:
        all of them
}

rule xb_webshell_17073529
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073529"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Shellci.biz"
    condition:
        $s1
}

rule xb_webshell_17073530
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073530"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<!-- Web shell - command execution, web.config parsing, and SQL query execution -->"
        $s2 = "<!-- Command execution - Run arbitrary Windows commands -->"
        $s3 = "<input name=\"xcmd\" type=\"text\" value=\"/c net user\" id=\"xcmd\""
    condition:
        all of them
}

rule xb_webshell_17073531
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073531"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<!-- Safe0ver By Evilc0der.org, Bet@ Versiyon, 7 Subat 2007  -->"
    condition:
        $s1
}

rule xb_webshell_17073532
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073532"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "ASPsh"
        $s2 = "goTitle.innerHTML = HTMLencode(\"CMD.EXE \" + sUsername + \" @ \" + sHostname);"
    condition:
        all of them
}

rule xb_webshell_17073533
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073533"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e7 94 a8 e6 88 b7 e8 bf 9b e7 a8 8b }
    condition:
        $s1
}

rule xb_webshell_17073534
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073534"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<TITLE>Shell Commander</TITLE>"
    condition:
        $s1
}

rule xb_webshell_17073535
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073535"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 3c 73 70 61 6e 3e 6d 73 73 71 6c b5 bc bf e2 bd c5 b1 be b9 a4 be df 20 62 79 3a b5 e3 b5 e3 }
    condition:
        $s1
}

rule xb_webshell_17073536
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073536"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 3c 66 6f 72 6d 20 61 63 74 69 6f 6e 3d 22 22 20 6d 65 74 68 6f 64 3d 22 70 6f 73 74 22 20 69 64 3d 22 66 6d 22 3e 0d 0a }
        $s2 = { 3c 74 74 3e e4 b8 8b e8 bd bd 3c 2f 74 74 3e }
    condition:
        all of them
}

rule xb_webshell_17073537
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073537"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<th>Server OS :</th>"
    condition:
        $s1
}

rule xb_webshell_17073538
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073538"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e9 9a 90 e8 97 8f e5 b0 8f e9 a9 ac }
    condition:
        $s1
}

rule xb_webshell_17073539
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073539"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "// PHP_KIT"
        $s2 = "// up.php = File Upload"
        $s3 = "// by: The Dark Raver"
    condition:
        all of them
}

rule xb_webshell_17073540
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073540"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>pwnshell - an interactive jsp shell</title>"
    condition:
        $s1
}

rule xb_webshell_17073542
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073542"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e6 95 b0 e6 8d ae e5 ba 93 e6 93 8d e4 bd 9c }
    condition:
        $s1
}

rule xb_webshell_17073544
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073544"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>Sosyete Safe Mode Bypass Shell - Edited By KingDefacer</title>"
        $s2 = "<option value=\"cat /etc/passwd\">cat/etc/passwd</option>"
    condition:
        all of them
}

rule xb_webshell_17073545
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073545"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Content-Length"
        $s2 = { 0d 0a 0d 0a 47 65 6f 72 67 20 73 61 79 73 2c 20 27 41 6c 6c 20 73 65 65 6d 73 20 66 69 6e 65 27 }
    condition:
        all of them
}

rule xb_webshell_17073546
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073546"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "WebSniff 1.0"
        $s2 = { e8 87 aa e5 8a a8 e5 97 85 e6 8e a2 3a 20 3c 2f 74 64 3e }
    condition:
        all of them
}

rule xb_webshell_17073547
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073547"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "404 Not Found</title>"
    condition:
        $s1
}

rule xb_webshell_17073548
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073548"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "id=\"ctl00\">"
    condition:
        $s1
}

rule xb_webshell_17073549
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073549"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "stest-minimized.php"
    condition:
        $s1
}

rule xb_webshell_17073550
{
    meta:
        description = "WebShell Detect 50.000 V1584931321"
        sid = "17073550"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 53 65 72 76 2d 55 20 e6 8f 90 e5 8d 87 e6 9d 83 e9 99 90 }
        $s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun love /add & net localgroup administrators goldsun /add\" size=\"50\"></td>"
    condition:
        all of them
}

rule xb_webshell_17073551
{
    meta:
        description = "WebShell Detect 50.000 V1585207874"
        sid = "17073551"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>ASPX Shell</title>"
        $s2 = "<h1>ASPX Shell by LT</h1>"
    condition:
        all of them
}

rule xb_webshell_17073552
{
    meta:
        description = "WebShell Detect 50.000 V1585207874"
        sid = "17073552"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "MINI MO Shell"
    condition:
        $s1
}

rule xb_webshell_17073554
{
    meta:
        description = "WebShell Detect 8.000 V1585207874"
        sid = "17073554"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<strong>==> PHPKonsole <==</strong>"
    condition:
        $s1
}

rule xb_webshell_17073555
{
    meta:
        description = "WebShell Detect 8.000 V1585207874"
        sid = "17073555"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<strong>==> Haxplorer <==</strong>"
    condition:
        $s1
}

rule xb_webshell_17073556
{
    meta:
        description = "WebShell Detect 9.000 V1585207874"
        sid = "17073556"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<!-- PHPShell by MAX666, Private Exploit, For Server Hacking  -->"
    condition:
        $s1
}

rule xb_webshell_17073557
{
    meta:
        description = "WebShell Detect 50.000 V1585207874"
        sid = "17073557"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "NIX REMOTE WEB-SHELL"
    condition:
        $s1
}

rule xb_webshell_17073558
{
    meta:
        description = "WebShell Detect 8.000 V1585223370"
        sid = "17073558"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e6 89 a7 e8 a1 8c 50 48 50 }
    condition:
        $s1
}

rule xb_webshell_17073559
{
    meta:
        description = "WebShell Detect 8.000 V1585223370"
        sid = "17073559"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e6 89 ab e6 8f 8f e5 90 8e e9 97 a8 }
    condition:
        $s1
}

rule xb_webshell_17073561
{
    meta:
        description = "WebShell Detect 8.000 V1585223370"
        sid = "17073561"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { e5 8f 8d e5 bc b9 e7 ab af e5 8f a3 }
    condition:
        $s1
}

rule xb_webshell_17073565
{
    meta:
        description = "WebShell Detect 50.000 V1585301106"
        sid = "17073565"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<center>.:Cyber Shell (v 1.0):."
    condition:
        $s1
}

rule xb_webshell_17073564
{
    meta:
        description = "WebShell Detect 50.000 V1585301106"
        sid = "17073564"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>500 Internal Server Error</title>"
    condition:
        $s1
}

rule xb_webshell_17073562
{
    meta:
        description = "WebShell Detect 13.000 V1585301106"
        sid = "17073562"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<title>BLaSTER</title>"
    condition:
        $s1
}

rule xb_webshell_17073566
{
    meta:
        description = "WebShell Detect 13.000 V1585301106"
        sid = "17073566"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<a href=\"mailto:priv8coder@gmail.com\">BLaSTER</a>"
    condition:
        $s1
}

rule xb_webshell_17073563
{
    meta:
        description = "WebShell Detect 50.000 V1585301106"
        sid = "17073563"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "<small>jsp File Browser version"
    condition:
        $s1
}

rule xb_webshell_17073604
{
    meta:
        description = "WebShell Detect 59.59296 V1587375945"
        sid = "17073604"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "**Coppermine Photo Gallery <= 1.4.3 remote cmmnds xctn**" nocase
    condition:
        $s1
}

rule xb_webshell_17073603
{
    meta:
        description = "WebShell Detect 59.59296 V1587375945"
        sid = "17073603"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "CTT Shell -=[" nocase
    condition:
        $s1
}

rule xb_webshell_17073606
{
    meta:
        description = "WebShell Detect 62.37172 V1587375945"
        sid = "17073606"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "ScanWrtieable" nocase
    condition:
        $s1
}

rule xb_webshell_17073601
{
    meta:
        description = "WebShell Detect 59.59296 V1587375945"
        sid = "17073601"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 42 61 63 6b 64 6f 6f 72 20 50 48 50 20 63 6f 64 a8 a6 65 20 70 61 72 20 72 41 69 64 45 6e 20 26 20 4c 46 4c }
    condition:
        $s1
}

rule xb_webshell_17073605
{
    meta:
        description = "WebShell Detect 59.59296 V1587375945"
        sid = "17073605"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 57 65 62 53 6e 69 66 66 20 31 2e 30 20 20 50 6f 77 65 72 65 64 20 62 79 20 20 43 2e 43 2e 54 a1 a3 6c 69 6e 78 20 d0 de b8 c4 b0 e6 }
    condition:
        $s1
}

rule xb_webshell_17073624
{
    meta:
        description = "WebShell Detect 9.76911 V1587375945"
        sid = "17073624"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { a7 aa a7 df a7 e6 a7 e0 a7 e2 a7 de a7 d1 a7 e4 a7 e0 a7 e2 }
    condition:
        $s1
}

rule xb_webshell_17073620
{
    meta:
        description = "WebShell Detect 16.15825 V1587375945"
        sid = "17073620"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 43 6f 6e 74 61 63 74 65 72 20 6c 65 20 63 72 a8 a6 61 74 65 75 72 }
    condition:
        $s1
}

rule xb_webshell_17073608
{
    meta:
        description = "WebShell Detect 19.91945 V1587375945"
        sid = "17073608"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 4c 69 73 74 65 72 20 75 6e 20 72 a8 a6 70 65 72 74 6f 69 72 65 73 }
    condition:
        $s1
}

rule xb_webshell_17073609
{
    meta:
        description = "WebShell Detect 16.82841 V1587375945"
        sid = "17073609"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Infos serveur" nocase
    condition:
        $s1
}

rule xb_webshell_17073616
{
    meta:
        description = "WebShell Detect 10.07784 V1587375945"
        sid = "17073616"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Envoyer un mail" nocase
    condition:
        $s1
}

rule xb_webshell_17073612
{
    meta:
        description = "WebShell Detect 19.91945 V1587375945"
        sid = "17073612"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Www.hkmjj.Com" nocase
    condition:
        $s1
}

rule xb_webshell_17073614
{
    meta:
        description = "WebShell Detect 19.91945 V1587375945"
        sid = "17073614"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "http://retrogod.altervista.org" nocase
    condition:
        $s1
}

rule xb_webshell_17073621
{
    meta:
        description = "WebShell Detect 19.91945 V1587375945"
        sid = "17073621"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 45 78 a8 a6 63 75 74 65 72 20 75 6e 65 20 63 6f 6d 6d 61 6e 64 65 20 64 61 6e 73 20 75 6e 20 73 68 65 6c 6c }
    condition:
        $s1
}

rule xb_webshell_17073613
{
    meta:
        description = "WebShell Detect 17.08624 V1587375945"
        sid = "17073613"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "www.cncert.net" nocase
    condition:
        $s1
}

rule xb_webshell_17073611
{
    meta:
        description = "WebShell Detect 18.12769 V1587375945"
        sid = "17073611"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 45 78 a8 a6 63 75 74 65 72 20 64 75 20 63 6f 64 65 20 50 48 50 }
    condition:
        $s1
}

rule xb_webshell_17073622
{
    meta:
        description = "WebShell Detect 13.56161 V1587375945"
        sid = "17073622"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 47 a8 a6 72 65 72 20 6c 65 73 20 66 69 63 68 69 65 72 73 }
    condition:
        $s1
}

rule xb_webshell_17073627
{
    meta:
        description = "WebShell Detect 8.13650 V1587375945"
        sid = "17073627"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 50 48 50 2d a7 ac a7 e0 a7 d5 }
    condition:
        $s1
}

rule xb_webshell_17073625
{
    meta:
        description = "WebShell Detect 16.42295 V1587375945"
        sid = "17073625"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "WebSniff 1.0" nocase
    condition:
        $s1
}

rule xb_webshell_17073626
{
    meta:
        description = "WebShell Detect 14.68834 V1587375945"
        sid = "17073626"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "pro info: ip" nocase
    condition:
        $s1
}

rule xb_webshell_17073628
{
    meta:
        description = "WebShell Detect 12.95343 V1587375945"
        sid = "17073628"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { 50 48 50 2d a7 aa a7 df a7 e6 a7 e0 }
    condition:
        $s1
}

rule xb_webshell_17073630
{
    meta:
        description = "WebShell Detect 16.20588 V1587375945"
        sid = "17073630"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "[ Defacing Tool Pro v ]" nocase
    condition:
        $s1
}

rule xb_webshell_17073631
{
    meta:
        description = "WebShell Detect 15.85901 V1587375945"
        sid = "17073631"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = { a7 b3 a7 d1 a7 de 20 a7 e5 a7 d5 a7 d1 a7 dd a7 f1 a7 f0 a7 e4 }
    condition:
        $s1
}

rule xb_webshell_17073634
{
    meta:
        description = "WebShell Detect 16.13526 V1587375945"
        sid = "17073634"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Php Back Connect" nocase
    condition:
        $s1
}

rule xb_webshell_17073652
{
    meta:
        description = "WebShell Detect 50.000 V1587461705"
        sid = "17073652"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = ".::News Remote PHP Shell Injection::."
    condition:
        $s1
}

rule xb_webshell_17073654
{
    meta:
        description = "WebShell Detect 9.000 V1587461705"
        sid = "17073654"
        category = "webshell"
        source = "etc_fw/pvs/rules/success/ml_webshell.rules"
        engine = "xbits-triage"
    strings:
        $s1 = "Echo commands"
    condition:
        $s1
}
