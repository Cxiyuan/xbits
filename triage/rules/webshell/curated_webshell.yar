/*
  xbits 静态 triage —— WebShell / 脚本类 YARA 规则（起步集，可按需扩充）
  仅做静态特征匹配，命中只作为"可疑/恶意"证据之一，不单独放宽 xbits 抑制。
*/

rule webshell_php_eval_superglobal
{
    meta:
        description = "PHP webshell: eval/assert on request superglobal"
        author = "xbits"
        severity = "critical"
        category = "webshell"
    strings:
        $php = "<?php"
        $eval = /\beval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)/
        $assert = /\bassert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)/
        $create = /\bcreate_function\s*\(/
    condition:
        $php and ($eval or $assert or $create)
}

rule webshell_php_obfuscated
{
    meta:
        description = "PHP obfuscated loader: base64/gzinflate/rot13 + eval"
        author = "xbits"
        severity = "high"
        category = "webshell"
    strings:
        $eval = /\beval\s*\(/
        $b64 = "base64_decode"
        $gz = "gzinflate"
        $rot = "str_rot13"
        $assert = /\bassert\s*\(/
    condition:
        $eval and any of ($b64, $gz, $rot) or ($assert and any of ($b64, $gz, $rot))
}

rule webshell_jsp_runtime_exec
{
    meta:
        description = "JSP/Java webshell: Runtime.exec / ProcessBuilder"
        author = "xbits"
        severity = "critical"
        category = "webshell"
    strings:
        $exec = "Runtime.getRuntime().exec"
        $pb = "new ProcessBuilder"
        $getrt = "getRuntime"
        $req = /request\.getParameter\s*\(/
        $class = "defineClass"
    condition:
        ($exec or $pb) or ($getrt and $req) or $class
}

rule webshell_asp_execute
{
    meta:
        description = "ASP webshell: Execute/Eval on Request"
        author = "xbits"
        severity = "high"
        category = "webshell"
    strings:
        $exec = /Execute\s*\(\s*Request/i
        $eval = /Eval\s*\(\s*Request/i
        $server = "Server.CreateObject"
        $wscript = "WScript.Shell"
    condition:
        ($exec or $eval) or ($server and $wscript)
}

rule webshell_common_markers
{
    meta:
        description = "Common webshell management markers"
        author = "xbits"
        severity = "medium"
        category = "webshell"
    strings:
        $a = "eval($_POST"
        $b = "eval($_GET"
        $c = "assert($_POST"
        $d = "AntSword"
        $e = "China Chopper"
        $f = "b374k"
        $g = "c99shell"
    condition:
        any of them
}
