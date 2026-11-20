/*
  xbits 静态 triage —— 可疑 PE / 二进制 YARA 规则（起步集）
  命中作为证据之一；已签名二进制的降级策略见 triage.py（signed dampening）。
*/

rule pe_process_injection
{
    meta:
        description = "PE imports/strings of process injection triad"
        author = "xbits"
        severity = "high"
        category = "malware"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
    condition:
        uint16(0) == 0x5A4D and $a and $b and ($c or $d)
}

rule pe_download_and_exec
{
    meta:
        description = "Download then execute behavior"
        author = "xbits"
        severity = "high"
        category = "malware"
    strings:
        $dl1 = "URLDownloadToFile"
        $dl2 = "InternetOpenUrl"
        $run1 = "WinExec"
        $run2 = "ShellExecute"
        $run3 = "CreateProcess"
    condition:
        uint16(0) == 0x5A4D and any of ($dl1, $dl2) and any of ($run1, $run2, $run3)
}

rule pe_upx_packed
{
    meta:
        description = "UPX packed executable"
        author = "xbits"
        severity = "medium"
        category = "packer"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx = "UPX!"
    condition:
        ($upx0 and $upx1) or $upx
}

rule pe_suspicious_service_persist
{
    meta:
        description = "Service/registry persistence APIs"
        author = "xbits"
        severity = "medium"
        category = "malware"
    strings:
        $svc = "CreateServiceA"
        $reg = "RegSetValueExA"
        $sched = "schtasks"
        $run = "CurrentVersion\\Run"
    condition:
        uint16(0) == 0x5A4D and ($svc or $reg) and ($sched or $run)
}

rule elf_reverse_shell_markers
{
    meta:
        description = "ELF strings for reverse shell / command exec"
        author = "xbits"
        severity = "high"
        category = "malware"
    strings:
        $elf = { 7F 45 4C 46 }
        $a = "/bin/sh"
        $b = "/bin/bash"
        $c = "socket"
        $d = "connect"
        $e = "dup2"
        $f = "execve"
    condition:
        $elf at 0 and any of ($a, $b) and 2 of ($c, $d, $e, $f)
}
