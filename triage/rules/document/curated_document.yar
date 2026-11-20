/*
  xbits 静态 triage —— 可疑 PDF 规则（起步集）
*/

rule pdf_js_openaction
{
    meta:
        description = "PDF with JavaScript auto-run (/OpenAction + /JavaScript)"
        author = "xbits"
        severity = "high"
        category = "document"
    strings:
        $pdf = "%PDF-"
        $js = "/JavaScript"
        $oa = "/OpenAction"
        $aa = "/AA"
        $launch = "/Launch"
    condition:
        $pdf at 0 and (($js and ($oa or $aa)) or $launch)
}

rule pdf_embedded_executable
{
    meta:
        description = "PDF embedding executable/file"
        author = "xbits"
        severity = "high"
        category = "document"
    strings:
        $pdf = "%PDF-"
        $emb = "/EmbeddedFile"
        $exe = "This program cannot be run in DOS mode"   /* MZ stub text */
        $js = "/JavaScript"
    condition:
        $pdf at 0 and $emb and ($exe or $js)
}
