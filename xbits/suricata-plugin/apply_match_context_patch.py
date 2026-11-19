#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apply xbits match-context export patch to Suricata 8.0.8 source tree.

Usage:
  python3 xbits/suricata-plugin/apply_match_context_patch.py /tmp/suricata-8.0.8
"""
from __future__ import annotations

import sys
from pathlib import Path


def replace_n(path: Path, old: str, new: str, expected: int) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"patch anchor count={count}, expected={expected} in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new), encoding="utf-8")


def replace_once(path: Path, old: str, new: str) -> None:
    replace_n(path, old, new, 1)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: apply_match_context_patch.py SURICATA_SRC", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    detect_h = root / "src" / "detect.h"
    engine_c = root / "src" / "detect-engine.c"
    lua_c = root / "src" / "detect-lua.c"

    replace_once(
        detect_h,
        "#endif /* SURICATA_DETECT_H */\n",
        """/* xbits match-context exporter (Suricata 8.0.8 patch). */
typedef void (*XbitsMatchContextFn)(uint32_t sid, const Packet *p, uint64_t tx_id,
        const char *buffer, const uint8_t *data, uint32_t data_len, void *user);
void XbitsRegisterMatchContextExporter(XbitsMatchContextFn cb, void *user);
void XbitsEmitMatchContextNamed(DetectEngineThreadCtx *det_ctx, const Signature *s,
        const char *name, const uint8_t *data, uint32_t data_len);

#endif /* SURICATA_DETECT_H */
""",
    )

    replace_once(
        engine_c,
        "static DetectEngineMasterCtx g_master_de_ctx = { SCMUTEX_INITIALIZER,\n    0, 99, NULL, NULL, TENANT_SELECTOR_UNKNOWN, NULL, NULL, 0};\n",
        """static DetectEngineMasterCtx g_master_de_ctx = { SCMUTEX_INITIALIZER,
    0, 99, NULL, NULL, TENANT_SELECTOR_UNKNOWN, NULL, NULL, 0};

/* xbits match-context exporter: populated by xbits-suricata-hook plugin. */
static XbitsMatchContextFn g_xbits_match_context_cb = NULL;
static void *g_xbits_match_context_user = NULL;

void XbitsRegisterMatchContextExporter(XbitsMatchContextFn cb, void *user)
{
    g_xbits_match_context_cb = cb;
    g_xbits_match_context_user = user;
}

static void XbitsEmitMatchContext(DetectEngineThreadCtx *det_ctx, const Signature *s,
        int list_id, const uint8_t *data, uint32_t data_len)
{
    if (g_xbits_match_context_cb == NULL || data == NULL || data_len == 0 || s == NULL)
        return;
    const char *name = DetectEngineBufferTypeGetNameById(det_ctx->de_ctx, list_id);
    if (name == NULL)
        return;
    const uint64_t tx_id = det_ctx->tx_id_set ? det_ctx->tx_id : 0;
    g_xbits_match_context_cb(s->id, det_ctx->p, tx_id, name, data, data_len,
            g_xbits_match_context_user);
}

void XbitsEmitMatchContextNamed(DetectEngineThreadCtx *det_ctx, const Signature *s,
        const char *name, const uint8_t *data, uint32_t data_len)
{
    if (g_xbits_match_context_cb == NULL || data == NULL || data_len == 0 || s == NULL ||
            name == NULL)
        return;
    const uint64_t tx_id = det_ctx->tx_id_set ? det_ctx->tx_id : 0;
    g_xbits_match_context_cb(s->id, det_ctx->p, tx_id, name, data, data_len,
            g_xbits_match_context_user);
}
""",
    )

    # App-layer generic/single buffer inspect (two identical sites).
    replace_n(
        engine_c,
        """    const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f, data,
            data_len, offset, ci_flags, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    if (match) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
""",
        """    const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f, data,
            data_len, offset, ci_flags, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    if (match) {
        XbitsEmitMatchContext(det_ctx, s, list_id, data, data_len);
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
""",
        2,
    )

    # Multi-buffer inspect (file.data, dns queries, etc.).
    replace_once(
        engine_c,
        """        const bool match = DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, engine->smd,
                NULL, f, buffer, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
""",
        """        const bool match = DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, engine->smd,
                NULL, f, buffer, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            XbitsEmitMatchContext(det_ctx, s, engine->sm_list, buffer->inspect,
                    buffer->inspect_len);
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
""",
    )

    # Packet sticky buffer inspect.
    replace_once(
        engine_c,
        """    const bool match = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx, s, engine->smd, p,
            p->flow, buffer->inspect, buffer->inspect_len, 0, ci_flags,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER);
    if (match) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
""",
        """    const bool match = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx, s, engine->smd, p,
            p->flow, buffer->inspect, buffer->inspect_len, 0, ci_flags,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER);
    if (match) {
        XbitsEmitMatchContext(det_ctx, s, list_id, buffer->inspect, buffer->inspect_len);
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
""",
    )

    replace_once(
        lua_c,
        """    lua_pushstring(tlua->luastate, lua->buffername); /* stack at -2 */
    LuaPushStringBuffer(tlua->luastate, (const uint8_t *)buffer, (size_t)buffer_len);
    lua_settable(tlua->luastate, -3);

    /* restore configured bytes limit and account for the allocations done for the setup above. */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCLuaSbUpdateBytesLimit(tlua->luastate);
    int r = DetectLuaRunMatch(det_ctx, lua, tlua);
    /* restore configured limit */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCReturnInt(r);
""",
        """    lua_pushstring(tlua->luastate, lua->buffername); /* stack at -2 */
    LuaPushStringBuffer(tlua->luastate, (const uint8_t *)buffer, (size_t)buffer_len);
    lua_settable(tlua->luastate, -3);

    /* restore configured bytes limit and account for the allocations done for the setup above. */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCLuaSbUpdateBytesLimit(tlua->luastate);
    int r = DetectLuaRunMatch(det_ctx, lua, tlua);
    /* restore configured limit */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    if (r)
        XbitsEmitMatchContextNamed(det_ctx, s, "lua", buffer, buffer_len);
    SCReturnInt(r);
""",
    )

    replace_once(
        lua_c,
        """    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, p->flow, p, s, flags);

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    /* restore configured bytes limit and account for the allocations done for the setup above. */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCLuaSbUpdateBytesLimit(tlua->luastate);
    int r = DetectLuaRunMatch(det_ctx, lua, tlua);
    /* restore configured limit */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCReturnInt(r);
""",
        """    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, p->flow, p, s, flags);

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    /* restore configured bytes limit and account for the allocations done for the setup above. */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCLuaSbUpdateBytesLimit(tlua->luastate);
    int r = DetectLuaRunMatch(det_ctx, lua, tlua);
    /* restore configured limit */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    /* No buffer export here: Lua match() inspects app-layer state via APIs,
       C has no single exact buffer to export. Do NOT approximate with p->payload. */
    SCReturnInt(r);
""",
    )

    replace_once(
        lua_c,
        """    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, f, NULL, s, flags);

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    /* restore configured bytes limit and account for the allocations done for the setup above. */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCLuaSbUpdateBytesLimit(tlua->luastate);
    int r = DetectLuaRunMatch(det_ctx, lua, tlua);
    /* restore configured limit */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCReturnInt(r);
""",
        """    LuaExtensionsMatchSetup(tlua->luastate, lua, det_ctx, f, NULL, s, flags);

    lua_getglobal(tlua->luastate, "match");
    lua_newtable(tlua->luastate); /* stack at -1 */

    /* restore configured bytes limit and account for the allocations done for the setup above. */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    SCLuaSbUpdateBytesLimit(tlua->luastate);
    int r = DetectLuaRunMatch(det_ctx, lua, tlua);
    /* restore configured limit */
    SCLuaSbRestoreBytesLimit(tlua->luastate, cfg_limit);
    /* No buffer export here: Lua app-tx match inspects app-layer state via APIs.
       Do NOT approximate with p->payload. */
    SCReturnInt(r);
""",
    )

    print("xbits match-context patch applied to", root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
