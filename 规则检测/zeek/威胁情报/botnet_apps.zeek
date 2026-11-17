##! 僵尸网络/挖矿应用元数据（由 convert_probe_zeek.py 生成）。
##! 仅用于告警名称/危险等级归一化，检测依赖 Zeek 协议/行为事件。
module XbitsBotnet;

export {
    type AppInfo: record {
        danger_class: count;
        drop: bool;
        desc: string;
    };

    global botnet_apps: table[string] of AppInfo = {
        ["IRC"] = AppInfo($danger_class=3, $drop=F, $desc="主机%u.%u.%u.%u使用IRC协议进行通信，可能已中毒"),
        ["比特币"] = AppInfo($danger_class=3, $drop=F, $desc="主机%u.%u.%u.%u存在比特币挖矿行为，可能已被僵尸网络控制"),
        ["Gh0st木马"] = AppInfo($danger_class=1, $drop=T, $desc="主机%u.%u.%u.%u感染了Gh0st木马"),
        ["HFS网络文件服务器"] = AppInfo($danger_class=1, $drop=F, $desc="主机%u.%u.%u.%u访问了HFS服务器，访问URL：%s，可能已被黑客攻破"),
        ["Studio54木马"] = AppInfo($danger_class=2, $drop=F, $desc="主机%u.%u.%u.%u感染了Studio54木马"),
    };
}
