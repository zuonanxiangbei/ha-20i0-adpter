# ha-20i0-adpter — HA 华为生态集成合集

本仓库包含两个 Home Assistant 自定义集成：

| 集成 | 作用 | 状态 |
|---|---|---|
| `hwhomebridge2` | 把 HA 里的设备桥接到**华为智慧生活 App / 小艺语音**（基于上游 `Wangxiaokang666-666/ha_hwhomebridge` v1.0.1 的 proot/noexec 兼容修改版） | 主力 |
| `huawei_20i0_adapter` | 欧普智能台灯 Pro（prodId `20I0`）适配器安装器 | 备用 / legacy |

> **⚠️ 非 Home Assistant 官方集成**，处于持续迭代中，存在适配兼容与稳定性风险，请勿直接用于生产环境。

---

## 安装（HACS）

1. HACS → **集成** → 右上角 **⋮** → **自定义仓库**
2. 仓库地址填：`https://github.com/zuonanxiangbei/ha-20i0-adpter`，类别选**集成**
3. 在集成列表找到「**华为智慧生活桥接**」→ 下载 → **重启 HA**
4. 设置 → 设备与服务 → **添加集成** → 搜索 `HuaweiHome Bridge 2`

> 注意：下载本仓库会同时安装 `huawei_20i0_adapter`（台灯适配器安装器）。
> 如不需要，忽略即可——不配置它不会产生任何实体或副作用。

---

## hwhomebridge2 — HA 设备接入华为智慧生活

控制链路：**华为智慧生活 App / 小艺 → 华为云 → HiLink SDK（.so）→ HA REST/WS API**。

### 使用流程

1. 添加集成 `HuaweiHome Bridge 2`，按提示完成配置
2. 集成会生成一个 **8 位 PIN**（5 分钟有效），同时 HA 侧设备自动注册为虚拟 HiLink 设备
3. 手机打开**华为智慧生活 App** → 右上角 **"+"** → 添加设备 → 选择 **"HA 网关"**
4. 输入 PIN 完成绑定，之后即可在 App / 小艺中看到并控制 HA 设备

### 本 Fork 说明（proot / noexec 兼容版）

域名为 `hwhomebridge2`，与原版 `hwhomebridge` 互不冲突，可并存。

1. **`.so` 加载三级回退**：直接加载失败（`Permission denied`，`/config` 位于 noexec 挂载时出现）→ 先 `chmod 755` 重试 → 仍失败则拷贝到 `/tmp`、`/usr/local/lib` 等可执行路径后再加载。
2. **不含 aarch64 `.so` 二进制**：运行时自动回退到原版 `hwhomebridge` 安装目录
   （`/config/custom_components/hwhomebridge/hilink_bridge/lib/<arch>/`）读取。
   **因此请勿卸载原版 hwhomebridge 集成**（禁用/删除其配置条目即可，文件需保留）。
   amd64 `.so` 已包含在本仓库内（迁移到 x86 主机时使用）。
3. `.storage` 运行时目录改为 `hwhomebridge2/config`，与原版隔离。

### 已知限制

- HiLink 网关发现依赖 **UDP 5683/5686 + 加入 IPv4 组播组 238.238.238.238**；
  在安卓 proot 等容器环境下组播可能被系统过滤，若 App 的 LAN 发现不通，
  依赖 PIN + 华为云绑定通道完成绑定。
- 设备能力映射见 `docs/adapter-guide.md`，默认适配器覆盖 6 个品类
  （灯 / 开关 / 插座 / 窗帘 / 风扇 / 取暖器），米家系设备有专用适配 JSON。

---

## huawei_20i0_adapter — 欧普台灯 Pro 适配器安装器（legacy）

`ha-huawei-smarthome`（xiasi0）的设备适配器是一个 prodId 一个文件，
新增 prodId `20I0`（欧普智能台灯 Pro，MT615-D20WTT）需要手动放置适配文件。
本集成的作用就是在配置时自动把 `prod_20I0.py` 拷到
`custom_components/huawei_smarthome/device_adapters/` 下，重启 HA 后生效。

**前提**：已安装 `ha-huawei-smarthome` 集成。当前 HA 环境未安装该集成时，
配置本安装器无意义，忽略即可。
