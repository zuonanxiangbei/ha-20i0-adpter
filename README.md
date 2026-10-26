# ha-20i0-adpter — HA 设备接入华为智慧生活（hwhomebridge2）

把 Home Assistant 里的设备桥接到**华为智慧生活 App / 小艺语音**。
基于上游 [`Wangxiaokang666-666/ha_hwhomebridge`](https://github.com/Wangxiaokang666-666/ha_hwhomebridge) v1.0.1 的 proot/noexec 兼容修改版，域名为 `hwhomebridge2`，与原版 `hwhomebridge` 互不冲突。

> **台灯适配器说明**：本仓库早先托管 `huawei_20i0_adapter`（欧普台灯 Pro 适配器安装器）。
> 因 HACS 一个仓库只能安装 `custom_components/` 下的**第一个**集成，该适配器已从 `custom_components/` 移出，
> 文件保留在仓库 `huawei_20I0_installer/` 目录，需要时手动拷贝。

> **⚠️ 非 Home Assistant 官方集成**，处于持续迭代中，存在适配兼容与稳定性风险，请勿直接用于生产环境。

---

## 安装（HACS）

1. HACS → **集成** → 右上角 **⋮** → **自定义仓库**
2. 仓库地址填：`https://github.com/zuonanxiangbei/ha-20i0-adpter`，类别选**集成**
3. 在集成列表找到「**华为智慧生活桥接**」→ 下载 → **重启 HA**
4. 设置 → 设备与服务 → **添加集成** → 搜索 `HuaweiHome Bridge 2`

> 注意：本仓库的 `custom_components/` 下现在**只有** `hwhomebridge2` 一个集成，HACS 会正确安装它。
> 若 HACS 里之前添加过本仓库并装成了别的集成，**先删除自定义仓库再重新添加一次**，强制刷新元数据。

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
2. **aarch64 / amd64 两个架构的 `.so` 均内置于本仓库**（aarch64 = 9,866,752 字节，
   amd64 = 2,383,384 字节），无需依赖原版 `hwhomebridge` 安装目录。
   若本目录缺文件，运行时仍会回退到 `/config/custom_components/hwhomebridge/hilink_bridge/lib/<arch>/` 读取。
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
