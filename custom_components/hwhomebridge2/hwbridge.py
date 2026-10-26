"""
hwbridge.py - 核心桥接逻辑

重构版本，使用 ServiceRouter + VirtualDevice 架构：
- ServiceRouter 管理产品注册、匹配、路由
- VirtualDevice 聚合同一 HA device 下的多个 entity
- SN 管理从 1:1 (entity) 演进为 1:N (VirtualDevice)

兼容性：
- 保留原有的 C 回调接口 (RegHomeAssistantPyCB)
- 保留原有的 C library 调用方式
- 新增的模块不影响 C 侧的任何接口
"""

import os
import shutil
import asyncio
import platform
import psutil
import socket
import json
import threading
import logging
from ctypes import *

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers.device_registry import EVENT_DEVICE_REGISTRY_UPDATED
from homeassistant.const import (
    EVENT_HOMEASSISTANT_STARTED,
    EVENT_STATE_CHANGED
)

from .service_router import ServiceRouter
from .pin_manager import PINManager
from .virtual_device import SNManager
from .const import SKIP_PLATFORMS, DOMAIN

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 全局变量
# ---------------------------------------------------------------------------

bridge_work = False
start_work = False
ghass = None
lib = None
service_router = None  # ServiceRouter 实例（替代原来的 light_plt/fan_plt 等）

hilink_bridge_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hilink_bridge")
# 运行时用户态目录，指向 HA 持久存储区 .storage/hwhomebridge/
# C SDK (HILINK_CONFIG_DIR)、device_ac、new_device.txt 均落此目录
hilink_config_dir = None
hilink_cfg_files = ("bridge.cfg",
                     "bridge_bak.cfg",
                     "hilink_cert.cfg",
                     "hilink_cert_bak.cfg",
                     "pidMap.cfg",
                     "pidMap_bak.cfg",
                     "subDevInfo.cfg",
                     "subDevInfo_bak.cfg",
                     "timer.cfg",
                     "timer_bak.cfg")

# 设备持久化（保存 device_id 而非 entity_id）
# 运行时在 start_hw_hilink_bridge 中拼接到 hilink_config_dir 下，避免污染 config 根目录
saved_device_file = None
excluded_devices_file = None
registered_device_ids = set()  # 已注册到 HiLink 的 device_id 集合
saved_device_ids = set()        # 从持久化文件恢复的 device_id 集合

# 状态缓冲区池：保持 bytes 对象引用，防止被垃圾回收导致 C 侧访问悬空指针
# C 侧会在回调返回时拷贝内容，Python 侧保持引用直到下次调用或进程结束
_char_state_bytes = {}  # {(sn, svc_id): bytes_object}

# 设备注册表监听器：device_id -> cancel callback
# 用于监听 HA device registry 的 disabled_by 变化（用户在 UI 上禁用/启用设备）
_cancel_device_registry_listeners = {}  # {device_id: cancel_callback}

# 禁用设备集合：存储被用户在 HA UI 上禁用的设备 SN
_disabled_device_sns = set()

# 排除设备集合：存储被设备管理页取消勾选的设备 SN（重启后不注册到 HiLink）
_excluded_device_sns = set()

# 设备发现锁：防止 OnBridgeStatusCB 多次触发并发发现
_discovery_lock = threading.Lock()
_discovery_in_progress = False


# ---------------------------------------------------------------------------
# 初始化
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# proot 兼容补丁：伪造网卡 MAC
# ---------------------------------------------------------------------------
# 现象：proot 在 syscall 层拒绝 SIOCGIFHWADDR（EPERM），SDK 取不到网卡 MAC。
# 后果：hilink_m2m 状态机置错 -> devStatus 卡在 4 -> 5683 永不监听 -> App 搜不到网关。
# 做法：解析 .so 的 ELF 重定位表，找到 ioctl 的 PLT 槽，把它改指向本进程的
#       Python 回调；对 SIOCGIFHWADDR 返回一个固定的 MAC，其余原样透传。
# 实测：打补丁后 devStatus 4 -> 9，5683 单播监听建立。
FAKE_MAC = bytes.fromhex("021122334455")   # 本地管理位 MAC，避免与真实设备冲突
_IOCTL_CB = None                            # 必须保活，否则回调被 GC 后崩溃


def _elf_plt_offset(so_path: str, symname: str):
    """从 ELF 里取 symname 的 PLT/GOT 重定位 r_offset（相对基址），找不到返回 None。"""
    import struct as _st

    with open(so_path, "rb") as f:
        d = f.read()
    if d[:4] != b"\x7fELF":
        return None

    e_shoff = _st.unpack_from("<Q", d, 0x28)[0]
    e_shentsize = _st.unpack_from("<H", d, 0x3A)[0]
    e_shnum = _st.unpack_from("<H", d, 0x3C)[0]
    e_shstrndx = _st.unpack_from("<H", d, 0x3E)[0]

    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        (name, typ, flags, addr, off, size, link, info,
         align, entsize) = _st.unpack_from("<IIQQQQIIQQ", d, o)
        secs.append({"name": name, "type": typ, "off": off, "size": size,
                     "link": link, "entsize": entsize})

    shstr_off = secs[e_shstrndx]["off"]

    def _sname(x):
        b = shstr_off + x
        return d[b:d.index(b"\0", b)].decode("utf-8", "replace")

    for sct in secs:
        sct["sname"] = _sname(sct["name"])
    byname = {sct["sname"]: sct for sct in secs}

    def _sym(nm_off, str_off, idx):
        o = nm_off + idx * 24
        st_name = _st.unpack_from("<I", d, o)[0]
        b = str_off + st_name
        return d[b:d.index(b"\0", b)].decode("utf-8", "replace")

    for rname in (".rela.plt", ".rela.dyn"):
        rs = byname.get(rname)
        if not rs:
            continue
        ds = secs[rs["link"]]
        dy = secs[ds["link"]]
        for i in range(rs["size"] // 24):
            o = rs["off"] + i * 24
            r_offset, r_info, _add = _st.unpack_from("<QQq", d, o)
            nm = _sym(ds["off"], dy["off"], r_info >> 32)
            if nm == symname:
                return r_offset
    return None


def _so_base(so_path: str):
    """从 /proc/self/maps 找 .so 的加载基址。"""
    base = None
    with open("/proc/self/maps", "r") as f:
        for line in f:
            ln = line.rstrip("\n")
            if not ln.endswith(so_path):
                continue
            parts = ln.split()
            try:
                start = int(parts[0].split("-")[0], 16)
                off = int(parts[2], 16)
            except Exception:
                continue
            b = start - off
            if base is None or b < base:
                base = b
    return base


def _patch_ioctl_mac(so_path: str, mac: bytes = FAKE_MAC) -> bool:
    """把 .so 的 ioctl PLT 槽换成 Python 回调，对 SIOCGIFHWADDR 返回伪造 MAC。"""
    global _IOCTL_CB
    import ctypes as _ct

    off = _elf_plt_offset(so_path, "ioctl")
    if off is None:
        _LOGGER.error("MACPATCH| 未在 ELF 中找到 ioctl 重定位，跳过")
        return False
    base = _so_base(so_path)
    if base is None:
        _LOGGER.error("MACPATCH| 未在 /proc/self/maps 找到基址，跳过")
        return False

    try:
        libc = _ct.CDLL(None)          # 本进程自己的 libc（实测可用）
    except Exception:
        libc = _ct.CDLL("libc.so.6")
    real_ioctl = libc.ioctl
    slot = base + off
    cb_t = _ct.CFUNCTYPE(_ct.c_int, _ct.c_int, _ct.c_ulong, _ct.c_void_p)

    def _fake(fd, req, arg):
        try:
            if req == 0x8927 and arg:      # SIOCGIFHWADDR
                buf = (_ct.c_char * 40).from_address(arg)
                buf[16:18] = (1).to_bytes(2, "little")   # sa_family = ARPHRD_ETHER
                buf[18:24] = mac
                return 0
            return real_ioctl(fd, req, arg)
        except Exception:
            return -1

    _IOCTL_CB = cb_t(_fake)
    newval = _ct.cast(_IOCTL_CB, _ct.c_void_p).value
    page = slot & ~0xFFF
    rc = libc.mprotect(_ct.c_void_p(page), _ct.c_size_t(0x1000), 3)
    if rc != 0:
        _LOGGER.error("MACPATCH| mprotect 失败 rc=%s" % rc)
        return False
    old = _ct.c_void_p.from_address(slot).value
    _ct.c_void_p.from_address(slot).value = newval
    libc.mprotect(_ct.c_void_p(page), _ct.c_size_t(0x1000), 1)
    now = _ct.c_void_p.from_address(slot).value
    _LOGGER.error("MACPATCH| base=%s slot=%s old=%s new=%s mac=%s ok=%s"
                  % (hex(base), hex(slot), hex(old or 0), hex(now or 0),
                     ":".join("%02x" % b for b in mac), now == newval))
    return now == newval


async def start_hw_hilink_bridge(hass: HomeAssistant):
    """启动 HiLink 桥接"""
    global ghass, lib, service_router

    ghass = hass

    # ===== 环境自举（musl/Alpine 需要 gcompat 才能加载 glibc 编译的 .so）=====
    try:
        import subprocess as _sp

        def _run(cmd, timeout=60):
            try:
                _p = _sp.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                return ("rc=%s | out=%s | err=%s" % (
                    _p.returncode,
                    (_p.stdout or "").strip()[:500],
                    (_p.stderr or "").strip()[:300]))
            except Exception as _e:
                return "EXC %s" % _e

        _LOGGER.error("PROBE|0 uname: " + _run("uname -a; id"))
        _LOGGER.error("PROBE|1 os: " + _run("cat /etc/alpine-release 2>&1; head -3 /etc/os-release 2>&1"))
        _LOGGER.error("PROBE|2 mounts: " + _run("mount | grep -E ' /config | /tmp ' | head -5"))
        _LOGGER.error("PROBE|3 loaders: " + _run("ls -l /lib/ld-linux-aarch64.so.1 /lib/ld-musl-* 2>&1"))
        _LOGGER.error("PROBE|4 libs: " + _run("ls -l /usr/lib/libstdc++.so.6 /usr/lib/libgcc_s.so.1 /lib/libatomic.so.1 2>&1"))
        _LOGGER.error("PROBE|5 pkg: " + _run("apk info -e gcompat libstdc++ libgcc libatomic 2>&1"))

        _marker = hass.config.path(".storage", "hwhomebridge2", ".apk_bootstrap_done")
        _need = (not os.path.exists("/lib/ld-linux-aarch64.so.1")
                 and not os.path.exists("/lib/ld-linux-x86-64.so.2"))
        if _need and not os.path.exists(_marker):
            _LOGGER.error("PROBE|6 apk add: " + _run(
                "apk add --no-cache gcompat libstdc++ libgcc libatomic 2>&1", timeout=300))
            _LOGGER.error("PROBE|7 after: " + _run("ls -l /lib/ld-linux-aarch64.so.1 2>&1"))
            try:
                os.makedirs(os.path.dirname(_marker), exist_ok=True)
                with open(_marker, "w") as _f:
                    _f.write("1")
            except Exception:
                pass
        else:
            _LOGGER.error("PROBE|6 apk add skipped (loader present or already attempted)")
    except Exception as _e:
        _LOGGER.error("PROBE|bootstrap EXC: %s" % _e)

    # 初始化 ServiceRouter
    service_router = ServiceRouter()
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'config', 'product_registry.json')
    result = await service_router.load_product_registry(config_path)
    if result:
        _LOGGER.info(f"Product registry loaded successfully, "
                      f"{service_router.registry.get_product_count()} products, "
                      f"{service_router.registry.get_default_count()} defaults, "
                      f"{service_router.registry.get_adapter_count()} vendor adapters")
    else:
        _LOGGER.error("Failed to load product registry, device matching will not work")

    global hilink_config_dir, saved_device_file, excluded_devices_file

    hilink_config_dir = hass.config.path('.storage', 'hwhomebridge2', 'config')

    os.makedirs(hilink_config_dir, exist_ok=True)

    # 将随插件发布的固定配置文件复制到运行时目录，C SDK 启动时需要这些文件
    # 始终覆盖：升级后固定配置可能有更新
    fixed_cfg_src_dir = os.path.join(hilink_bridge_path, 'config')
    for fname in ('hilink.cfg', 'hilink_bak.cfg'):
        src = os.path.join(fixed_cfg_src_dir, fname)
        dst = os.path.join(hilink_config_dir, fname)
        if os.path.exists(src):
            shutil.copy2(src, dst)

    os.environ['HILINK_CONFIG_DIR'] = hilink_config_dir + '/'
    saved_device_file = os.path.join(hilink_config_dir, 'new_device.txt')
    excluded_devices_file = os.path.join(hilink_config_dir, 'excluded_devices.txt')
    _LOGGER.info(f"hwhomebridge runtime dir: {hilink_config_dir}")

    # 加载 C 库（按 CPU 架构选择对应的 so）
    machine = platform.machine() or ""
    arch = ""
    if machine.lower() in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine.lower() in ("aarch64", "arm64"):
        arch = "aarch64"

    if not arch:
        _LOGGER.error(f"Unsupported CPU architecture: {machine}, bridge will not start")
        return

    so_path = os.path.join(hilink_bridge_path, "lib", arch, "libhilink_bridge.so")
    if not os.path.exists(so_path):
        # 本 fork 不含 .so 二进制，回退到原版 hwhomebridge 安装目录读取
        alt_path = os.path.join(
            hass.config.path("custom_components", "hwhomebridge",
                             "hilink_bridge", "lib", arch),
            "libhilink_bridge.so",
        )
        if os.path.exists(alt_path):
            _LOGGER.error(f"PROBE| so not in fork, fallback to original install: {alt_path}")
            so_path = alt_path
        else:
            _LOGGER.error(f"SO file not found: {so_path}, bridge will not start")
            return

    _LOGGER.info(f"Loading hilink bridge so: {so_path}")

    # ===== proot/noexec 兼容补丁（本 fork 新增）=====
    # /config 可能位于 noexec 挂载（安卓共享存储），dlopen 直接报 Permission denied。
    # 依次尝试：直接加载 -> chmod 755 重试 -> 拷贝到可执行路径加载。
    def _load_so(path):
        try:
            return cdll.LoadLibrary(path)
        except Exception as e:
            _LOGGER.error(f"Failed to load so {path}: {e}")
            return None

    loaded_from = so_path
    lib = _load_so(so_path)

    if lib is None:
        try:
            os.chmod(so_path, 0o755)
            lib = _load_so(so_path)
            if lib is not None:
                _LOGGER.error("PROBE| so loaded after chmod 755")
        except Exception as e:
            _LOGGER.error(f"PROBE| chmod retry failed: {e}")

    if lib is None:
        for base in ("/tmp", "/var/tmp", "/usr/local/lib", "/usr/lib", "/root"):
            try:
                if not os.path.isdir(base):
                    continue
                dst = os.path.join(base, f"libhilink_bridge_{arch}.so")
                shutil.copy2(so_path, dst)
                os.chmod(dst, 0o755)
                lib = _load_so(dst)
                if lib is not None:
                    loaded_from = dst
                    _LOGGER.error(f"PROBE| so loaded from executable copy: {dst}")
                    break
            except Exception as e:
                _LOGGER.error(f"PROBE| load from {base} failed: {e}")
                continue

    if lib is None:
        _LOGGER.error(f"Failed to load so {so_path}: all attempts failed, bridge will not start")
        return
    _LOGGER.info(f"open hilink bridge so success.")
    try:
        _patch_ioctl_mac(loaded_from)
    except Exception as _e:
        _LOGGER.error("MACPATCH| EXC %s" % _e)

    # 设置A_C（48字节随机字符串）
    # 优先从 device_ac 文件读取已保存的 ac，避免每次启动重新生成
    device_ac_file = os.path.join(hilink_config_dir, 'device_ac')
    ac = _load_or_create_ac(device_ac_file)
    ac_value = (c_ubyte * 48)(*ac)
    lib.HILINK_SetAutoAc(ac_value, 48)

    # 设置返回 const char* 的函数的 restype，避免 ctypes 默认按 int 截断指针
    lib.GetGatewaySN.restype = c_char_p

    # 注册 C 回调
    register_hilink_callbacks()

    # 设置 ServiceRouter 的依赖
    service_router.set_hass(hass)
    service_router.set_lib(lib)

    # ===== 网卡探测 + 指定首选网卡 =====
    # proot 环境里 netlink / getifaddrs 不可用（ip 命令报 Socket not connected，
    # /proc/net/* 全是 Permission denied），SDK 可能因此拿不到本机网卡而不开监听。
    # 这里用不打 netlink 的 SIOCGIFCONF ioctl 枚举网卡，并显式告诉 SDK 用哪块。
    _pickname = None
    try:
        import struct as _st
        import fcntl as _fc
        import array as _ar

        _ifaces = []
        try:
            _sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _maxlen = 8192
            _buf = _ar.array("B", b"\0" * _maxlen)
            _SIOCGIFCONF = 0x8912
            _ifc = _st.pack("i4xL", _maxlen, _buf.buffer_info()[0])
            _res = _fc.ioctl(_sk.fileno(), _SIOCGIFCONF, _ifc)
            _outlen = _st.unpack("i4xL", _res)[0]
            _raw = _buf.tobytes()[:_outlen]
            for _i in range(0, len(_raw), 40):
                _rec = _raw[_i:_i + 40]
                if len(_rec) < 40:
                    break
                _nm = _rec[:16].split(b"\0")[0].decode("utf-8", "replace")
                _ip = socket.inet_ntoa(_rec[20:24])
                if _nm:
                    _ifaces.append((_nm, _ip))
            _sk.close()
        except Exception as _e:
            _LOGGER.error("IFACE| SIOCGIFCONF failed: %s" % _e)

        try:
            _LOGGER.error("IFACE| if_nameindex: %s" % (socket.if_nameindex(),))
        except Exception as _e:
            _LOGGER.error("IFACE| if_nameindex failed: %s" % _e)

        _LOGGER.error("IFACE| SIOCGIFCONF list: %s" % (_ifaces,))

        # 选择优先级：wlan0 > wlan* > eth* > ap* > 其他（排除 lo）
        # 注：proot 里 SIOCGIFCONF 常只返回 lo，故以 if_nameindex 为主。
        try:
            _names = [n for _, n in socket.if_nameindex()]
        except Exception as _e:
            _LOGGER.error("IFACE| if_nameindex retry failed: %s" % _e)
            _names = [n for n, _ in _ifaces]

        _cands = []
        for _p in ("wlan0",):
            if _p in _names:
                _cands.append(_p)
        for _pfx in ("wlan", "eth", "ap"):
            for _n in _names:
                if _n.startswith(_pfx) and _n not in _cands:
                    _cands.append(_n)
        for _n in _names:
            if _n != "lo" and _n not in _cands:
                _cands.append(_n)

        _pickname = _cands[0] if _cands else None
        _LOGGER.error("IFACE| candidates=%s -> pick=%r" % (_cands, _pickname))

        if _pickname is not None:
            try:
                lib.HILINK_SetPreferredIface.argtypes = [c_char_p]
                lib.HILINK_SetPreferredIface.restype = c_int
                _r = lib.HILINK_SetPreferredIface(_pickname.encode())
                _LOGGER.error("IFACE| SetPreferredIface(%r) rlt=%r" % (_pickname, _r))
            except Exception as _e:
                _LOGGER.error("IFACE| SetPreferredIface EXC %s" % _e)
        else:
            _LOGGER.error("IFACE| no usable interface detected")
    except Exception as _e:
        _LOGGER.error("IFACE| probe EXC %s" % _e)

    # 启动 C 库
    def _fd_socket_snapshot():
        """枚举本进程所有 socket fd：类型 / 域 / 本地地址 / 对端。
        绕开 /proc（proot 里 /proc/<pid>/fd 不可读），直接 fstat + getsockname，
        是唯一能看清「SDK 到底建了哪些 socket」的手段。"""
        import stat as _stat
        import ctypes as _ct
        _out = {}
        try:
            _lc = _ct.CDLL("libc.so")
        except Exception:
            try:
                _lc = _ct.CDLL(None)
            except Exception:
                return {"-": {"err": "no libc"}}
        for _fd in range(0, 1024):
            try:
                _stt = os.fstat(_fd)
            except OSError:
                continue
            if not _stat.S_ISSOCK(_stt.st_mode):
                continue
            _info = {"ino": _stt.st_ino}
            for _name, _lvl, _opt, _ln_ in (("type", 1, 3, 4),
                                            ("domain", 1, 39, 4)):
                _v = _ct.c_int(0)
                _vl = _ct.c_int(_ln_)
                try:
                    _rc = _lc.getsockopt(_ct.c_int(_fd), _ct.c_int(_lvl),
                                         _ct.c_int(_opt), _ct.byref(_v),
                                         _ct.byref(_vl))
                    _info[_name] = _v.value if _rc == 0 else "rc=%s" % _rc
                except Exception:
                    _info[_name] = "EXC"
            # SO_ERROR + TCP_INFO.tcpi_state：判断到路由器的连接到底通没通
            _eb = _ct.c_int(0)
            _el = _ct.c_int(4)
            try:
                _rc = _lc.getsockopt(_ct.c_int(_fd), _ct.c_int(1), _ct.c_int(4),
                                     _ct.byref(_eb), _ct.byref(_el))
                if _rc == 0:
                    _info["so_err"] = _eb.value
            except Exception:
                pass
            _tb = _ct.create_string_buffer(128)
            _tl = _ct.c_int(128)
            try:
                _rc = _lc.getsockopt(_ct.c_int(_fd), _ct.c_int(6), _ct.c_int(11),
                                     _tb, _ct.byref(_tl))
                if _rc == 0 and _tl.value >= 1:
                    _stt_s = _tb.raw[0]
                    _names = {1: "ESTAB", 2: "SYN_SENT", 3: "SYN_RECV",
                              4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
                              7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
                              10: "LISTEN", 11: "CLOSING"}
                    _info["tcp"] = _names.get(_stt_s, str(_stt_s))
            except Exception:
                pass
            for _name, _fn in (("local", _lc.getsockname),
                               ("peer", _lc.getpeername)):
                _buf = _ct.create_string_buffer(128)
                _ln = _ct.c_int(128)
                try:
                    _rc = _fn(_ct.c_int(_fd), _buf, _ct.byref(_ln))
                    if _rc != 0:
                        _info[_name] = "-"
                        continue
                    _raw = _buf.raw[:_ln.value]
                    _fam = int.from_bytes(_raw[0:2], "little")
                    _port = int.from_bytes(_raw[2:4], "big")
                    if _fam == 2:
                        _ip = socket.inet_ntoa(_raw[4:8])
                    elif _fam == 10:
                        _ip = socket.inet_ntop(socket.AF_INET6, _raw[8:24])
                    else:
                        _ip = "fam%s" % _fam
                    _info[_name] = "%s:%s" % (_ip, _port)
                except Exception:
                    _info[_name] = "EXC"
            _out[_fd] = _info
        return _out

    def _thread_snapshot():
        """返回 [(tid, comm), ...]，用于判断 SDK 是否真的起了后台线程"""
        _out = []
        try:
            for _tid in os.listdir("/proc/self/task"):
                _comm = ""
                try:
                    with open("/proc/self/task/%s/comm" % _tid, "r") as _fh:
                        _comm = _fh.read().strip()
                except Exception:
                    pass
                _out.append((_tid, _comm))
        except Exception as _e:
            _out.append(("-", "EXC %s" % _e))
        return _out

    _sock_before = _fd_socket_snapshot()
    _LOGGER.error("PROBE|U0 sockets_before_main=%d" % len(_sock_before))
    _thr_before = _thread_snapshot()
    _LOGGER.error("PROBE|T0 threads_before=%d %s" % (len(_thr_before), _thr_before))

    rlt = lib.main()
    _LOGGER.info(f"start hilink bridge rlt={rlt}.")
    try:
        _thr_mid = _thread_snapshot()
        _LOGGER.error("PROBE|T1 threads_after_main=%d %s" % (len(_thr_mid), _thr_mid))
    except Exception as _e:
        _LOGGER.error("PROBE|T1 EXC %s" % _e)

    # ===== 网络发现诊断（lib.main 之后，SDK 应已开始监听）=====
    try:
        import time as _time
        import subprocess as _sp2
        import socket as _sock
        import struct as _struct

        def _run2(cmd, timeout=30):
            try:
                _p = _sp2.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
                return ("rc=%s | out=%s | err=%s" % (
                    _p.returncode,
                    (_p.stdout or "").strip()[:1600],
                    (_p.stderr or "").strip()[:200]))
            except Exception as _e:
                return "EXC %s" % _e

        await asyncio.sleep(4)  # 等 SDK 线程起监听
        _LOGGER.error("PROBE|A main() rlt=%r" % (rlt,))
        _LOGGER.error("PROBE|B udp: " + _run2("cat /proc/net/udp 2>&1 | head -30"))
        _LOGGER.error("PROBE|C addr: " + _run2("ip -o -4 addr 2>&1 | head -8; cat /proc/net/route 2>&1 | head -5"))
        _LOGGER.error("PROBE|D igmp: " + _run2("cat /proc/net/igmp 2>&1 | head -15"))
        _LOGGER.error("PROBE|E rundir: " + _run2("ls -la /config/.storage/hwhomebridge2/config/ 2>&1"))

        # SDK 状态快照：线程 / fd / 网关 SN / 设备状态
        try:
            _thr_now = _thread_snapshot()
            _LOGGER.error("PROBE|H threads_now=%d %s" % (len(_thr_now), _thr_now))
        except Exception as _e:
            _LOGGER.error("PROBE|H threads EXC %s" % _e)
        try:
            _LOGGER.error("PROBE|I fds: " + _run2(
                "ls -l /proc/%d/fd 2>&1 | head -60" % os.getpid()))
        except Exception as _e:
            _LOGGER.error("PROBE|I fds EXC %s" % _e)
        try:
            _gsn = lib.GetGatewaySN()
            _LOGGER.error("PROBE|J gatewaySN=%r" % (_gsn,))
        except Exception as _e:
            _LOGGER.error("PROBE|J gatewaySN EXC %s" % _e)
        try:
            _dstat = lib.HILINK_GetDevStatus()
            _LOGGER.error("PROBE|K devStatus=%r" % (_dstat,))
        except Exception as _e:
            _LOGGER.error("PROBE|K devStatus EXC %s" % _e)

        # ===== 网卡 MAC / IP：SDK 靠 ioctl 拿 MAC，拿不到就整个链路不启动 =====
        _myip = None
        try:
            import fcntl as _fc2
            _skx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for _nm in [x for x in (_pickname, "wlan0", "lo") if x]:
                _req = _nm.encode().ljust(16, b"\0") + b"\0" * 24  # struct ifreq 40B
                try:
                    _rb = _fc2.ioctl(_skx.fileno(), 0x8927, _req)  # SIOCGIFHWADDR
                    _mac = ":".join("%02x" % b for b in _rb[18:24])
                    _fam = int.from_bytes(_rb[16:18], "little")
                    _LOGGER.error("PROBE|V SIOCGIFHWADDR(%s) = %s fam=%d" % (_nm, _mac, _fam))
                except Exception as _e:
                    _LOGGER.error("PROBE|V SIOCGIFHWADDR(%s) FAIL %s" % (_nm, _e))
                try:
                    _rb = _fc2.ioctl(_skx.fileno(), 0x8915, _req)  # SIOCGIFADDR
                    _ip = socket.inet_ntoa(_rb[20:24])
                    if _nm == _pickname:
                        _myip = _ip
                    _LOGGER.error("PROBE|V SIOCGIFADDR(%s) = %s" % (_nm, _ip))
                except Exception as _e:
                    _LOGGER.error("PROBE|V SIOCGIFADDR(%s) FAIL %s" % (_nm, _e))
            _skx.close()
        except Exception as _e:
            _LOGGER.error("PROBE|V EXC %s" % _e)

        # 有些版本的 SDK 期待「IP 字符串」而不是网卡名，再试一次
        if _myip:
            try:
                _ri = lib.HILINK_SetPreferredIface(_myip.encode())
                _LOGGER.error("IFACE| SetPreferredIface(by IP %r) rlt=%r" % (_myip, _ri))
            except Exception as _e:
                _LOGGER.error("IFACE| SetPreferredIface(by IP) EXC %s" % _e)

        # 云侧可达性：SDK 若连不上华为云，可能直接放弃起监听
        try:
            _h = "query.hicloud.com"
            _LOGGER.error("PROBE|L dns: " + _run2(
                "getent hosts %s 2>&1; cat /etc/resolv.conf 2>&1 | head -5" % _h))
            try:
                _c = _sock.create_connection((_h, 443), timeout=6)
                _c.close()
                _LOGGER.error("PROBE|M tcp %s:443 OK" % _h)
            except Exception as _e:
                _LOGGER.error("PROBE|M tcp %s:443 FAIL %s" % (_h, _e))
            try:
                _LOGGER.error("PROBE|N getaddrinfo: %s" % (
                    _sock.getaddrinfo(_h, 443, _sock.AF_INET)[:3],))
            except Exception as _e:
                _LOGGER.error("PROBE|N getaddrinfo FAIL %s" % _e)
        except Exception as _e:
            _LOGGER.error("PROBE|L/M/N EXC %s" % _e)

        # ===== 差分诊断：SDK 走 gcompat 的 glibc ABI 垫片，Python 走 musl =====
        # 两套 libc 各调一次 getifaddrs / if_nametoindex / gethostbyname，
        # 看 SDK 侧看到的世界是否残缺。放子进程跑（垫片崩了不会带崩 HA）。
        try:
            _gc_script = r'''
import ctypes, socket


class Sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_char * 14)]


class IfAddrs(ctypes.Structure):
    pass


IfAddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(IfAddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.POINTER(Sockaddr)),
    ("ifa_netmask", ctypes.POINTER(Sockaddr)),
    ("ifa_ifu", ctypes.POINTER(Sockaddr)),
    ("ifa_data", ctypes.c_void_p),
]


class HostEnt(ctypes.Structure):
    _fields_ = [("h_name", ctypes.c_char_p),
                ("h_aliases", ctypes.POINTER(ctypes.c_char_p)),
                ("h_addrtype", ctypes.c_int), ("h_length", ctypes.c_int),
                ("h_addr_list", ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))]


def probe(tag, soname):
    try:
        lc = ctypes.CDLL(soname)
    except Exception as e:
        print(tag + " CDLL FAIL " + repr(e))
        return
    try:
        lc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(IfAddrs))]
        lc.getifaddrs.restype = ctypes.c_int
        lc.freeifaddrs.argtypes = [ctypes.POINTER(IfAddrs)]
        p = ctypes.POINTER(IfAddrs)()
        rc = lc.getifaddrs(ctypes.byref(p))
        items = []
        if rc == 0:
            cur, g = p, 0
            while cur and g < 64:
                g += 1
                it = cur.contents
                nm = (it.ifa_name or b"").decode("utf-8", "replace")
                fam = it.ifa_addr.contents.sa_family if it.ifa_addr else 0
                items.append((nm, fam, hex(it.ifa_flags)))
                cur = it.ifa_next
            try:
                lc.freeifaddrs(p)
            except Exception:
                pass
        print(tag + " getifaddrs rc=" + repr(rc) + " -> " + repr(items))
    except Exception as e:
        print(tag + " getifaddrs EXC " + repr(e))
    try:
        lc.if_nametoindex.argtypes = [ctypes.c_char_p]
        lc.if_nametoindex.restype = ctypes.c_uint
        print(tag + " if_nametoindex(wlan0)=" + repr(lc.if_nametoindex(b"wlan0")))
    except Exception as e:
        print(tag + " if_nametoindex EXC " + repr(e))
    try:
        lc.gethostbyname.argtypes = [ctypes.c_char_p]
        lc.gethostbyname.restype = ctypes.POINTER(HostEnt)
        he = lc.gethostbyname(b"query.hicloud.com")
        if not he:
            print(tag + " gethostbyname NULL")
        else:
            h = he.contents
            ip = "-"
            if h.h_addr_list and h.h_addr_list[0]:
                ip = socket.inet_ntoa(ctypes.string_at(h.h_addr_list[0], 4))
            print(tag + " gethostbyname -> " + ip + " fam=" + repr(h.h_addrtype)
                  + " len=" + repr(h.h_length))
    except Exception as e:
        print(tag + " gethostbyname EXC " + repr(e))


def socktest(tag):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        r = []
        try:
            s.setsockopt(socket.SOL_SOCKET,
                         getattr(socket, "SO_BINDTODEVICE", 25), b"wlan0")
            r.append("SO_BINDTODEVICE(bind-to-wlan0) OK")
        except Exception as e:
            r.append("SO_BINDTODEVICE FAIL " + repr(e))
        try:
            s.bind(("0.0.0.0", 5683))
            r.append("bind 0.0.0.0:5683 OK")
        except Exception as e:
            r.append("bind 0.0.0.0:5683 FAIL " + repr(e))
        try:
            s.close()
        except Exception:
            pass
        try:
            s3 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            r.append("raw socket OK")
            s3.close()
        except Exception as e:
            r.append("raw socket FAIL " + repr(e))
        try:
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s4.bind(("0.0.0.0", 5353))
            r.append("bind 5353(REUSEADDR) OK")
            s4.close()
        except Exception as e:
            r.append("bind 5353 FAIL " + repr(e))
        print(tag + " " + " | ".join(r))
    except Exception as e:
        print(tag + " socktest EXC " + repr(e))


probe("gcompat", "libc.so.6")
probe("musl", "libc.so")
socktest("capability")
'''
            with open("/tmp/gc_probe.py", "w") as _f:
                _f.write(_gc_script)
            await hass.async_add_executor_job(
                lambda: _sp2.run("python3 /tmp/gc_probe.py > /tmp/gc_out.txt 2>&1",
                                 shell=True, timeout=120).returncode)
            try:
                with open("/tmp/gc_out.txt", "r") as _f:
                    _lines = _f.read().splitlines()
                for _ln in _lines[-24:]:
                    _LOGGER.error("PROBE|P " + _ln)
            except Exception as _e:
                _LOGGER.error("PROBE|P read EXC %s" % _e)
        except Exception as _e:
            _LOGGER.error("PROBE|P EXC %s" % _e)

        # SDK 线程在内核里挂在哪（poll 说明在等 socket；futex 说明纯空闲）
        try:
            _before_ids = {t for t, _ in _thr_before}
            for _tid, _comm in _thread_snapshot():
                if _tid in _before_ids:
                    continue
                _pid_ = os.getpid()
                _wc = _run2("cat /proc/%d/task/%s/wchan 2>&1; echo; "
                            "awk '{print \"state=\" $3}' /proc/%d/task/%s/stat 2>&1"
                            % (_pid_, _tid, _pid_, _tid))
                _LOGGER.error("PROBE|S tid=%s comm=%s %s" % (_tid, _comm, _wc))
        except Exception as _e:
            _LOGGER.error("PROBE|S EXC %s" % _e)

        # ===== socket fd 差分：main() 到底新建了哪些 socket / 绑在哪个端口 =====
        try:
            _sock_after = _fd_socket_snapshot()
            _new = {f: v for f, v in _sock_after.items() if f not in _sock_before}
            _gone = [f for f in _sock_before if f not in _sock_after]
            _LOGGER.error("PROBE|U sockets_after=%d new=%d gone=%d" % (
                len(_sock_after), len(_new), len(_gone)))
            for _f, _v in sorted(_new.items()):
                _LOGGER.error("PROBE|U  NEW fd=%s %s" % (_f, _v))
            if not _new:
                _LOGGER.error("PROBE|U  main() 没新建任何 socket，全量 DGRAM 如下：")
                for _f, _v in sorted(_sock_after.items()):
                    if _v.get("type") == 2:
                        _LOGGER.error("PROBE|U  dgram fd=%s %s" % (_f, _v))
        except Exception as _e:
            _LOGGER.error("PROBE|U EXC %s" % _e)

        # 垫片与加载器实况
        try:
            _LOGGER.error("PROBE|R libs: " + _run2(
                "ls -l /lib/libc.so.6 /usr/glibc-compat/lib/libc.so.6 2>&1; "
                "apk info -v gcompat 2>&1 | head -3; ls /lib/ld-* 2>&1"))
        except Exception as _e:
            _LOGGER.error("PROBE|R EXC %s" % _e)

        # 端口占用测试（不带 SO_REUSEADDR，能绑上说明真没被占）
        # 两轮：+4s / +12s，排除"监听线程起得慢"
        for _round, _delay in ((1, 0), (2, 8)):
            if _delay:
                await asyncio.sleep(_delay)
                _LOGGER.error("PROBE|T2 threads=%s" % (_thread_snapshot(),))
                try:
                    _r2 = (lib.HILINK_SetPreferredIface(_pickname.encode())
                           if _pickname else None)
                    _LOGGER.error("IFACE| re-SetPreferredIface(%r) rlt=%r" % (_pickname, _r2))
                except Exception as _e:
                    _LOGGER.error("IFACE| re-SetPreferredIface EXC %s" % _e)
            for _port in (5683, 5686, 5685):
                try:
                    _t = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                    _t.bind(("0.0.0.0", _port))
                    _t.close()
                    _LOGGER.error("PROBE|F r%d port %d: FREE (SDK 未监听)" % (_round, _port))
                except Exception as _e:
                    _LOGGER.error("PROBE|F r%d port %d: BUSY (%s)" % (_round, _port, _e))

        # 组播收发自测
        try:
            _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM, _sock.IPPROTO_UDP)
            _s.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
            _s.bind(("", 45678))
            _mreq = _struct.pack("4s4s", _sock.inet_aton("238.238.238.238"),
                                 _sock.inet_aton("0.0.0.0"))
            try:
                _s.setsockopt(_sock.IPPROTO_IP, _sock.IP_ADD_MEMBERSHIP, _mreq)
                _join = "JOIN OK"
            except Exception as _e:
                _join = "JOIN FAIL %s" % _e
            _s.settimeout(3)
            try:
                _s.sendto(b"probe", ("238.238.238.238", 45678))
                _r = _s.recvfrom(64)
                _loop = "LOOPBACK OK %r" % (_r[0][:16],)
            except Exception as _e:
                _loop = "LOOPBACK FAIL %s" % _e
            _s.close()
            _LOGGER.error("PROBE|G mcast: %s | %s" % (_join, _loop))
        except Exception as _e:
            _LOGGER.error("PROBE|G mcast EXC %s" % _e)
    except Exception as _e:
        _LOGGER.error("PROBE|net-diag EXC %s" % _e)

    # 监听 HA 启动完成事件
    # 注意：如果HA已经启动完成，事件不会触发，需要主动检查
    if hass.state.value == "RUNNING":
        _LOGGER.info("Home Assistant already running, directly initializing bridge")
        # HA已经启动，直接调用初始化
        await handle_started_event(None)
    else:
        _LOGGER.info("Waiting for Home Assistant to start")
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, handle_started_event)


async def handle_started_event(event):
    """HA 启动完成后的处理
    
    架构优化：移除对特定平台（xiaomi_miot）的依赖
    - 不再等待特定平台加载
    - 改为等待 HA 完全启动后直接监听状态变化
    - 设备发现逻辑移至 _discover_and_register_devices
    
    Args:
        event: 事件对象，当HA已经启动时直接调用时为None
    """
    global start_work

    _LOGGER.info("Home Assistant started, initializing bridge")
    
    # 给其他集成一些时间完成加载（可选）
    # 实际上 EVENT_HOMEASSISTANT_STARTED 已经在所有集成加载后触发
    # 这里只是添加日志便于调试
    await asyncio.sleep(2)  # 短暂延迟确保所有集成的实体都已创建
    
    _LOGGER.info("Bridge initialization complete, starting state monitoring")

    # 监听状态变化事件
    ghass.bus.async_listen(EVENT_STATE_CHANGED, handle_state_event)

    # 监听设备删除事件
    ghass.bus.async_listen(EVENT_DEVICE_REGISTRY_UPDATED, handle_device_registry_updated)

    start_work = True
    
    _LOGGER.info("start_work set to True")
    
    # 发现并注册设备（不再依赖 OnBridgeStatusCB 的触发）
    # OnBridgeStatusCB 可能在 HA 启动前就触发并等待 start_work，
    # 但等待循环不可靠，导致 notify_new_device 未被调用。
    # 这里直接调用确保设备发现一定执行。
    _LOGGER.info("Starting device discovery from handle_started_event")
    notify_new_device(ghass)

    # 设备注册完成后，延迟同步所有设备状态到 HiLink
    # 延迟原因：C 侧在 HilinkSyncBrgDevStatus(3) 后会执行 batch bind，
    # 期间 UpdateHAStatus 调用会被 C 侧丢弃甚至导致崩溃。
    # 等待 batch bind 完成后再上报状态。
    if service_router is not None and service_router.sn_manager.get_device_count() > 0:
        _LOGGER.info("Scheduling delayed state sync for newly registered devices")
        ghass.loop.call_later(30, _delayed_resync_all_devices)



def register_hilink_callbacks():
    """向 C 侧注册所有 Python 回调。

    在 async_setup（首次启动）和 async_setup_entry（重载集成）时都会调用。
    重载时 async_unload_entry 会先 nullify 回调，这里重新注册恢复。
    """
    if lib is None:
        _LOGGER.warning("Cannot register callbacks: lib is None")
        return
    try:
        lib.RegHomeAssistantPyCB(pActionCB, pTypeCheckCB, pDevStatusCB, pBridgeStatusCB, pGetCharStateCB)
    except Exception as e:
        _LOGGER.error(f"Failed to register RegHomeAssistantPyCB: {e}")
    try:
        lib.RegPINQueryCallback(pPINQueryCB)
        _LOGGER.info("PIN query callback registered successfully")
    except AttributeError:
        _LOGGER.warning("C library does not support RegPINQueryCallback, PIN feature may not work")
    except Exception as e:
        _LOGGER.error(f"Failed to register PIN query callback: {e}")
    try:
        lib.RegGetRoomInfoCallback(pRoomInfoCB)
        _LOGGER.info("Room info callback registered successfully")
    except AttributeError:
        _LOGGER.warning("C library does not support RegGetRoomInfoCallback, device names may not be set")
    except Exception as e:
        _LOGGER.error(f"Failed to register room info callback: {e}")
    _LOGGER.info("All HiLink callbacks registered")


def nullify_hilink_callbacks():
    """将所有 C 侧回调指针置 NULL，防止 SDK 线程在解释器销毁后调用 Python 回调。

    C 侧所有回调调用点都有 NULL check，置空后 SDK 线程继续运行但不再进入 Python。
    重载集成时 async_setup_entry 会调用 register_hilink_callbacks 重新注册。
    """
    if lib is None:
        return
    try:
        lib.RegHomeAssistantPyCB(None, None, None, None, None)
    except Exception as e:
        _LOGGER.error(f"Failed to nullify RegHomeAssistantPyCB: {e}")
    try:
        lib.RegPINQueryCallback(None)
    except AttributeError:
        pass
    except Exception as e:
        _LOGGER.error(f"Failed to nullify RegPINQueryCallback: {e}")
    try:
        lib.RegGetRoomInfoCallback(None)
    except AttributeError:
        pass
    except Exception as e:
        _LOGGER.error(f"Failed to nullify RegGetRoomInfoCallback: {e}")
    _LOGGER.info("All HiLink callbacks nullified")


def stop_hw_hilink_bridge(hass: HomeAssistant):
    """停止 HiLink 桥接，删除子设备+重置网关，清理持久化文件

    在集成被永久删除（async_remove_entry）时通过 executor 调用。
    1. 遍历所有已注册子设备，逐个调用 status=2 删除云端信息
    2. 调用 C 侧 exit_brg() 重置网关并退出 SDK 后台线程
    """
    global bridge_work, start_work

    bridge_work = False
    start_work = False

    # 1. 逐个删除子设备云端信息（C 侧 exit_brg 不会级联删除子设备）
    if service_router is not None:
        all_vds = service_router.sn_manager.get_all_devices()
        for vd in all_vds:
            _LOGGER.info(f"Removing sub-device from HiLink cloud: sn={vd.sn}")
            service_router.register_device_to_hilink(vd.sn, 2)

    # 2. 调用 C 侧 exit_brg() 重置网关并退出后台线程
    if lib is not None:
        try:
            rlt = lib.exit_brg()
            _LOGGER.info(f"exit_brg() = {rlt}")
        except Exception as e:
            _LOGGER.error(f"Failed to call exit_brg: {e}")

    # 清理 Python 侧状态
    if service_router is not None:
        service_router.sn_manager.clear()
    registered_device_ids.clear()
    saved_device_ids.clear()
    _excluded_device_sns.clear()

    # 清理 HA 设备注册表条目（调度到事件循环执行，因为可能在后台线程调用）
    ghass.loop.call_soon_threadsafe(_cleanup_all_device_entries_async)

    # 删除持久化文件（与 OnBridgeStatusCB devStatus==9 路径一致）
    if saved_device_file and os.path.exists(saved_device_file):
        os.remove(saved_device_file)
    if excluded_devices_file and os.path.exists(excluded_devices_file):
        os.remove(excluded_devices_file)
    for filename in hilink_cfg_files:
        onefile = os.path.join(hilink_config_dir, filename)
        if os.path.exists(onefile):
            os.remove(onefile)

    _LOGGER.info("HiLink bridge stopped, gateway removed from cloud")


# ---------------------------------------------------------------------------
# C 回调函数
# ---------------------------------------------------------------------------

def OnPyActionCB(sn_data, payload_data):
    """C 回调：HiLink 控制命令到达

    通过 ServiceRouter 路由到正确的 entity。
    """
    sn = bytes.decode(sn_data)
    payload = bytes.decode(payload_data)
    _LOGGER.info(f"=== OnPyActionCB called, sn={sn}, payload={payload}")

    # 禁用设备不处理控制命令
    if _is_device_disabled(sn):
        _LOGGER.info(f"OnPyActionCB: device {sn} is disabled, ignoring control command")
        return

    if service_router is not None:
        result = service_router.route_action(sn, payload)
        if not result:
            _LOGGER.warning(f"OnPyActionCB: route_action failed for sn={sn}, payload={payload}")
    else:
        _LOGGER.error("OnPyActionCB: service_router not initialized")
        _LOGGER.warning(f"OnPyActionCB: route_action failed for sn={sn}, payload={payload}")


def OnTypeCheckCB(sn_data):
    """C 回调：查询设备类型索引

    在新架构中，通过 SN 查找 VirtualDevice，
    然后根据产品定义返回产品索引。
    但由于 C 侧的 map_prodIds 数组仍然是基于索引的，
    这里需要一个从 PID 到索引的映射。
    """
    sn = bytes.decode(sn_data)

    if service_router is None:
        return -1

    vd = service_router.sn_manager.get_by_sn(sn)
    if vd is None:
        return -1

    # 查找 PID 在 C 侧 map_prodIds 数组中的索引
    pid = vd.product.pid
    pid_index = _get_pid_index(pid)
    if pid_index < 0:
        _LOGGER.warning(f"OnTypeCheckCB: PID {pid} not found in C-side map_prodIds")
        return -1

    return pid_index


def OnDevStatusCB(sn_data, svcId):
    """C 回调：查询设备状态
    
    根据不同的服务类型返回相应的状态值：
    - switch: 返回 0 或 1
    - brightness: 返回 0-100 的亮度值
    - 其他数值型服务：返回对应的数值
    
    特殊处理：当 switch 服务映射到 button entity 时，
    button 没有 on/off 状态，需要使用缓存的 switch_state。
    """
    sn = bytes.decode(sn_data)

    if service_router is None:
        return 0

    vd = service_router.sn_manager.get_by_sn(sn)
    if vd is None:
        return 0

    svc_id_decoded = bytes.decode(svcId) if isinstance(svcId, bytes) else svcId

    # 通过 VirtualDevice 查找对应 entity 的状态
    entity_id = vd.get_entity_for_service(svc_id_decoded)
    if entity_id is None:
        # 默认用第一个 service 的 entity
        entity_id = vd.get_entity_for_service("switch")

    if entity_id and ghass:
        state = ghass.states.get(entity_id)
        domain = entity_id.split('.')[0] if entity_id else ""
        
        # 特殊处理：button/select 域没有 on/off 状态，使用缓存的 switch_state
        # button: 电饭煲取消按钮（小米电饭煲）
        # select: 电饭煲工作状态 select（美的电饭煲），通过 text_to_enum 映射后缓存
        if svc_id_decoded == "switch" and domain in ("button", "select"):
            _LOGGER.debug(f"OnDevStatusCB: {domain} entity {entity_id}, using cached switch_state={vd.switch_state}")
            return vd.switch_state
        
        # brightness 服务：返回亮度值 (0-100)
        if svc_id_decoded == "brightness":
            if state and state.state == 'on':
                brightness = state.attributes.get('brightness', 0)
                # HA 的亮度范围是 0-255，需要转换为华为的 0-100
                brightness_huawei = int(brightness * 100 / 255) if brightness else 0
                _LOGGER.debug(f"OnDevStatusCB: brightness entity {entity_id}, HA brightness={brightness}, Huawei brightness={brightness_huawei}")
                return brightness_huawei
            else:
                return 0
        
        # 普通处理：从 entity state 读取
        if state and state.state == 'on':
            return 1

    return 0


def _delayed_resync_all_devices():
    """延迟重新同步所有设备状态到 HiLink

    在 OnBridgeStatusCB(devStatus=1) 时调度，延迟 30 秒执行。
    此时 C 侧的 batch bind（批量绑定子设备到云端）应该已完成，
    UpdateHAStatus 调用不会再被 "batch ops priority time" 丢弃。
    """
    if not bridge_work:
        _LOGGER.info("Delayed resync skipped: bridge is offline")
        return
    if service_router is None:
        return
    _LOGGER.info("Starting delayed state re-sync for all devices")
    for vd in service_router.sn_manager.get_all_devices():
        if _is_device_disabled(vd.sn):
            _LOGGER.debug(f"Skipping disabled device during resync: sn={vd.sn}")
            continue
        service_router.sync_device_state(vd)
        _LOGGER.info(f"Re-synced state for sn={vd.sn} after gateway online (delayed)")


def OnGetCharStateCB(sn_data, svcId):
    """C 回调：查询指定服务的状态，返回 JSON 字符串

    供 HilinkGetBrgDevCharState 使用，通过 ServiceRouter
    查询对应 VirtualDevice 的 entity 状态，返回符合 profile 的 JSON。

    Args:
        sn_data: 设备 SN（C 字符串）
        svcId: 服务 ID（C 字符串）

    Returns:
        bytes 对象（自动转换为 c_char_p），如 '{"on":1}' 或 '{"brightness":50}'
        查询失败返回 None
        
    注意：
        - C 侧会在回调返回时立即拷贝内容
        - Python 侧缓存 bytes 对象防止过早被垃圾回收
        - 下次调用同一 (sn, svc_id) 时会覆盖旧的 bytes 对象
    """
    sn = bytes.decode(sn_data)
    svc_id_decoded = bytes.decode(svcId) if isinstance(svcId, bytes) and svcId else ""

    _LOGGER.debug(f"OnGetCharStateCB: sn={sn}, svcId={svc_id_decoded}")

    if service_router is None:
        return None

    result = service_router.get_char_state(sn, svc_id_decoded)
    if result is not None:
        _LOGGER.debug(f"OnGetCharStateCB: sn={sn}, svcId={svc_id_decoded}, result={result}")
        # 缓存 bytes 对象，防止在 C 侧拷贝前被垃圾回收
        # C 侧会在回调返回时立即拷贝内容，下次调用时覆盖此缓存
        result_bytes = result.encode('utf-8')
        key = (sn, svc_id_decoded)
        _char_state_bytes[key] = result_bytes
        return result_bytes
    
    return None


def OnBridgeStatusCB(status):
    """C 回调：桥接状态变化"""
    devStatus = lib.HILINK_GetDevStatus()
    _LOGGER.info(f"=== hwbridge status is {status}, dev status is {devStatus}.")

    if 1 == devStatus:
        global bridge_work
        bridge_work = True
        
        if not start_work:
            return
        
        if ghass is not None:
            # 防止 C 侧多次触发 devStatus=1 导致并发发现
            global _discovery_in_progress
            with _discovery_lock:
                if _discovery_in_progress:
                    _LOGGER.info("Gateway online, but discovery already in progress, skip")
                    return
                _discovery_in_progress = True
            try:
                _LOGGER.info("Gateway back online, re-discovering devices")
                notify_new_device(ghass)
            finally:
                with _discovery_lock:
                    _discovery_in_progress = False
            # 网关上线后，对所有已注册的 VirtualDevice 重新同步状态
            # notify_new_device 会跳过已注册设备，但它们的初始状态
            # 可能因网关未上线而未成功上报
            #
            # 注意：网关上线后 C 侧会执行 batch bind（批量绑定子设备到云端），
            # 期间 UpdateHAStatus 调用会被 C 侧丢弃（batch ops priority time,
            # ignore information report）。需要延迟等到 batch bind 完成后再
            # 上报状态，否则状态上报会被全部丢弃。
            if service_router is not None:
                _LOGGER.info("Scheduling delayed state re-sync (waiting for batch bind to complete)")
                ghass.loop.call_later(30, _delayed_resync_all_devices)
    elif 9 == devStatus:
        bridge_work = False
        if start_work:
            registered_device_ids.clear()
            saved_device_ids.clear()
            _excluded_device_sns.clear()
            if saved_device_file and os.path.exists(saved_device_file):
                os.remove(saved_device_file)
            if excluded_devices_file and os.path.exists(excluded_devices_file):
                os.remove(excluded_devices_file)
            for filename in hilink_cfg_files:
                onefile = os.path.join(hilink_config_dir, filename)
                if os.path.exists(onefile):
                    os.remove(onefile)
            _LOGGER.info("Bridge went offline (devStatus=9) after startup, cleaned persisted files")
        else:
            _LOGGER.info("devStatus=9 during startup, skipping persisted file cleanup")


# 注册 C 回调的 ctypes 类型
BRG_ACTION_FUNC = CFUNCTYPE(None, c_char_p, c_char_p)
pActionCB = BRG_ACTION_FUNC(OnPyActionCB)

BRG_TYPECHECK_FUNC = CFUNCTYPE(c_int, c_char_p)
pTypeCheckCB = BRG_TYPECHECK_FUNC(OnTypeCheckCB)

BRG_DEVSTATUS_FUNC = CFUNCTYPE(c_int, c_char_p, c_char_p)
pDevStatusCB = BRG_DEVSTATUS_FUNC(OnDevStatusCB)

BRG_GETCHARSTATE_FUNC = CFUNCTYPE(c_char_p, c_char_p, c_char_p)
pGetCharStateCB = BRG_GETCHARSTATE_FUNC(OnGetCharStateCB)

BRG_NOTIFYSTATUS_FUNC = CFUNCTYPE(None, c_int)
pBridgeStatusCB = BRG_NOTIFYSTATUS_FUNC(OnBridgeStatusCB)


# ---------------------------------------------------------------------------
# PIN查询回调函数（供C侧SDK调用）
# ---------------------------------------------------------------------------

def OnPINQueryCB():
    """C回调：查询当前PIN码
    
    当SDK收到智慧生活APP的PIN校验请求时，调用此函数获取正确的PIN码。
    
    Returns:
        int: 当前有效的8位PIN码整数
        0: 无有效PIN码或已过期
    """
    pin = PINManager.get_current_pin()
    if pin:
        _LOGGER.info(f"C-side queried PIN: {pin}")
        return pin
    else:
        _LOGGER.warning("C-side queried PIN, but no valid PIN available")
        return 0


PIN_QUERY_FUNC = CFUNCTYPE(c_int)
pPINQueryCB = PIN_QUERY_FUNC(OnPINQueryCB)


# ---------------------------------------------------------------------------
# 房间信息回调函数（供C侧SDK调用，用于获取设备名和房间名）
# ---------------------------------------------------------------------------

_room_info_lock = threading.Lock()


def OnGetRoomInfoCB(sn_ptr, roomName_ptr, devName_ptr):
    """C回调：根据 SN 获取设备的房间名和设备名

    C 侧 SDK 在注册设备上云时需要调用此回调获取设备名称。

    Args:
        sn_ptr: 设备 SN 的指针（c_void_p，实际指向 C 字符串）
        roomName_ptr: 房间名输出缓冲区（C 侧分配，40 bytes）
        devName_ptr: 设备名输出缓冲区（C 侧分配，64 bytes）
    """
    if sn_ptr is None or devName_ptr is None:
        return

    # c_void_p 参数需要手动读取字符串
    try:
        sn_addr = cast(sn_ptr, POINTER(c_char))
        sn = string_at(sn_addr).decode('utf-8')
    except Exception:
        return

    if not sn or service_router is None:
        return

    with _room_info_lock:
        # 1. 从 SN 查找 VirtualDevice
        vd = service_router.sn_manager.get_by_sn(sn)
        if vd is None:
            return

        # 2. 从 HA device_registry 获取设备名称和区域名称
        # 设备名优先级：桥接设备条目 name_by_user > 原始 HA 设备 name_by_user/name
        # 房间名优先级：桥接设备条目 area_id > 原始 HA 设备 area_id
        dev_name = ""
        room_name = ""
        if ghass is not None:
            try:
                dev_reg = dr.async_get(ghass)
                area_reg = ar.async_get(ghass)
                entries = ghass.config_entries.async_entries(DOMAIN)
                entry_id = entries[0].entry_id if entries else None

                # 优先：桥接设备条目的 name_by_user 和 area_id
                bridge_entry = None
                if entry_id:
                    bridge_entry = dev_reg.async_get_device(
                        identifiers={(DOMAIN, entry_id, vd.sn)}
                    )
                    if bridge_entry and bridge_entry.name_by_user:
                        dev_name = bridge_entry.name_by_user

                # 其次：原始 HA 设备的 name_by_user 或 name
                orig_entry = None
                if not dev_name:
                    orig_entry = dev_reg.devices.get(vd.ha_device_id)
                    if orig_entry:
                        dev_name = orig_entry.name_by_user or orig_entry.name or ""

                # 房间名：优先从桥接设备条目获取 area_id，其次从原始设备
                area_id = None
                if bridge_entry and bridge_entry.area_id:
                    area_id = bridge_entry.area_id
                elif orig_entry is None:
                    orig_entry = dev_reg.devices.get(vd.ha_device_id)
                if not area_id and orig_entry and orig_entry.area_id:
                    area_id = orig_entry.area_id

                if area_id:
                    area = area_reg.async_get_area(area_id)
                    if area and area.name:
                        room_name = area.name
            except Exception:
                pass

        # 3. 将设备名写入 devName 缓冲区（64 bytes）
        if dev_name:
            dev_name_bytes = dev_name.encode('utf-8')
            # 截断到 63 字节（留 1 字节给 \0），SUB_DEV_NAME_MAX_LEN=64
            if len(dev_name_bytes) >= 64:
                dev_name_bytes = dev_name_bytes[:63]
            # 将 c_void_p 转换为可写的字节数组，然后写入设备名
            devName_arr = cast(devName_ptr, POINTER(c_ubyte * 64)).contents
            for i, b in enumerate(dev_name_bytes):
                devName_arr[i] = b
            devName_arr[len(dev_name_bytes)] = 0  # null terminate

        # 4. 将房间名写入 roomName 缓冲区（40 bytes）
        if room_name and roomName_ptr is not None:
            room_name_bytes = room_name.encode('utf-8')
            # 截断到 39 字节（留 1 字节给 \0），ROOM_NAME_MAX_LEN=40
            if len(room_name_bytes) >= 40:
                room_name_bytes = room_name_bytes[:39]
            roomName_arr = cast(roomName_ptr, POINTER(c_ubyte * 40)).contents
            for i, b in enumerate(room_name_bytes):
                roomName_arr[i] = b
            roomName_arr[len(room_name_bytes)] = 0  # null terminate

# C 回调签名：void FuncGetRoomInfoCB(char* sn, char* roomName, char* devName)
ROOM_INFO_FUNC = CFUNCTYPE(None, c_void_p, c_void_p, c_void_p)
pRoomInfoCB = ROOM_INFO_FUNC(OnGetRoomInfoCB)

# ---------------------------------------------------------------------------
# 设备发现与注册
# ---------------------------------------------------------------------------

def notify_new_device(hass: HomeAssistant):
    """发现并注册新设备

    核心改动：使用 ServiceRouter 的聚合逻辑替代原来的
    逐 entity 注册方式。新的方式按 device 维度注册，
    一个 HA device 对应一个 VirtualDevice（一个 SN）。
    """
    # 加载持久化的设备列表
    if saved_device_file and os.path.exists(saved_device_file):
        with open(saved_device_file, 'r') as f:
            for line in f:
                device_id = line.strip()
                if device_id:
                    saved_device_ids.add(device_id)
        _LOGGER.info(f"Loaded {len(saved_device_ids)} saved device IDs")
    else:
        _LOGGER.warning(f"saved_device_file is not set (value={saved_device_file}), "
                        "persisted device list will not be loaded")

    # 加载排除设备列表（设备管理页取消勾选的设备，重启后不注册到 HiLink）
    if excluded_devices_file and os.path.exists(excluded_devices_file):
        with open(excluded_devices_file, 'r') as f:
            for line in f:
                sn = line.strip()
                if sn:
                    _excluded_device_sns.add(sn)
        _LOGGER.info(f"Loaded {len(_excluded_device_sns)} excluded device SNs")

    # 通过 HA 的 device_registry 和 entity_registry 发现设备
    _discover_and_register_devices(hass)


def _discover_and_register_devices(hass: HomeAssistant):
    """发现并注册 HA device 到 HiLink

    架构优化：移除对特定平台的依赖
    
    核心流程：
    1. 从 HA 的 device_registry 中获取所有设备
    2. 对每个设备，通过 product_matcher 尝试匹配产品
    3. 如果匹配成功，通过 ServiceRouter 注册
    4. 注册成功后同步到 HiLink
    
    过滤策略：
    - 跳过没有实体的设备
    - 跳过无法匹配产品定义的设备（静默跳过，不报错）
    - 支持任意来源的设备（xiaomi/tuya/zigbee/mqtt等）
    """
    if service_router is None:
        _LOGGER.error("ServiceRouter not initialized, cannot discover devices")
        return

    device_reg = dr.async_get(hass)
    entity_reg = er.async_get(hass)

    # 获取所有设备（不再限制为特定平台）
    all_devices = device_reg.devices
    
    _LOGGER.info(f"Starting device discovery, total {len(all_devices)} devices in registry")

    registered_count = 0
    skipped_count = 0
    
    # 对每个 device，调用 _register_single_device
    for device_id in all_devices.keys():
        result = _register_single_device(device_id)
        if result:
            registered_count += 1
        else:
            skipped_count += 1
    
    _LOGGER.info(f"Device discovery complete: {registered_count} registered, "
                 f"{skipped_count} skipped")


def _register_single_device(device_id: str, reuse_sn: str = None, is_update: bool = False) -> bool:
    """注册单个设备到 HiLink
    
    从 HA 的 device_registry 和 entity_registry 收集设备信息，
    通过 ServiceRouter 注册到 HiLink。
    
    Args:
        device_id: HA 的 device_id
        reuse_sn: 复用指定的 SN（用于设备更新场景）
        is_update: 是否为更新场景（True 则不保存到持久化文件）
    
    Returns:
        True 表示注册成功，False 表示跳过或失败
    """
    if service_router is None:
        _LOGGER.error("ServiceRouter not initialized, cannot register device")
        return False
    
    if ghass is None:
        return False

    # 复合 key 支持："<真实device_id>|<子实体entity_id>"
    # 用途：一个 HA device 下有多路可控实体（如双开开关的左右两路）时，
    # 每一路拆成一个独立虚拟设备，各自一个 SN，华为 App 里才会出现两个开关。
    sub_entity = None
    real_device_id = device_id
    if "|" in device_id:
        real_device_id, sub_entity = device_id.split("|", 1)

    # 防重复注册：如果设备已注册且不是更新场景，跳过
    if not is_update and device_id in registered_device_ids:
        _LOGGER.debug(f"Device {device_id} already registered, skip")
        return False

    # 预生成 SN 用于排除检查（排除列表存储的是 SN，不是 device_id）
    expected_sn = SNManager.generate_sn(device_id) if not reuse_sn else reuse_sn
    is_excluded = not is_update and expected_sn in _excluded_device_sns
    if is_excluded:
        _LOGGER.info(f"Device {device_id} (sn={expected_sn}) is excluded, will register to SNManager only")
    device_reg = dr.async_get(ghass)
    entity_reg = er.async_get(ghass)

    device_entry = device_reg.async_get(real_device_id)
    if not device_entry:
        _LOGGER.debug(f"Device {device_id} not found in registry")
        return False

    # 收集该 device 下的所有 entity
    device_entities = er.async_entries_for_device(entity_reg, real_device_id)
    
    # 跳过没有实体的设备
    if not device_entities:
        _LOGGER.debug(f"Device {device_id} has no entities, skipping")
        return False
    
    entity_list = []
    for entry in device_entities:
        # 拆分场景：只保留指定的那一个子实体
        if sub_entity is not None and entry.entity_id != sub_entity:
            continue

        # 跳过来自反向桥接集成（如 huawei_smarthome）的实体，避免循环接入
        if getattr(entry, "platform", None) in SKIP_PLATFORMS:
            _LOGGER.debug(f"Skipping entity {entry.entity_id} from platform '{entry.platform}' to avoid bridge loop")
            continue

        state = ghass.states.get(entry.entity_id)
        entity_name = state.name if state and hasattr(state, 'name') else ""
        
        # device_class 从两个来源获取：1) RegistryEntry 2) State.attributes
        device_class = entry.device_class
        if not device_class and state:
            device_class = state.attributes.get('device_class')
        
        entity_list.append({
            "entity_id": entry.entity_id,
            "domain": entry.domain,
            "device_class": device_class,
            "name": entity_name,
        })

    # 过滤后若无可用实体，跳过该设备
    if not entity_list:
        _LOGGER.debug(f"Device {device_id} has no eligible entities after platform filter, skipping")
        return False

    # 构建设备信息
    model = device_entry.model or ""
    name = device_entry.name_by_user or device_entry.name or ""
    manufacturer = device_entry.manufacturer or ""

    # 拆分场景：用子实体名做虚拟设备名，避免同一 device 拆出的多路同名
    if sub_entity is not None:
        sub_name = ""
        for ent in entity_list:
            if ent["entity_id"] == sub_entity and ent.get("name"):
                sub_name = ent["name"]
                break
        name = sub_name or ((name + " " + sub_entity.split(".")[-1])
                            if name else sub_entity)

    _LOGGER.debug(f"Registering device: id={device_id}, name={name}, model={model}, "
                  f"manufacturer={manufacturer}, entities={len(entity_list)}, "
                  f"reuse_sn={reuse_sn}, is_update={is_update}")
    
    # 通过 ServiceRouter 注册（内部会通过 product_matcher 匹配）
    # 如果匹配失败，register_device 会返回 None
    vd = service_router.register_device(
        device_id=real_device_id,
        device_name=name,
        entity_list=entity_list,
        model=model,
        manufacturer=manufacturer,
        reuse_sn=reuse_sn,
        sn_seed=device_id
    )

    if vd is not None:
        if is_excluded:
            vd.online = False
            _LOGGER.info(f"Device registered to SNManager only (excluded): sn={vd.sn}, device_id={device_id}")
            return True

        # 注册到 HiLink
        if is_update:
            # 更新场景：设备已在线，status=1
            service_router.register_device_to_hilink(vd.sn, 1)
        elif device_id in saved_device_ids:
            # 已知设备，status=1
            service_router.register_device_to_hilink(vd.sn, 1)
        else:
            # 新设备，先用status=3注册，再调用status=1确认上线
            service_router.register_device_to_hilink(vd.sn, 3)
            service_router.register_device_to_hilink(vd.sn, 1)
            _save_device_id(device_id)

        registered_device_ids.add(device_id)

        if _is_device_disabled(vd.sn):
            vd.online = False
            service_router.register_device_to_hilink(vd.sn, 0)
            _LOGGER.info(f"Device {device_id} (sn={vd.sn}) is disabled, reported offline")
        else:
            vd.online = True

        _create_bridge_device_entry(vd, name, model, manufacturer)

        _LOGGER.info(f"Device registered, state sync deferred: sn={vd.sn}, device_id={device_id}, "
                     f"name={name}, model={model}")

        # 多路可控实体拆分（如双开开关的第二路）
        if sub_entity is None and not is_update:
            _register_extra_controllables(real_device_id, vd)

        return True
    else:
        # 匹配失败，静默跳过
        _LOGGER.debug(f"Device {device_id} ({name}, model={model}) did not match any product, skipping")
        return False


# ---------------------------------------------------------------------------
# 多路可控实体拆分
# ---------------------------------------------------------------------------

# 允许被拆成独立虚拟设备的 domain（一个实体 = 一个可开关设备）
_SPLIT_DOMAINS = {"switch", "light", "fan", "water_heater"}

# 明显不是"主控开关"的实体名关键词（命中即跳过）
_SPLIT_EXCLUDE = [
    "防闪烁", "指示灯", "童锁", "物理控制", "勿扰", "延时", "倒计时",
    "提醒", "保护", "限制", "循环", "定时", "锁", "提示音", "静音",
    "模式", "fault", "异常", "接线", "wiring", "temperature", "温度",
    "电压", "voltage", "水印", "追踪", "侦测", "检测", "报警", "画框",
    "区域", "围栏", "授权", "息屏", "记忆", "保温", "杀菌", "防冻",
    "预约", "凌动", "增减", "水印", "locked",
]

# 主控开关实体名必须包含其中之一
_SPLIT_INCLUDE = ["开关", "on", "power", "relay", "socket", "插座", "风扇"]


def _register_extra_controllables(device_id: str, first_vd) -> int:
    """把同一个 HA device 下「尚未被映射」的多余可控实体各拆成一个虚拟设备

    背景：一个 VirtualDevice 的一个 service 只能挂一个 entity，而小米双开
    开关（xiaomi.switch.w2）在 HA 里是一个 device、两个 switch 实体
    （左键/右键各控一路灯）。不拆的话第二路永远进不了华为 App。

    做法：主虚拟设备映射走第一个实体后，把剩下的「像主控开关」的实体
    用 "<device_id>|<entity_id>" 的复合 key 各注册一次，各自拿到独立 SN。
    """
    if service_router is None or ghass is None or first_vd is None:
        return 0

    entity_reg = er.async_get(ghass)
    entries = er.async_entries_for_device(entity_reg, device_id)

    used = {eid for eid in first_vd.get_all_entity_ids() if eid}
    extra = []
    for entry in entries:
        eid = entry.entity_id
        if eid in used:
            continue
        if entry.domain not in _SPLIT_DOMAINS:
            continue
        if getattr(entry, "platform", None) in SKIP_PLATFORMS:
            continue

        state = ghass.states.get(eid)
        if state is not None and state.state == "unavailable":
            continue

        label = ((getattr(entry, "original_name", None) or "")
                 or (state.name if state else "") or "").lower()
        eid_l = eid.lower()
        if any(k in label or k in eid_l for k in _SPLIT_EXCLUDE):
            continue
        if not any(k in label or k in eid_l for k in _SPLIT_INCLUDE):
            continue
        extra.append(eid)

    if not extra:
        return 0

    _LOGGER.info(f"Device {device_id}: {len(extra)} extra controllable entities "
                 f"will be split into separate virtual devices: {extra}")

    count = 0
    for eid in extra:
        try:
            if _register_single_device(f"{device_id}|{eid}"):
                count += 1
        except Exception as exc:  # noqa: BLE001
            _LOGGER.error(f"Failed to split-register {device_id}|{eid}: {exc}")

    return count


# ---------------------------------------------------------------------------
# 状态变化处理
# ---------------------------------------------------------------------------

def handle_state_event(event):
    """处理 HA state change 事件，将状态同步到 HiLink"""
    if 'entity_id' not in event.data:
        return

    entity_id = event.data['entity_id']
    
    if not bridge_work:
        return

    # 通过 ServiceRouter 查找 entity 所属的 VirtualDevice
    if service_router is None:
        return

    vd = service_router.sn_manager.get_virtual_device_by_entity(entity_id)
    if vd is None:
        return

    # 禁用设备不转发状态变化
    if _is_device_disabled(vd.sn):
        return

    old_state = event.data['old_state']
    new_state = event.data['new_state']

    # 处理设备离线状态
    if new_state and new_state.state == 'unavailable':
        if vd.online:
            vd.online = False
            service_router.register_device_to_hilink(vd.sn, 0)
            _LOGGER.info(f"Device {entity_id} went offline, notified HiLink")
        return

    # 处理设备恢复在线
    if old_state and old_state.state == 'unavailable':
        if not vd.online:
            vd.online = True
            service_router.register_device_to_hilink(vd.sn, 1)
            _LOGGER.info(f"Device {entity_id} came back online, notified HiLink")

    # 同步状态到 HiLink
    if vd.online:
        service_router.report_state(vd.sn, entity_id, new_state)

def handle_device_registry_updated(event):
    """处理 HA 设备注册表变化事件

    支持三种事件类型：
    - create: 新设备接入，自动注册到 HiLink
    - update: 设备信息更新，重新匹配并注册
    - remove: 设备删除，从 HiLink 注销

    注意：本集成自己创建的桥接设备条目（identifiers 中含 DOMAIN + sn）
    的 disabled_by 变化由 _on_device_registry_updated 专门处理，
    此处跳过这些事件避免冲突。
    """
    if not bridge_work:
        return

    if service_router is None:
        return

    event_type = event.data.get('action')
    device_id = event.data.get('device_id')

    if not event_type or not device_id:
        return

    # 跳过本集成自己创建的桥接设备条目
    if ghass is not None:
        dev_reg = dr.async_get(ghass)
        dev_entry = dev_reg.devices.get(device_id)
        if dev_entry is not None:
            entries = ghass.config_entries.async_entries(DOMAIN)
            entry_id = entries[0].entry_id if entries else None
            if entry_id and entry_id in dev_entry.config_entries:
                for ident in dev_entry.identifiers:
                    if len(ident) == 3 and ident[0] == DOMAIN and ident[1] == entry_id:
                        sn = ident[2]
                        changes = event.data.get('changes', {})
                        if event_type == 'update' and 'disabled_by' in changes:
                            _LOGGER.debug(f"Skipping bridge device entry update (disabled_by): device_id={device_id}")
                            return
                        if event_type == 'update' and 'name_by_user' in changes:
                            _LOGGER.info(f"Bridge device name changed, re-registering: sn={sn}")
                            vd = service_router.sn_manager.get_by_sn(sn)
                            if vd is not None and vd.online:
                                service_router.register_device_to_hilink(sn, 1)
                                service_router.sync_device_state(vd)
                            return
                        if event_type == 'update':
                            _LOGGER.debug(f"Skipping bridge device entry update: device_id={device_id}")
                            return

    _LOGGER.debug(f"Device registry event: action={event_type}, device_id={device_id}")

    if event_type == 'create':
        _handle_new_device_event(device_id)
    elif event_type == 'update':
        _handle_device_update_event(device_id, event)
    elif event_type == 'remove':
        _handle_device_remove_event(device_id)


def _handle_new_device_event(device_id: str):
    """处理新设备创建事件
    
    新设备创建时，实体可能还未完全加载，延迟处理以确保实体就绪。
    """
    if device_id in registered_device_ids:
        _LOGGER.debug(f"Device {device_id} already registered, skip create event")
        return
    
    _LOGGER.info(f"New device created in HA: device_id={device_id}, scheduling registration")
    
    # 延迟处理：等待实体的创建完成
    # 使用 hass.loop.call_later 或 asyncio.create_task 实现
    # 这里用同步延迟，因为回调可能在后台线程
    if ghass:
        ghass.loop.call_later(2, lambda: _register_single_device(device_id))


def _handle_device_update_event(device_id: str, event):
    """处理设备更新事件
    
    设备更新时，检查关键字段是否变化，决定是否重新注册。
    关键字段：model, manufacturer, name_by_user, name
    """
    if device_id not in registered_device_ids:
        # 未注册的设备更新，按新设备处理
        _LOGGER.debug(f"Device {device_id} updated but not registered, treating as new device")
        _handle_new_device_event(device_id)
        return
    
    # 获取旧设备信息
    vd = service_router.sn_manager.get_by_device_id(device_id)
    if not vd:
        return
    
    # 从事件数据中提取设备变化信息
    changes = event.data.get('changes', {})
    
    # 检查关键字段是否变化
    # HA 的 changes 格式可能是 {field: (old_value, new_value)} 或 {field: new_value}
    key_fields = {'model', 'manufacturer', 'name_by_user', 'name'}
    changed_fields = key_fields & set(changes.keys())
    
    if not changed_fields:
        _LOGGER.debug(f"Device {device_id} updated but no key fields changed, skip re-registration")
        return
    
    _LOGGER.info(f"Device {device_id} key fields changed: {changed_fields}, re-registering")
    
    # 重新注册设备（复用原 SN）
    _register_single_device(device_id, reuse_sn=vd.sn, is_update=True)


def _handle_device_remove_event(device_id: str):
    """处理设备删除事件"""
    _LOGGER.info(f"Device removed in HA: device_id={device_id}, reporting offline to HiLink")
    
    vd = service_router.unregister_device(device_id)
    if vd is not None:
        registered_device_ids.discard(device_id)
        _remove_bridge_device_entry(vd.sn)
        _LOGGER.info(f"Device {device_id} (sn={vd.sn}) reported offline and cleaned up")
    else:
        _LOGGER.debug(f"Device {device_id} was not registered in HiLink, skip offline report")


# ---------------------------------------------------------------------------
# HA 设备注册表管理与禁用/启用
# ---------------------------------------------------------------------------

def _create_bridge_device_entry(vd, name: str, model: str, manufacturer: str):
    """在 HA 设备注册表中为桥接设备创建条目

    使设备显示在集成页面，用户可通过 HA UI 的设备设置齿轮菜单
    禁用/启用设备（利用 HA 原生 disabled_by 机制）。

    此函数可能从后台线程（C 回调）调用，因此通过 call_soon_threadsafe
    将实际工作调度到事件循环中执行，确保 dev_reg.async_get_or_create
    和 async_track_device_registry_updated_event 在正确的线程中运行。

    Args:
        vd: VirtualDevice
        name: 设备名称
        model: 设备型号
        manufacturer: 设备制造商
    """
    if ghass is None:
        return

    if not name:
        name = vd.product.name or vd.product.pid or "Bridge Device"

    ghass.loop.call_soon_threadsafe(
        _create_bridge_device_entry_async, vd, name, model, manufacturer
    )


def _create_bridge_device_entry_async(vd, name: str, model: str, manufacturer: str, clear_disabled: bool = False):
    """在事件循环中创建 HA 设备注册表条目（由 _create_bridge_device_entry 调度）

    Args:
        vd: VirtualDevice
        name: 设备名称
        model: 设备型号
        manufacturer: 设备制造商
        clear_disabled: 是否清除残留的 disabled_by 状态（仅在设备管理页重新勾选时使用）
    """
    if ghass is None:
        return

    try:
        dev_reg = dr.async_get(ghass)

        # 查找当前 config entry
        entries = ghass.config_entries.async_entries(DOMAIN)
        entry_id = entries[0].entry_id if entries else None
        if entry_id is None:
            _LOGGER.warning("_create_bridge_device_entry_async: no config entry found")
            return

        identifier = (DOMAIN, entry_id, vd.sn)
        device_entry = dev_reg.async_get_or_create(
            config_entry_id=entry_id,
            identifiers={identifier},
            name=name,
            model=model or vd.product.pid,
            manufacturer=manufacturer,
        )

        if clear_disabled and device_entry.disabled_by is not None:
            dev_reg.async_update_device(
                device_entry.id, disabled_by=None
            )
            _LOGGER.info(f"Cleared residual disabled_by for sn={vd.sn}")
            device_entry = dev_reg.devices.get(device_entry.id)
        elif device_entry.disabled_by is not None:
            _disabled_device_sns.add(vd.sn)
            vd.online = False
            if service_router is not None:
                service_router.register_device_to_hilink(vd.sn, 0)
            _LOGGER.info(f"Restored disabled state for sn={vd.sn}")

        if device_entry.id not in _cancel_device_registry_listeners:
            from homeassistant.helpers.event import async_track_device_registry_updated_event
            cancel = async_track_device_registry_updated_event(
                ghass,
                device_entry.id,
                _on_device_registry_updated,
            )
            _cancel_device_registry_listeners[device_entry.id] = cancel
            _LOGGER.info(f"Created device registry entry for sn={vd.sn}, name={name}, device_id={device_entry.id}")

    except Exception as e:
        _LOGGER.error(f"_create_bridge_device_entry_async failed for sn={vd.sn}: {e}")


def _remove_bridge_device_entry(sn: str):
    """从 HA 设备注册表中移除桥接设备条目

    此函数可能从后台线程调用，通过 call_soon_threadsafe 调度到事件循环。

    Args:
        sn: 设备 SN
    """
    if ghass is None:
        return

    ghass.loop.call_soon_threadsafe(_remove_bridge_device_entry_async, sn)


def _remove_bridge_device_entry_async(sn: str):
    """在事件循环中移除桥接设备条目"""
    if ghass is None:
        return

    try:
        dev_reg = dr.async_get(ghass)

        # 通过 identifiers 查找设备
        entries = ghass.config_entries.async_entries(DOMAIN)
        entry_id = entries[0].entry_id if entries else None
        if entry_id is None:
            return

        identifier = (DOMAIN, entry_id, sn)
        device_entry = dev_reg.async_get_device(identifiers={identifier})
        if device_entry is not None:
            cancel = _cancel_device_registry_listeners.pop(device_entry.id, None)
            if cancel is not None and callable(cancel):
                cancel()
            dev_reg.async_remove_device(device_entry.id)
            _LOGGER.info(f"Removed device registry entry for sn={sn}")

        _disabled_device_sns.discard(sn)
    except Exception as e:
        _LOGGER.error(f"_remove_bridge_device_entry_async failed for sn={sn}: {e}")


def _on_device_registry_updated(event):
    """处理 HA 设备注册表更新事件

    当用户在 HA UI 上禁用/启用设备时，HA 会触发此事件。
    我们检查 disabled_by 字段的变化，相应地暂停/恢复设备的桥接。

    注意：不使用 changes['disabled_by'] 的值来判断禁用/启用，
    因为该值可能是旧值。直接从 device_entry.disabled_by 读取当前值。
    """
    if not bridge_work:
        return

    if service_router is None:
        return

    data = event.data
    action = data.get('action') if isinstance(data, dict) else getattr(data, 'action', None)
    device_id = data.get('device_id') if isinstance(data, dict) else getattr(data, 'device_id', None)

    if action != 'update' or not device_id:
        return

    changes = data.get('changes', {}) if isinstance(data, dict) else getattr(data, 'changes', {})
    if 'disabled_by' not in changes:
        return

    if ghass is None:
        return

    dev_reg = dr.async_get(ghass)
    device_entry = dev_reg.devices.get(device_id)
    if device_entry is None:
        return

    # 从 identifiers 中提取 SN
    entries = ghass.config_entries.async_entries(DOMAIN)
    entry_id = entries[0].entry_id if entries else None
    if entry_id is None:
        return

    sn = None
    for ident in device_entry.identifiers:
        if len(ident) == 3 and ident[0] == DOMAIN and ident[1] == entry_id:
            sn = ident[2]
            break

    if sn is None:
        return

    vd = service_router.sn_manager.get_by_sn(sn)
    if vd is None:
        return

    if device_entry.disabled_by is not None:
        _disabled_device_sns.add(sn)
        vd.online = False
        service_router.register_device_to_hilink(sn, 0)
        _LOGGER.info(f"Device disabled by user in HA UI: sn={sn}, disabled_by={device_entry.disabled_by}")
    else:
        _disabled_device_sns.discard(sn)
        vd.online = True
        service_router.register_device_to_hilink(sn, 1)
        # 同步当前状态
        service_router.sync_device_state(vd)
        _LOGGER.info(f"Device enabled by user in HA UI: sn={sn}")


def _is_device_disabled(sn: str) -> bool:
    """检查设备是否被禁用（用户在 HA UI 上禁用）"""
    return sn in _disabled_device_sns


def _cleanup_all_device_entries():
    """清理所有桥接设备的 HA 设备注册表条目（用于集成卸载/删除）

    此函数可能从后台线程调用，通过 call_soon_threadsafe 调度到事件循环。
    """
    if ghass is None:
        return

    ghass.loop.call_soon_threadsafe(_cleanup_all_device_entries_async)


def _cleanup_all_device_entries_async():
    """在事件循环中清理所有桥接设备条目"""
    if ghass is None:
        return

    dev_reg = dr.async_get(ghass)
    entries = ghass.config_entries.async_entries(DOMAIN)
    entry_id = entries[0].entry_id if entries else None
    if entry_id is None:
        return

    # 取消所有监听器
    for cancel in _cancel_device_registry_listeners.values():
        if cancel is not None and callable(cancel):
            cancel()
    _cancel_device_registry_listeners.clear()

    # 移除所有属于此 config entry 的设备
    for device in list(dev_reg.devices.values()):
        if entry_id in device.config_entries:
            dev_reg.async_remove_device(device.id)

    _disabled_device_sns.clear()
    _LOGGER.info("All bridge device entries cleaned up")


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _get_pid_index(pid: str) -> int:
    """查询 PID 在 C 侧 map_prodIds 数组中的索引

    C 侧的 map_prodIds 数组：
    index 0 -> "001"
    index 1 -> "002"
    index 2 -> "003"
    index 3 -> "004"
    index 4 -> "005"
    index 5 -> "006"
    index 6 -> "007"
    index 7 -> "008"

    此映射需要与 C 侧保持同步。后续可以通过自动生成来保证一致性。
    """
    pid_index_map = {
        "001": 0,
        "002": 1,
        "003": 2,
        "004": 3,
        "005": 4,
        "006": 5,
        "007": 6,
        "008": 7,
    }
    return pid_index_map.get(pid, -1)


def _save_device_id(device_id: str):
    """持久化 device_id

    使用 hass.loop 的 executor 在后台线程执行文件写入，
    避免在事件循环中执行阻塞 I/O。
    """
    if device_id not in saved_device_ids:
        saved_device_ids.add(device_id)
        if ghass is not None:
            ghass.loop.run_in_executor(None, _write_device_id_to_file, device_id)
        elif saved_device_file:
            with open(saved_device_file, "a") as f:
                f.write(device_id + '\n')


def _write_device_id_to_file(device_id: str):
    """在后台线程中执行文件写入"""
    try:
        if not saved_device_file:
            _LOGGER.warning("saved_device_file is not set, cannot persist device_id")
            return
        with open(saved_device_file, "a") as f:
            f.write(device_id + '\n')
    except Exception as e:
        _LOGGER.error(f"Failed to save device_id {device_id}: {e}")


def _add_excluded_device(sn: str):
    """添加排除设备并持久化"""
    if sn not in _excluded_device_sns:
        _excluded_device_sns.add(sn)
        if ghass is not None:
            ghass.loop.run_in_executor(None, _write_excluded_device_to_file, sn)
        elif excluded_devices_file:
            with open(excluded_devices_file, "a") as f:
                f.write(sn + '\n')


def _write_excluded_device_to_file(sn: str):
    """在后台线程中写入排除设备"""
    try:
        if not excluded_devices_file:
            return
        with open(excluded_devices_file, "a") as f:
            f.write(sn + '\n')
    except Exception as e:
        _LOGGER.error(f"Failed to save excluded device {sn}: {e}")


def _remove_excluded_device(sn: str):
    """移除排除设备并持久化"""
    if sn in _excluded_device_sns:
        _excluded_device_sns.discard(sn)
        if ghass is not None:
            ghass.loop.run_in_executor(None, _rewrite_excluded_devices_file)
        elif excluded_devices_file:
            _rewrite_excluded_devices_file()


def _rewrite_excluded_devices_file():
    """重写排除设备文件（在后台线程中执行）"""
    try:
        if not excluded_devices_file:
            return
        with open(excluded_devices_file, "w") as f:
            for sn in _excluded_device_sns:
                f.write(sn + '\n')
    except Exception as e:
        _LOGGER.error(f"Failed to rewrite excluded devices file: {e}")


def _load_or_create_ac(device_ac_file: str) -> bytes:
    """加载或创建 A_C（48字节随机字符串）

    优先从 device_ac 文件读取已保存的 ac，避免每次启动重新生成。
    如果文件不存在，则生成新的 ac 并保存到文件供下次使用。

    Args:
        device_ac_file: device_ac 文件路径

    Returns:
        48 字节的 ac 数据
    """
    if os.path.exists(device_ac_file):
        try:
            with open(device_ac_file, 'rb') as f:
                ac = f.read()
            if len(ac) != 48:
                _LOGGER.warning(f"device_ac file has invalid ac length {len(ac)}, regenerating")
                ac = os.urandom(48)
                _save_ac_to_file(device_ac_file, ac)
            else:
                _LOGGER.info("Loaded AC from device_ac file")
            return ac
        except Exception as e:
            _LOGGER.error(f"Failed to load AC from device_ac file: {e}, regenerating")
            ac = os.urandom(48)
            _save_ac_to_file(device_ac_file, ac)
            return ac
    else:
        ac = os.urandom(48)
        _save_ac_to_file(device_ac_file, ac)
        _LOGGER.info("Generated new AC and saved to device_ac file")
        return ac


def _save_ac_to_file(device_ac_file: str, ac: bytes):
    """保存 ac 到 device_ac 文件"""
    try:
        os.makedirs(os.path.dirname(device_ac_file), exist_ok=True)
        with open(device_ac_file, 'wb') as f:
            f.write(ac)
    except Exception as e:
        _LOGGER.error(f"Failed to save AC to device_ac file: {e}")


def get_network_info() -> dict[str, str]:
    """获取本机网络接口信息"""
    interfaces = psutil.net_if_addrs()
    results: dict[str, str] = {}
    for name, addresses in interfaces.items():
        if name == 'hassio' or name.startswith('docker'):
            continue
        for address in addresses:
            if (
                address.family != socket.AF_INET
                or not address.address
                or not address.netmask
            ):
                continue
            if address.address == '127.0.0.1':
                continue
            results[name] = address.address
    return results
