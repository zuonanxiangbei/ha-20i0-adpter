"""hwhomebridge integration entry point."""

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN
from .hwbridge import start_hw_hilink_bridge, nullify_hilink_callbacks

_LOGGER = logging.getLogger(__name__)

DIAG_SERVICE = "netdiag"


async def _async_netdiag_log() -> None:
    """把网络发现相关的运行时状态打到 ERROR 级日志，便于远程读取 /api/error_log。"""
    import subprocess as sp
    import socket as sock_mod
    import struct as struct_mod

    def run(cmd, timeout=25):
        try:
            p = sp.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return "rc=%s | out=%s | err=%s" % (
                p.returncode,
                (p.stdout or "").strip()[:900],
                (p.stderr or "").strip()[:200],
            )
        except Exception as e:  # noqa: BLE001
            return "EXC %s" % e

    _LOGGER.error("DIAG|ifaces: " + run("ls /sys/class/net/"))
    _LOGGER.error("DIAG|mcast_rx: " + run(
        "for i in /sys/class/net/*/statistics/multicast; do printf '%s=' \"$i\"; cat \"$i\"; done"))
    _LOGGER.error("DIAG|rx_pkts: " + run(
        "for i in /sys/class/net/*/statistics/rx_packets; do printf '%s=' \"$i\"; cat \"$i\"; done"))
    _LOGGER.error("DIAG|igmp: " + run("cat /proc/net/igmp 2>&1 | head -20"))
    _LOGGER.error("DIAG|udp: " + run("cat /proc/net/udp 2>&1 | head -30"))
    _LOGGER.error("DIAG|addr: " + run("ip -o -4 addr 2>&1 | head -10"))

    def loop_test():
        try:
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_DGRAM, sock_mod.IPPROTO_UDP)
            s.setsockopt(sock_mod.SOL_SOCKET, sock_mod.SO_REUSEADDR, 1)
            s.bind(("", 45679))
            mreq = struct_mod.pack("4s4s", sock_mod.inet_aton("238.238.238.238"),
                                   sock_mod.inet_aton("0.0.0.0"))
            try:
                s.setsockopt(sock_mod.IPPROTO_IP, sock_mod.IP_ADD_MEMBERSHIP, mreq)
                join = "JOIN OK"
            except Exception as e:  # noqa: BLE001
                join = "JOIN FAIL %s" % e
            s.settimeout(2)
            try:
                s.sendto(b"diag", ("238.238.238.238", 45679))
                got = s.recvfrom(64)
                loop = "LOOPBACK OK %r" % (got[0][:16],)
            except Exception as e:  # noqa: BLE001
                loop = "LOOPBACK FAIL %s" % e
            s.close()
            return "%s | %s" % (join, loop)
        except Exception as e:  # noqa: BLE001
            return "EXC %s" % e

    _LOGGER.error("DIAG|loop: " + loop_test())


async def _async_register_diag_service(hass: HomeAssistant) -> None:
    """注册 netdiag 诊断服务（可重复调用，已注册则跳过）。"""
    if hass.services.has_service(DOMAIN, DIAG_SERVICE):
        return

    async def _handle(call):  # noqa: ARG001
        await _async_netdiag_log()

    hass.services.async_register(DOMAIN, DIAG_SERVICE, _handle)
    _LOGGER.info("netdiag service registered")



async def async_setup(hass: HomeAssistant, config: dict):
    """Set up the hwhomebridge component.

    Called by HA for both YAML and config_flow setups.
    Starts the HiLink bridge.
    """
    _LOGGER.info("async_setup called, starting hwhomebridge integration")
    hass.data.setdefault(DOMAIN, {})
    await _async_register_diag_service(hass)
    await start_hw_hilink_bridge(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Set up hwhomebridge from a config entry.

    Bridged sub-devices are created dynamically by hwbridge.py as they
    are registered to HiLink. If devices were already discovered and
    registered during async_setup (before this function runs), their
    device registry entries are created here retrospectively.
    """
    from .hwbridge import service_router, _create_bridge_device_entry_async, register_hilink_callbacks

    # 重载集成时 async_unload_entry 已 nullify 回调，这里重新注册
    register_hilink_callbacks()

    dev_reg = dr.async_get(hass)

    # 为在 async_setup_entry 之前已注册的设备补建 HA 设备注册表条目
    if service_router is not None:
        for vd in service_router.sn_manager.get_all_devices():
            device_entry = dev_reg.devices.get(vd.ha_device_id)
            name = ""
            model = ""
            manufacturer = ""
            if device_entry:
                name = device_entry.name_by_user or device_entry.name or ""
                model = device_entry.model or ""
                manufacturer = device_entry.manufacturer or ""
            _create_bridge_device_entry_async(vd, name, model, manufacturer)

    _LOGGER.info("hwhomebridge config entry setup complete")
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry - nullify C callbacks to prevent core dump on shutdown."""
    nullify_hilink_callbacks()
    return True


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """集成被永久删除时调用：删除网关、清理持久化文件

    HA 删除流程：先 async_unload_entry（移除实体状态，C 库仍存活），
    再 async_remove_entry（此时 C 库可用，exit_brg 可正常调用）。
    """
    from .hwbridge import stop_hw_hilink_bridge

    # 根据语言选择通知文案
    lang = hass.config.language or "en"
    if lang.startswith("zh"):
        notif_title = "请重启 Home Assistant"
        notif_message = (
            "HuaweiHome Bridge 已删除，如需重新添加本集成，请先重启 Home Assistant。"
            "否则本集成将无法重新正常工作。"
        )
    else:
        notif_title = "Please restart Home Assistant"
        notif_message = (
            "HuaweiHome Bridge has been removed. If you want to re-add this integration, "
            "please restart Home Assistant first, otherwise the integration will not work properly."
        )

    # 先创建重启通知（在 exit_brg 之前，防止 SDK 退出导致进程崩溃后通知丢失）
    try:
        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": notif_title,
                "message": notif_message,
                "notification_id": "hwhomebridge_restart_required",
            },
            blocking=True,
        )
        _LOGGER.info("Restart notification created successfully")
    except Exception as e:
        _LOGGER.error(f"Failed to create restart notification: {e}")
    finally:
        # 确保无论通知是否成功，都执行清理
        await hass.async_add_executor_job(stop_hw_hilink_bridge, hass)
        _LOGGER.info("hwhomebridge integration removed, gateway cleaned up from cloud")
