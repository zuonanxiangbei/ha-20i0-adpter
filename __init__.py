"""把 prod_20I0.py 复制到 huawei_smarthome 的 device_adapters 目录。

触发方式（任一即可）：
1. UI 添加集成（推荐）：设置 > 设备与服务 > 添加集成 > 搜 huawei_20i0，
   点「提交」即安装 —— 由 config_flow 创建 entry，走 async_setup_entry。
2. YAML 方式：configuration.yaml 里写一行 `huawei_20i0_adapter:`，走 async_setup。
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

DOMAIN = "huawei_20i0_adapter"
ADAPTER_FILE = "prod_20I0.py"


def _install(hass: HomeAssistant) -> tuple[bool, str]:
    """把适配器文件复制到华为集成的 device_adapters 目录。"""
    source = Path(__file__).parent / ADAPTER_FILE
    target_dir = Path(
        hass.config.path(
            "custom_components", "huawei_smarthome", "device_adapters"
        )
    )
    target = target_dir / ADAPTER_FILE
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    except OSError as err:
        return False, str(err)
    return target.is_file(), str(target)


async def async_setup_entry(hass: HomeAssistant, entry) -> bool:
    """UI 添加集成时执行：复制适配器文件。"""
    ok, detail = await hass.async_add_executor_job(_install, hass)
    if ok:
        _LOGGER.warning(
            "[20I0] 台灯适配器已写入 %s —— 请重启 Home Assistant，"
            "再到 设置 > 设备与服务 > Huawei SmartHome 点「重新加载」，"
            "台灯的实体就会出现",
            detail,
        )
    else:
        _LOGGER.error(
            "[20I0] 台灯适配器写入失败：%s —— 请确认 huawei_smarthome 集成已安装",
            detail,
        )
    return True


async def async_unload_entry(hass: HomeAssistant, entry) -> bool:
    """卸载无需处理（复制出去的文件保留，不影响华为集成运行）。"""
    return True


async def async_setup(hass: HomeAssistant, config) -> bool:
    """YAML 方式触发（configuration.yaml 里写了 huawei_20i0_adapter: 时）。"""
    await async_setup_entry(hass, None)
    return True
