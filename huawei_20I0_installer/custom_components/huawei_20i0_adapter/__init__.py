"""把 prod_20I0.py 复制到 huawei_smarthome 的 device_adapters 目录。

HA 启动时自动执行一次，成功后在日志里留一条提示。
复制完成需要再重启一次 HA（或重载 Huawei SmartHome 集成）才会生效。
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

DOMAIN = "huawei_20i0_adapter"
ADAPTER_FILE = "prod_20I0.py"


async def async_setup(hass, config):  # noqa: D103
    """HA 启动时执行：安装适配器文件。"""
    source = Path(__file__).parent / ADAPTER_FILE
    target_dir = Path(
        hass.config.path(
            "custom_components", "huawei_smarthome", "device_adapters"
        )
    )
    target = target_dir / ADAPTER_FILE

    def _install() -> tuple[bool, str]:
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        except OSError as err:
            return False, str(err)
        return target.is_file(), str(target)

    ok, detail = await hass.async_add_executor_job(_install)

    if ok:
        _LOGGER.warning(
            "[20I0] 台灯适配器已写入 %s —— 请重启 Home Assistant，"
            "再到 设置 > 设备与服务 > Huawei SmartHome 点「重新加载」，"
            "台灯的实体就会出现",
            detail,
        )
    else:
        _LOGGER.error(
            "[20I0] 台灯适配器写入失败：%s —— 请检查 huawei_smarthome 集成是否已安装",
            detail,
        )
    return True
