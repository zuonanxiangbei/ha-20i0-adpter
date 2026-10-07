"""华为智选 欧普智能台灯 Pro（prodId 20I0，型号 MT615-D20WTT）适配器。

依据该产品公开 Profile（smarthome-drcn.dbankcdn.com/device/guide/20I0/20I0.json）编写，
字段与取值范围均取自 Profile 实际声明，未经真实设备逐项验证。

实体映射：
  * 主灯           -> HA light（开关 / 亮度 3-255 / 色温 3000-5000K）
  * lightMode      -> select「灯光模式」：阅读 / 书写 / 最爱 / 智能 / 夜间唤醒
  * nightMode      -> switch「夜灯」（enable 开关；起止时间不投影）
  * studyMode      -> switch「学习模式开关」 + select「学习模式」：番茄 / 课堂 / 考试 / 自定义
  * studyMode 时长、studyResult、timer、delay、update、netInfo -> 不投影
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .api import EntitySpec
from .context import DeviceContext

PROD_ID = "20I0"


def _field(
    profile: Mapping[str, Any], sid: str, name: str
) -> Mapping[str, Any] | None:
    for service in profile.get("services", ()):
        if not isinstance(service, Mapping) or service.get("serviceId") != sid:
            continue
        for field in service.get("characteristics", ()):
            if isinstance(field, Mapping) and field.get("characteristicName") == name:
                return field
    return None


def _number(value: Any) -> int | float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else number


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.strip().casefold() in {"1", "true", "on"}:
            return True
        if value.strip().casefold() in {"0", "false", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _range(field: Mapping[str, Any] | None) -> tuple[float, float] | None:
    if field is None:
        return None
    minimum = _number(field.get("min"))
    maximum = _number(field.get("max"))
    if minimum is None or maximum is None or maximum <= minimum:
        return None
    return float(minimum), float(maximum)


def _payload_number(value: Any, field: Mapping[str, Any]) -> Any:
    """按 Profile 声明的类型回写（int/enum 取整，其余原样）。"""
    number = _number(value)
    if number is None:
        return value
    if str(field.get("characteristicType") or "").casefold() in {
        "int",
        "integer",
        "enum",
    }:
        return int(round(number))
    return number


def _device_brightness_to_ha(value: Any, field: Mapping[str, Any]) -> int | None:
    """设备亮度（Profile 3..255）-> HA 1..255。"""
    number = _number(value)
    value_range = _range(field)
    if number is None or value_range is None:
        return None
    minimum, maximum = value_range
    number = min(max(float(number), minimum), maximum)
    return round(1 + (number - minimum) * 254 / (maximum - minimum))


def _ha_brightness_to_device(value: Any, field: Mapping[str, Any]) -> Any:
    number = _number(value)
    value_range = _range(field)
    if number is None or value_range is None:
        raise ValueError("20I0 brightness range is missing from the Profile")
    minimum, maximum = value_range
    number = min(max(float(number), 1.0), 255.0)
    return _payload_number(
        minimum + (number - 1) * (maximum - minimum) / 254, field
    )


def _enum_options(field: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    options: list[tuple[str, Any]] = []
    for item in field.get("enumList", ()):
        if not isinstance(item, Mapping) or item.get("enumVal") is None:
            continue
        label = item.get("descCh") or item.get("descEn") or item.get("enumVal")
        options.append((str(label), item["enumVal"]))
    return tuple(options)


def _enum_label(field: Mapping[str, Any], value: Any) -> str | None:
    number = _number(value)
    for label, raw in _enum_options(field):
        if number is not None and _number(raw) == number:
            return label
    return None


async def _turn_on(context: DeviceContext, data: Mapping[str, Any]) -> None:
    await context.async_send_service("switch", {"on": 1})
    profile = context.profile or {}

    # 先亮度后色温，与固件写入顺序习惯保持一致
    brightness = _field(profile, "brightness", "brightness")
    if data.get("brightness") is not None and brightness is not None:
        await context.async_send_service(
            "brightness",
            {"brightness": _ha_brightness_to_device(data["brightness"], brightness)},
        )

    cct = _field(profile, "cct", "colorTemperature")
    if data.get("color_temp_kelvin") is not None and cct is not None:
        value_range = _range(cct)
        value = _number(data["color_temp_kelvin"])
        if value_range is not None and value is not None:
            value = min(max(value, value_range[0]), value_range[1])
            await context.async_send_service(
                "cct", {"colorTemperature": _payload_number(value, cct)}
            )


async def _turn_off(context: DeviceContext, _data: Mapping[str, Any]) -> None:
    await context.async_send_service("switch", {"on": 0})


class OppleDeskLampProAdapter:
    """华为智选 欧普智能台灯 Pro."""

    prod_id = PROD_ID

    def entities(self, context: DeviceContext) -> tuple[EntitySpec, ...]:
        profile = context.profile
        if profile is None:
            return ()
        specs: list[EntitySpec] = []

        switch = _field(profile, "switch", "on")
        brightness = _field(profile, "brightness", "brightness")
        cct = _field(profile, "cct", "colorTemperature")
        brightness_range = _range(brightness)
        cct_range = _range(cct)

        # ---- 主灯 ----
        if switch is not None:
            mode = (
                "color_temp"
                if cct_range is not None
                else "brightness"
                if brightness_range is not None
                else "onoff"
            )

            def light_state(
                device: DeviceContext,
                _brightness: Mapping[str, Any] = brightness or {},
                _brightness_range: tuple[float, float] | None = brightness_range,
                _cct_range: tuple[float, float] | None = cct_range,
                _mode: str = mode,
            ) -> Mapping[str, Any]:
                return {
                    "is_on": _bool(device.value("switch", "on")),
                    "brightness": (
                        _device_brightness_to_ha(
                            device.value("brightness", "brightness"),
                            _brightness,
                        )
                        if _brightness_range is not None
                        else None
                    ),
                    "color_temp_kelvin": (
                        _number(device.value("cct", "colorTemperature"))
                        if _cct_range is not None
                        else None
                    ),
                    "color_mode": _mode,
                }

            metadata: dict[str, Any] = {"supported_color_modes": {mode}}
            if cct_range is not None:
                metadata.update(
                    {
                        "min_color_temp_kelvin": int(cct_range[0]),
                        "max_color_temp_kelvin": int(cct_range[1]),
                    }
                )
            specs.append(
                EntitySpec(
                    platform="light",
                    key="light",
                    name=None,
                    state=light_state,
                    metadata=metadata,
                    actions={"turn_on": _turn_on, "turn_off": _turn_off},
                )
            )

        # ---- 开关型：nightMode.enable / studyMode.enable ----
        for sid, key, name in (
            ("nightMode", "night_light", "夜灯"),
            ("studyMode", "study_switch", "学习模式"),
        ):
            if _field(profile, sid, "enable") is None:
                continue

            async def switch_on(
                device: DeviceContext, _data: Mapping[str, Any], _sid: str = sid
            ) -> None:
                await device.async_send_service(_sid, {"enable": 1})

            async def switch_off(
                device: DeviceContext, _data: Mapping[str, Any], _sid: str = sid
            ) -> None:
                await device.async_send_service(_sid, {"enable": 0})

            specs.append(
                EntitySpec(
                    platform="switch",
                    key=key,
                    name=name,
                    state=lambda device, _sid=sid: {
                        "is_on": _bool(device.value(_sid, "enable"))
                    },
                    actions={"turn_on": switch_on, "turn_off": switch_off},
                )
            )

        # ---- 选择型：lightMode.mode / studyMode.mode ----
        for sid, key, name in (
            ("lightMode", "light_mode", "灯光模式"),
            ("studyMode", "study_mode", "学习模式"),
        ):
            mode_field = _field(profile, sid, "mode")
            options = _enum_options(mode_field) if mode_field is not None else ()
            if mode_field is None or not options:
                continue

            async def select_option(
                device: DeviceContext,
                data: Mapping[str, Any],
                _sid: str = sid,
                _field_def: Mapping[str, Any] = mode_field,
                _options: tuple[tuple[str, Any], ...] = options,
            ) -> None:
                option = str(data.get("option"))
                for label, raw in _options:
                    if label == option:
                        await device.async_send_service(
                            _sid,
                            {"mode": _payload_number(raw, _field_def)},
                        )
                        return
                raise ValueError(f"20I0 unknown {sid}: {option}")

            specs.append(
                EntitySpec(
                    platform="select",
                    key=key,
                    name=name,
                    state=lambda device, _sid=sid, _field_def=mode_field: {
                        "current_option": _enum_label(
                            _field_def, device.value(_sid, "mode")
                        )
                    },
                    metadata={"options": tuple(label for label, _ in options)},
                    actions={"select_option": select_option},
                )
            )

        return tuple(specs)


ADAPTER = OppleDeskLampProAdapter()
