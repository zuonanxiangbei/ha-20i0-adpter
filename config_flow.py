"""UI 添加流程：在「添加集成」里点一下即完成安装。"""

from __future__ import annotations

from homeassistant import config_entries

DOMAIN = "huawei_20i0_adapter"


class Huawei20I0AdapterConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """处理一次性添加流程。"""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """用户点「提交」后创建配置项，由 async_setup_entry 执行安装。"""
        if user_input is not None:
            return self.async_create_entry(
                title="华为智选 欧普智能台灯 Pro (20I0) 适配器",
                data={},
            )
        return self.async_show_form(step_id="user")
