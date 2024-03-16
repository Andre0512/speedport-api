import logging
from contextlib import suppress
from datetime import datetime

import aiohttp

from . import exceptions
from .api import SpeedportApi
from .call import Call
from .device import WlanDevice

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.WARNING)


class LoginException(Exception):
    pass


class Speedport:
    def __init__(
        self,
        host: str = "speedport.ip",
        password: str = "",
        https: bool = False,
        session: aiohttp.ClientSession | None = None,
        pause_time: int = 5,
    ):
        self._api: SpeedportApi | None = None
        self._host: str = host
        self._password: str = password
        self._https: bool = https
        self._session: aiohttp.ClientSession | None = session
        self._status = {}
        self._ip_data = {}
        self._pause_time = pause_time

    async def __aenter__(self):
        return await self.create()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __getitem__(self, item):
        if (status := self._status.get(item)) is not None:
            return status
        if (ip_data := self._ip_data.get(item)) is not None:
            return ip_data
        raise KeyError

    def get(self, item, default=None):
        try:
            return self[item]
        except KeyError:
            return default

    async def create(self):
        self._api = await SpeedportApi(
            self._host, self._password, self._https, self._session, self._pause_time
        ).create()
        await self.update_status()
        return self

    async def close(self):
        if self._api:
            await self._api.close()

    def set_pause_time(self, pause_time: int):
        if self._api:
            self._api.pause_time = pause_time
        self._pause_time = pause_time

    @property
    def api(self) -> SpeedportApi:
        if self._api:
            return self._api
        raise ConnectionError()

    @property
    async def devices(self) -> dict[str, WlanDevice]:
        data = await self.api.get_devices()
        devices = data.get("addmlandevice", []) + data.get("addmwlan5device", [])
        devices += data.get("addmwlandevice", []) + data.get("addmdevice", [])
        devices = sorted(devices, key=lambda d: int(d["mdevice_ipv4"].split(".")[-1]))
        return {device.get("mdevice_mac"): WlanDevice(device) for device in devices}

    @property
    async def calls(self) -> list[Call]:
        data = await self.api.get_phone_calls()
        types = ["dialedcalls", "missedcalls", "takencalls"]
        result: list[Call] = []
        for call_type in types:
            for call in data.get(f"add{call_type}"):
                result.append(Call(call, call_type))
        result.sort(key=lambda d: d.date)
        return result

    async def wifi_on(self):
        await self.api.set_wifi(status=True, guest=False)

    async def wifi_off(self):
        await self.api.set_wifi(status=False, guest=False)

    async def wps_on(self):
        await self.api.wps_on()

    async def reconnect(self):
        await self.api.reconnect()

    async def reboot(self):
        await self.api.reboot()

    async def wifi_guest_on(self):
        await self.api.set_wifi(status=True, guest=True)

    async def wifi_guest_off(self):
        await self.api.set_wifi(status=False, guest=True)

    async def wifi_office_on(self):
        await self.api.set_wifi(status=True, office=True)

    async def wifi_office_off(self):
        await self.api.set_wifi(status=False, office=True)

    async def update_ip_data(self):
        with suppress(exceptions.LoginPausedError):
            self._ip_data = await self.api.get_ip_data()

    async def update_status(self):
        self._status = await self.api.get_status()

    @property
    def device_name(self):
        return self._status.get("device_name", "")

    @property
    def serial_number(self):
        return self._status.get("serial_number", "")

    @property
    def firmware_version(self):
        return self._status.get("firmware_version", "")

    @property
    def dsl_downstream(self):
        return int(self._status.get("dsl_downstream", "0"))

    @property
    def dsl_upstream(self):
        return int(self._status.get("dsl_upstream", "0"))

    @property
    def inet_download(self):
        return int(self._status.get("inet_download", "0"))

    @property
    def inet_upload(self):
        return int(self._status.get("inet_upload", "0"))

    @property
    def inet_uptime(self):
        return datetime.fromisoformat(self._status.get("inet_uptime"))

    @property
    def online_status(self):
        return self._status.get("onlinestatus", "")

    @property
    def login_state(self):
        return bool(self._status.get("loginstate"))

    @property
    def rebooting(self):
        return bool(self._status.get("rebooting"))

    @property
    def wlan_active(self):
        return bool(int(self._status.get("use_wlan")))

    @property
    def wlan_guest_active(self):
        return bool(int(self._status.get("wlan_guest_active")))

    @property
    def wlan_office_active(self):
        return bool(int(self._status.get("wlan_office_active")))

    @property
    def wlan_ssid(self):
        return self._status.get("wlan_ssid")

    @property
    def wlan_guest_ssid(self):
        return self._status.get("wlan_guest_ssid")

    @property
    def wlan_office_ssid(self):
        return self._status.get("wlan_office_ssid")

    @property
    def dns_v4(self):
        return self._ip_data.get("dns_v4", "")

    @property
    def dns_v6(self):
        return self._ip_data.get("dns_v6", "")

    @property
    def gateway_ip_v4(self):
        return self._ip_data.get("gateway_ip_v4", "")

    @property
    def gateway_ip_v6(self):
        return self._ip_data.get("gateway_ip_v6", "")

    @property
    def public_ip_v4(self):
        return self._ip_data.get("public_ip_v4", "")

    @property
    def public_ip_v6(self):
        return self._ip_data.get("public_ip_v6", "")

    @property
    def sec_dns_v4(self):
        return self._ip_data.get("sec_dns_v4", "")

    @property
    def sec_dns_v6(self):
        return self._ip_data.get("sec_dns_v6", "")

    @property
    def transmitted_ip_v6_pool_for_lan(self):
        return self._ip_data.get("transmitted_ip_v6_pool_for_lan", "")

    @property
    def used_ip_v6_lan(self):
        return self._ip_data.get("used_ip_v6_lan", "")

    @property
    async def wps_remaining(self):
        return int((await self.api.get_wps_state())["wlan_wps_state"])

    async def login(self, password=""):
        return await self.api.login(password or self._password)
