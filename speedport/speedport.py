import functools
import logging
from datetime import datetime

from .api import SpeedportApi
from .device import WlanDevice

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.WARNING)


class LoginException(Exception):
    pass


def need_auth(func):
    @functools.wraps(func)
    async def inner(self):
        if not self._login_key:
            _LOGGER.error("You need to login!")
            raise PermissionError("You need to login!")
        return await func(self)

    return inner


class Speedport:
    def __init__(self, **kwargs):
        self._api_kwargs = kwargs
        self._api: SpeedportApi | None = None
        self._status = {}
        self._ip_data = {}

    async def __aenter__(self):
        await self.create()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def create(self):
        self._api = await SpeedportApi(**self._api_kwargs).create()

    async def close(self):
        if self._api:
            await self._api.close()

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

    async def wifi_on(self):
        await self.api.set_wifi(status=True, guest=False)

    async def wifi_off(self):
        await self.api.set_wifi(status=False, guest=False)

    async def wifi_guest_on(self):
        await self.api.set_wifi(status=True, guest=True)

    async def wifi_guest_off(self):
        await self.api.set_wifi(status=False, guest=True)

    async def wifi_office_on(self):
        await self.api.set_wifi(status=True, office=True)

    async def wifi_office_off(self):
        await self.api.set_wifi(status=False, office=True)

    async def update_ip_data(self):
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
    def onlinestatus(self):
        return self._status.get("onlinestatus", "")

    @property
    def loginstate(self):
        return bool(self._status.get("loginstate"))

    @property
    def rebooting(self):
        return bool(self._status.get("rebooting"))

    @property
    def wlan_active(self):
        return bool(self._status.get("use_wlan"))

    @property
    def wlan_guest_active(self):
        return bool(self._status.get("wlan_guest_active"))

    @property
    def wlan_office_active(self):
        return bool(self._status.get("wlan_office_active"))

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
