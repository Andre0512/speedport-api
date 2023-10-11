import functools
import logging

import aiohttp

from speedport import exceptions
from speedport.connection import Connection

_LOGGER = logging.getLogger(__name__)


def need_auth(func):
    @functools.wraps(func)
    async def inner(self: "SpeedportApi", *args, **kwargs):
        if not self.api.is_logged_in:
            if not self.password:
                error = f'You need to set a password to use "{func.__name__}"'
                _LOGGER.error(error)
                raise PermissionError(error)
            await self.api.login(self.password)
        try:
            return await func(self, *args, **kwargs)
        except exceptions.DecryptionKeyError:
            await self.api.login(self.password)
            return await func(self, *args, **kwargs)

    return inner


class SpeedportApi:
    def __init__(
        self,
        host: str = "speedport.ip",
        password: str = "",
        https: bool = False,
        session: aiohttp.ClientSession | None = None,
    ):
        self._api: Connection | None = None
        self._host: str = host
        self._password: str = password
        self._https: bool = https
        self._session: aiohttp.ClientSession | None = session

    async def __aenter__(self):
        return await self.create()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def create(self):
        self._api = await Connection(self._host, self._https, self._session).create()
        return self

    async def close(self):
        if self._api:
            await self._api.close()

    @property
    def api(self) -> Connection:
        if self._api:
            return self._api
        raise ConnectionError()

    @property
    def password(self) -> str:
        return self._password

    async def get_status(self):
        return await self.api.get("data/Status.json")

    async def get_devices(self):
        return await self.api.get("data/DeviceList.json")

    async def get_ip_data(self):
        referer = "html/content/internet/con_ipdata.html"
        return await self.api.get("data/IPData.json", referer=referer, auth=True)

    @need_auth
    async def get_wps_state(self):
        referer = "html/content/network/wlan_wps.html"
        return await self.api.get("data/WPSStatus.json", referer=referer)

    @need_auth
    async def set_wifi(self, status=True, guest=False, office=False):
        """Set wifi on/off"""
        extra = "guest" if guest else "office" if office else ""
        _LOGGER.info(
            "Turn %s %s wifi...", ["off", "on"][bool(status)], extra if extra else ""
        )
        data = (
            {f"wlan_{extra}_active": str(int(status))}
            if extra
            else {"use_wlan": str(int(status))}
        )
        referer = f"html/content/network/wlan_{extra if extra else 'basic'}.html"
        return await self.api.post(
            f"data/{'WLANBasic' if extra else 'Modules'}.json", data, referer
        )

    @need_auth
    async def wps_on(self):
        _LOGGER.info("Enable wps connect...")
        await self.api.post(
            "data/WLANAccess.json",
            {"wlan_add": "on", "wps_key": "connect"},
            "html/content/network/wlan_wps.html",
        )

    @need_auth
    async def reconnect(self):
        _LOGGER.info("Reconnect with internet provider...")
        await self.api.post(
            "data/Connect.json",
            {"req_connect": "reconnect"},
            "html/content/internet/con_ipdata.html",
        )

    @need_auth
    async def reboot(self):
        _LOGGER.info("Reboot speedport...")
        await self.api.post(
            "data/Reboot.json",
            {"reboot_device": "true"},
            "html/content/config/restart.html",
        )

    async def login(self, password=""):
        return await self.api.login(password or self.password)
