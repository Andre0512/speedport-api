import functools
import logging
from datetime import datetime, timedelta

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
        except exceptions.DecryptionKeyError as exception:
            if not self.last_logout:
                _LOGGER.info(f"Paused fetching for {self.pause_time} min")
                self.last_logout = datetime.now()
            if datetime.now() > (
                time := self.last_logout + timedelta(minutes=self.pause_time)
            ):
                self.last_logout = None
                await self.api.login(self.password)
                return await func(self, *args, **kwargs)
            remaining = time - datetime.now()
            error = f"Paused for 00:{remaining.seconds // 60:02d}:{remaining.seconds % 60:02d}"
            _LOGGER.debug(error)
            raise exceptions.LoginPausedError(error) from exception

    return inner


class SpeedportApi:
    def __init__(
        self,
        host: str = "speedport.ip",
        password: str = "",
        https: bool = False,
        session: aiohttp.ClientSession | None = None,
        pause_time: int = 5,
    ):
        self._api: Connection | None = None
        self._host: str = host
        self._password: str = password
        self._https: bool = https
        self._url = f"https://{host}" if https else f"http://{host}"
        self._session: aiohttp.ClientSession | None = session
        self._pause_time: int = pause_time
        self._last_logout: datetime | None = None

    async def __aenter__(self):
        return await self.create()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def create(self):
        self._api = await Connection(self._url, self._session).create()
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

    @property
    def url(self) -> str:
        return self._url

    @property
    def pause_time(self) -> int:
        return self._pause_time

    @pause_time.setter
    def pause_time(self, pause_time: int):
        self._pause_time = pause_time

    @property
    def last_logout(self) -> datetime | None:
        return self._last_logout

    @last_logout.setter
    def last_logout(self, last_logout: datetime | None):
        self._last_logout = last_logout

    @need_auth
    async def get_secure_status(self):
        return await self.api.get("data/SecureStatus.json", auth=True)

    @need_auth
    async def get_phone_handler(self):
        return await self.api.get("data/IPPhoneHandler.json", auth=True)

    async def get_router(self):
        return await self.api.get("data/Router.json")

    async def get_status(self):
        return await self.api.get("data/Status.json")

    async def get_devices(self):
        return await self.api.get("data/DeviceList.json")

    async def get_login(self):
        return await self.api.get("data/Login.json")

    @need_auth
    async def get_ip_data(self):
        referer = "html/content/internet/con_ipdata.html"
        return await self.api.get("data/IPData.json", referer=referer, auth=True)

    @need_auth
    async def get_wps_state(self):
        referer = "html/content/network/wlan_wps.html"
        return await self.api.get("data/WPSStatus.json", referer=referer)

    @need_auth
    async def get_phone_calls(self):
        referer = "html/content/phone/phone_call_taken.html"
        return await self.api.get("data/PhoneCalls.json", referer=referer, auth=True)

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
