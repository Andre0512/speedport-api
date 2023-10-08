import logging

from speedport.connection import Connection

_LOGGER = logging.getLogger(__name__)


class SpeedportApi:
    def __init__(self, **kwargs):
        self._api_kwargs = kwargs
        self._api: Connection | None = None

    async def __aenter__(self):
        return await self.create()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def create(self):
        self._api = await Connection(**self._api_kwargs).create()
        return self

    async def close(self):
        if self._api:
            await self._api.close()

    @property
    def api(self) -> Connection:
        if self._api:
            return self._api
        raise ConnectionError()

    async def get_status(self):
        return await self.api.get("data/Status.json")

    async def get_devices(self):
        return await self.api.get("data/DeviceList.json")

    async def get_ip_data(self):
        referer = "html/content/internet/con_ipdata.html"
        return await self.api.get("data/IPData.json", referer=referer, auth=True)

    async def get_wps_state(self):
        referer = "html/content/network/wlan_wps.html"
        return int(
            (await self.api.get("data/WPSStatus.json", referer=referer))[
                "wlan_wps_state"
            ]
        )

    async def set_wifi(self, status: bool, guest=False, office=False):
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

    async def wps_on(self):
        _LOGGER.info("Enable wps connect...")
        await self.api.post(
            "data/WLANAccess.json",
            {"wlan_add": "on", "wps_key": "connect"},
            "html/content/network/wlan_wps.html",
        )

    async def reconnect(self):
        _LOGGER.info("Reconnect with internet provider...")
        await self.api.post(
            "data/Connect.json",
            {"req_connect": "reconnect"},
            "html/content/internet/con_ipdata.html",
        )

    async def reboot(self):
        _LOGGER.info("Reboot speedport...")
        await self.api.post(
            "data/Reboot.json",
            {"reboot_device": "true"},
            "html/content/config/restart.html",
        )
