#!/usr/bin/env python
import functools
import json
import logging
import re
from datetime import datetime
from hashlib import sha256
from json import JSONDecodeError

import aiohttp
from Crypto.Cipher import AES

from .device import WlanDevice

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.WARNING)


class Speedport:
    def __init__(self, host="speedport.ip", https=False):
        # Is this the default key for everyone or should we parse it?
        self._default_key = "cdc0cac1280b516e674f0057e4929bca84447cca8425007e33a88a5cf598a190"
        self._login_password = ""
        self._login_key = ""
        self._cookies = {}
        self._url = f"https://{host}" if https else f"http://{host}"

    def decode(self, data, key=""):
        key = key or self._default_key
        ciphertext_tag = bytes.fromhex(data)
        cipher = AES.new(bytes.fromhex(key), AES.MODE_CCM, bytes.fromhex(key)[:8])
        decrypted = cipher.decrypt_and_verify(ciphertext_tag[:-16], ciphertext_tag[-16:])
        try:
            return self._simplify_response(json.loads(decrypted.decode()))
        except JSONDecodeError:
            return decrypted.decode()

    def encode(self, data, key=""):
        key = key or self._default_key
        cipher = AES.new(bytes.fromhex(key), AES.MODE_CCM, bytes.fromhex(key)[:8])
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return ciphertext.hex() + tag.hex()

    async def get(self, path, auth=False, referer=""):
        url = f"{self._url}/{path}"
        kwargs = {"cookies": self._cookies}
        if referer:
            referer = f"{self._url}/{referer}"
            kwargs.update({"headers": {"Referer": referer}})
            url += f"?_tn={await self._get_httoken(referer)}"
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
            async with session.get(url, **kwargs) as response:
                _LOGGER.debug(f"GET - {url} - {response.status}")
                key = self._login_key if auth else self._default_key
                return self.decode(await response.text(), key=key)

    async def post(self, path, data, referer):
        url = f"{self._url}/{path}"
        referer = f"{self._url}/{referer}"
        data.update({"httoken": await self._get_httoken(referer)})
        data = "&".join([f"{k}={v}" for k, v in data.items()])
        data = self.encode(data, key=self._login_key)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
            async with session.post(url, cookies=self._cookies, headers={"Referer": referer}, data=data,
                                    timeout=30) as response:
                _LOGGER.debug(f"POST - {url} - {response.status}")
                return self.decode(await response.text(), key=self._login_key)

    async def _get_httoken(self, url):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
            async with session.get(url, cookies=self._cookies) as response:
                _LOGGER.debug(f"GET - {url} - {response.status}")
                return re.findall("_httoken = (\\d+)", await response.text())[0]

    @staticmethod
    def _simplify_response(data):
        result = {}
        for item in data:
            if type(item["varvalue"]) is list:
                list_item = {}
                for i, sub_item in enumerate(item["varvalue"]):
                    list_item[sub_item["varid"]] = sub_item["varvalue"]
                result.setdefault(item["varid"], []).append(list_item)
            else:
                result[item["varid"]] = item["varvalue"]
        return result

    async def _get_login_key(self):
        if not self._login_key:
            self._login_key = (await self.post("data/Login.json", {"getChallenge": "1"}, "/"))['challenge']
        return self._login_key

    async def login(self, password):
        self._login_password = password
        url = f"{self._url}/data/Login.json"
        login_key = sha256(f"{await self._get_login_key()}:{password}".encode()).hexdigest()
        data = self.encode("showpw=0&password=" + login_key)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(verify_ssl=False)) as session:
            async with session.post(url, data=data) as response:
                _LOGGER.debug(f"POST - {url} - {response.status}")
                if result := self.decode(await response.text())["login"] == "success":
                    self._cookies = response.cookies
                return result

    @property
    async def status(self):
        return await self.get("data/Status.json")

    @property
    async def devices(self):
        data = await self.get("data/DeviceList.json")
        devices = data.get("addmlandevice", []) + data.get("addmwlan5device", []) + data.get("addmwlandevice", [])
        devices = sorted(devices, key=lambda d: int(d["mdevice_ipv4"].split(".")[-1]))
        return [WlanDevice(device) for device in devices]

    @staticmethod
    def need_auth(func):
        @functools.wraps(func)
        async def inner(self):
            if not self._login_key:
                _LOGGER.error("You need to login!")
                raise PermissionError("You need to login!")
            return await func(self)

        return inner

    @property
    @need_auth
    async def ip_data(self):
        referer = "html/content/internet/con_ipdata.html"
        return await self.get(f"data/IPData.json", referer=referer, auth=True)

    @property
    @need_auth
    async def wps_state(self):
        referer = "html/content/network/wlan_wps.html"
        return int((await self.get(f"data/WPSStatus.json", referer=referer))["wlan_wps_state"])

    async def _set_wifi(self, on=True, guest=False, office=False):
        """ Set wifi on/off """
        extra = "guest" if guest else "office" if office else ""
        _LOGGER.info(f"Turn {['off', 'on'][bool(on)]} {extra if extra else ''} wifi...")
        data = {f"wlan_{extra}_active": str(int(on))} if extra else {"use_wlan": str(int(on))}
        referer = f"html/content/network/wlan_{extra if extra else 'basic'}.html"
        return await self.post(f"data/{'WLANBasic' if extra else 'Modules'}.json", data, referer)

    @need_auth
    async def wifi_on(self):
        await self._set_wifi(on=True, guest=False)

    @need_auth
    async def wifi_off(self):
        await self._set_wifi(on=False, guest=False)

    @need_auth
    async def wifi_guest_on(self):
        await self._set_wifi(on=True, guest=True)

    @need_auth
    async def wifi_guest_off(self):
        await self._set_wifi(on=False, guest=True)

    @need_auth
    async def wifi_office_on(self):
        await self._set_wifi(on=True, office=True)

    @need_auth
    async def wifi_office_off(self):
        await self._set_wifi(on=False, office=True)

    @need_auth
    async def wps_on(self):
        _LOGGER.info("Enable wps connect...")
        await self.post("data/WLANAccess.json", {"wlan_add": "on", "wps_key": "connect"},
                        "html/content/network/wlan_wps.html")

    @need_auth
    async def reconnect(self):
        _LOGGER.info("Reconnect with internet provider...")
        await self.post("data/Connect.json", {"req_connect": "reconnect"}, "html/content/internet/con_ipdata.html")

    @need_auth
    async def reboot(self):
        _LOGGER.info("Reboot speedport...")
        await self.post("data/Reboot.json", {"reboot_device": "true"}, "html/content/config/restart.html")

    @property
    async def device_name(self):
        return (await self.status).get("device_name", "")

    @property
    async def serial_number(self):
        return (await self.status).get("serial_number", "")

    @property
    async def firmware_version(self):
        return (await self.status).get("firmware_version", "")

    @property
    async def dsl_downstream(self):
        return int((await self.status).get("dsl_downstream", "0"))

    @property
    async def dsl_upstream(self):
        return int((await self.status).get("dsl_upstream", "0"))

    @property
    async def inet_download(self):
        return int((await self.status).get("inet_download", "0"))

    @property
    async def inet_upload(self):
        return int((await self.status).get("inet_upload", "0"))

    @property
    async def inet_uptime(self):
        return datetime.fromisoformat((await self.status).get("inet_uptime"))

    @property
    async def onlinestatus(self):
        return (await self.status).get("onlinestatus", "")

    @property
    async def loginstate(self):
        return bool((await self.status).get("loginstate"))

    @property
    async def rebooting(self):
        return bool((await self.status).get("rebooting"))

    @property
    async def wlan_active(self):
        return bool((await self.status).get("use_wlan"))

    @property
    async def wlan_guest_active(self):
        return bool((await self.status).get("wlan_guest_active"))

    @property
    async def wlan_office_active(self):
        return bool((await self.status).get("wlan_office_active"))

    @property
    async def dns_v4(self):
        return (await self.ip_data).get("dns_v4", "")

    @property
    async def dns_v6(self):
        return (await self.ip_data).get("dns_v6", "")

    @property
    async def gateway_ip_v4(self):
        return (await self.ip_data).get("gateway_ip_v4", "")

    @property
    async def gateway_ip_v6(self):
        return (await self.ip_data).get("gateway_ip_v6", "")

    @property
    async def public_ip_v4(self):
        return (await self.ip_data).get("public_ip_v4", "")

    @property
    async def public_ip_v6(self):
        return (await self.ip_data).get("public_ip_v6", "")

    @property
    async def sec_dns_v4(self):
        return (await self.ip_data).get("sec_dns_v4", "")

    @property
    async def sec_dns_v6(self):
        return (await self.ip_data).get("sec_dns_v6", "")

    @property
    async def transmitted_ip_v6_pool_for_lan(self):
        return (await self.ip_data).get("transmitted_ip_v6_pool_for_lan", "")

    @property
    async def used_ip_v6_lan(self):
        return (await self.ip_data).get("used_ip_v6_lan", "")
