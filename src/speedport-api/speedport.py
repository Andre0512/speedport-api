#!/usr/bin/env python
import json
import logging
import re
from hashlib import sha256
from json import JSONDecodeError

import requests as requests
from Crypto.Cipher import AES

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.WARNING)


class WlanDevice(dict):
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Speedport:
    def __init__(self, host="speedport-api.ip"):
        # Is this the default key for everyone or should we parse it?
        self._default_key = "cdc0cac1280b516e674f0057e4929bca84447cca8425007e33a88a5cf598a190"
        self._login_key = ""
        self._cookies = {}
        self._url = f"http://{host}"

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

    def get(self, path, key="", referer=""):
        url = f"{self._url}/{path}"
        kwargs = {"cookies": self._cookies}
        if referer:
            referer = f"{self._url}/{referer}"
            kwargs.update({"headers": {"Referer": referer}})
            url += f"?_tn={self._get_httoken(referer)}"
        response = requests.get(url, **kwargs)
        _LOGGER.debug(f"GET - {url} - {response.status_code}")
        return self.decode(response.text, key=key)

    def post(self, path, data, referer):
        url = f"{self._url}/{path}"
        referer = f"{self._url}/{referer}"
        data = self.encode(f"{data}&httoken={self._get_httoken(referer)}", key=self._login_key)
        response = requests.post(url, cookies=self._cookies, headers={"Referer": referer}, data=data)
        _LOGGER.debug(f"POST - {url} - {response.status_code}")
        return self.decode(response.text, key=self._login_key)

    def _get_httoken(self, url):
        response = requests.get(url, cookies=self._cookies)
        _LOGGER.debug(f"GET - {url} - {response.status_code}")
        return re.findall("_httoken = (\\d+)", response.text)[0]

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

    def _get_login_key(self):
        if not self._login_key:
            self._login_key = self.post("data/Login.json", "getChallenge=1", "/")['challenge']
        return self._login_key

    def login(self, password):
        """  """
        if not self._login_key:
            url = f"{self._url}/data/Login.json"
            login_key = sha256(f"{self._get_login_key()}:{password}".encode()).hexdigest()
            data = self.encode("showpw=0&password=" + login_key)
            response = requests.post(url, data=data)
            _LOGGER.debug(f"POST - {url} - {response.status_code}")
            self._cookies = response.cookies

    @property
    def status(self):
        return self.get("data/Status.json")

    @property
    def devices(self):
        data = self.get("data/DeviceList.json")
        result = []
        devices = data.get("addmlandevice", []) + data.get("addmwlan5device", []) + data.get("addmwlandevice", [])
        for device in devices:
            new = WlanDevice()
            for item, value in device.items():
                if "mdevice_" in item:
                    item = item.replace("mdevice_", "")
                    new[item] = device[f"mdevice_{item}"]
                if item in ["connected", "fix_dhcp", "slave", "use_dhcp"]:
                    new[item] = bool(int(value))
                if item in ["downspeed", "hasui", "rssi", "upspeed", "wifi"]:
                    new[item] = int(value)
            new["type"] = ["lan", "wlan", "wlan5"][int(device["mdevice_type"])]
            result.append(new)
        return result

    @property
    def ip_data(self):
        referer = "html/content/internet/con_ipdata.html"
        return self.get(f"data/IPData.json", referer=referer, key=self._login_key)

    @property
    def wps_state(self):
        referer = "html/content/network/wlan_wps.html"
        return self.get(f"data/WPSStatus.json", referer=referer)["wlan_wps_state"]

    def _set_wifi(self, on=True, guest=False):
        """ Set wifi on/off """
        _LOGGER.info(f"Turn {['off', 'on'][bool(on)]}{' guest' if guest else ''} wifi...")
        data = f"wlan_guest_active={int(on)}" if guest else f"use_wlan={int(on)}"
        referer = f"html/content/network/wlan_{'guest' if guest else 'basic'}.html"
        return self.post(f"data/{'WLANBasic' if guest else 'Modules'}.json", data, referer)

    def wifi_on(self):
        self._set_wifi(on=True, guest=False)

    def wifi_off(self):
        self._set_wifi(on=False, guest=False)

    def wifi_guest_on(self):
        self._set_wifi(on=True, guest=True)

    def wifi_guest_off(self):
        self._set_wifi(on=False, guest=True)

    def wps_on(self):
        _LOGGER.info("Enable wps connect for 120 seconds...")
        self.post("data/WLANAccess.json", "wlan_add=on&wps_key=connect", "html/content/network/wlan_wps.html")

    def reconnect(self):
        _LOGGER.info("Reconnect with internet provider...")
        self.post("data/Connect.json", "req_connect=reconnect", "html/content/internet/con_ipdata.html")
