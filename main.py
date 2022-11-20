#!/usr/bin/env python
import json
import re
import time
from hashlib import sha256
from pprint import pprint

import requests as requests
from Crypto.Cipher import AES

URL = "http://speedport.ip"


class WlanDevice(dict):
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Speedport:
    def __init__(self):
        self._default_key = "cdc0cac1280b516e674f0057e4929bca84447cca8425007e33a88a5cf598a190"
        self._login_key = ""
        self._httoken = ""
        self._cookies = {}

    def decode(self, data, key="", to_json=True):
        key = key or self._default_key
        ciphertext_tag = bytes.fromhex(data)
        cipher = AES.new(bytes.fromhex(key), AES.MODE_CCM, bytes.fromhex(key)[:8])
        decrypted = cipher.decrypt_and_verify(ciphertext_tag[:-16], ciphertext_tag[-16:])
        return json.loads(decrypted.decode()) if to_json else decrypted.decode()

    def encode(self, data, key=""):
        key = key or self._default_key
        cipher = AES.new(bytes.fromhex(key), AES.MODE_CCM, bytes.fromhex(key)[:8])
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return ciphertext.hex() + tag.hex()

    def get(self, path, key="", to_json=True):
        response = requests.get(f"{URL}/{path}", cookies=self._cookies).text
        return self.decode(response, key=key, to_json=to_json)

    def post(self, path, data, key="", to_json=True):
        data = self.encode(f"{data}&httoken={self._httoken}", key=key)
        response = requests.post(f"{URL}/{path}", cookies=self._cookies, data=data).text
        return self.decode(response, key=key, to_json=to_json)

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

    def _get_httoken(self):
        if not self._httoken:
            response = requests.get(URL)
            self._httoken = re.findall("_httoken = (\\d+)", response.text)[0]
        return self._httoken

    def _get_login_key(self):
        if not self._login_key:
            data = self.encode(f"getChallenge=1&httoken={self._get_httoken()}")
            response = requests.post(f"{URL}/data/Login.json", data=data)
            self._login_key = self._simplify_response(self.decode(response.text))['challenge']
        return self._login_key

    def login(self, password):
        if not self._cookies:
            data = self.encode(
                "showpw=0&password=" + sha256(f"{self._get_login_key()}:{password}".encode()).hexdigest())
            response = requests.post(f"{URL}/data/Login.json", data=data)
            # pprint(simplify_response(decode(response.text)))
            self._cookies = response.cookies

    @property
    def status(self):
        return self._simplify_response(self.get("data/Status.json"))

    @property
    def devices(self):
        data = self._simplify_response(self.get("data/DeviceList.json"))
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
