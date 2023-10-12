import asyncio
import json
import logging
import re
from hashlib import sha256
from json import JSONDecodeError
from typing import Self

import aiohttp
from Crypto.Cipher import AES

from speedport import const, exceptions

_LOGGER = logging.getLogger(__name__)


def decode(data, key: str = "") -> dict[str, list | dict | str] | str:
    """Decode speedport's self-implemented encryption"""
    key = key or const.DEFAULT_KEY
    try:
        ciphertext_tag = bytes.fromhex(data)
    except ValueError as exc:
        raise exceptions.DecryptionKeyError("Wrong decryption key") from exc
    cipher = AES.new(bytes.fromhex(key), AES.MODE_CCM, bytes.fromhex(key)[:8])
    decrypted = cipher.decrypt_and_verify(ciphertext_tag[:-16], ciphertext_tag[-16:])
    try:
        return simplify_response(json.loads(decrypted.decode()))
    except JSONDecodeError:
        return decrypted.decode()


def encode(data, key: str = "") -> str:
    """Encode for speedport's self-implemented encryption"""
    key = key or const.DEFAULT_KEY
    cipher = AES.new(bytes.fromhex(key), AES.MODE_CCM, bytes.fromhex(key)[:8])
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return ciphertext.hex() + tag.hex()


def simplify_response(
    data: list[dict[str, str | list[dict[str, str]]]]
) -> dict[str, list | dict | str]:
    """Remove 'varid' and 'varvalue' to have a flatter data structure without overhead"""
    result = {}
    for item in data:
        if isinstance(item["varvalue"], list):
            list_item = {}
            for sub_item in item["varvalue"]:
                list_item[sub_item["varid"]] = sub_item["varvalue"]
            result.setdefault(item["varid"], []).append(list_item)
        else:
            result[item["varid"]] = item["varvalue"]
    return result


class Connection:
    def __init__(
        self,
        host: str = "speedport.ip",
        https: bool = False,
        session: aiohttp.ClientSession | None = None,
    ):
        self._login_key = ""
        self._cookies = {}
        self._url = f"https://{host}" if https else f"http://{host}"
        self._session: aiohttp.ClientSession | None = session

    async def __aenter__(self):
        return await self.create()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def create(self) -> Self:
        """Create aiohttp session"""
        connector = aiohttp.TCPConnector(verify_ssl=False)
        self._session = aiohttp.ClientSession(connector=connector)
        return self

    async def close(self):
        """Close aiohttp session"""
        if self._session:
            await self._session.close()

    async def get(self, path: str, auth: bool = False, referer: str = ""):
        url = f"{self._url}/{path}"
        kwargs = {"cookies": self._cookies}
        if referer:
            referer = f"{self._url}/{referer}"
            kwargs.update({"headers": {"Referer": referer}})
            url += f"?_tn={await self._get_httoken(referer)}"
        async with self._session.get(url, **kwargs) as response:
            _LOGGER.debug("GET - %s - %s", url, response.status)
            key = self._login_key if auth else const.DEFAULT_KEY
            return decode(await response.text(), key=key)

    async def post(self, path: str, data: dict[str, str], referer: str):
        url = f"{self._url}/{path}"
        referer = f"{self._url}/{referer}"
        data.update({"httoken": await self._get_httoken(referer)})
        data = "&".join([f"{k}={v}" for k, v in data.items()])
        data = encode(data, key=self._login_key)
        async with self._session.post(
            url,
            cookies=self._cookies,
            headers={"Referer": referer},
            data=data,
            timeout=30,
        ) as response:
            _LOGGER.debug("POST - %s - %s", url, response.status)
            return decode(await response.text(), key=self._login_key)

    async def _get_httoken(self, url: str):
        async with self._session.get(url, cookies=self._cookies) as response:
            _LOGGER.debug("GET - %s - %s", url, response.status)
            return re.findall("_httoken = (\\d+)", await response.text())[0]

    async def _get_login_key(self):
        data = {"getChallenge": "1"}
        if response := await self.post("data/Login.json", data, "/"):
            self._login_key = response["challenge"]
        return self._login_key

    async def login(self, password: str):
        url = f"{self._url}/data/Login.json"
        self.clear()
        login_data = f"{await self._get_login_key()}:{password}".encode()
        login_key = sha256(login_data).hexdigest()
        data = encode("showpw=0&password=" + login_key)
        async with self._session.post(url, data=data) as response:
            _LOGGER.debug("POST - %s - %s", url, response.status)
            result = decode(await response.text())
            _LOGGER.debug(result)
        if result["login"] == "success":
            self._cookies = response.cookies
        elif (sleep_time := result.get("login_locked")) and int(sleep_time) < 60:
            _LOGGER.warning("Can't login, wait %ss...", sleep_time)
            await asyncio.sleep(int(sleep_time) + 1)
            return await self.login(password)
        else:
            _LOGGER.error(result)
            raise exceptions.LoginException("Can't login")
        return result["login"]

    @property
    def is_logged_in(self):
        return bool(self._login_key)

    def clear(self):
        self._login_key = ""
        self._session.cookie_jar.clear_domain(self._url)