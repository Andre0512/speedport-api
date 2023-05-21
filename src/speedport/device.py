class WlanDevice:
    def __init__(self, data):
        self._data = data

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"{self.__class__} ({self.__dict__})"

    def __getitem__(self, item):
        try:
            return self.__getattribute__(item)
        except AttributeError:
            return self._data.get(f"mdevice_{item}", self._data.get(item))

    @property
    def data(self):
        return self._data

    @property
    def connected(self):
        return bool(int(self._data.get("mdevice_connected") or "0"))

    @property
    def downspeed(self):
        return int(self._data.get("mdevice_downspeed") or "0")

    @property
    def fix_dhcp(self):
        return bool(int(self._data.get("mdevice_fix_dhcp") or "0"))

    @property
    def gua_ipv6(self):
        return self._data.get("mdevice_gua_ipv6")

    @property
    def hasui(self):
        return int(self._data.get("mdevice_hasui") or "0")

    @property
    def ipv4(self):
        return self._data.get("mdevice_ipv4")

    @property
    def mac(self):
        return self._data.get("mdevice_mac")

    @property
    def name(self):
        return self._data.get("mdevice_name")

    @property
    def reservedip(self):
        return self._data.get("mdevice_reservedip")

    @property
    def rssi(self):
        return int(self._data.get("mdevice_rssi") or "0")

    @property
    def slave(self):
        return bool(int(self._data.get("mdevice_slave") or "0"))

    @property
    def type(self):
        return ["lan", "wlan", "wlan5"][int(self._data.get("mdevice_type", "0")) % 3]

    @property
    def ula_ipv6(self):
        return self._data.get("mdevice_ula_ipv6")

    @property
    def upspeed(self):
        return int(self._data.get("mdevice_upspeed") or "0")

    @property
    def use_dhcp(self):
        return bool(int(self._data.get("mdevice_use_dhcp") or "0"))

    @property
    def wifi(self):
        return int(self._data.get("mdevice_wifi") or "0")

    @property
    def id(self):
        return int(self._data.get("id") or "0")
