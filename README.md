**This python package is unofficial and is not related in any way to Telekom. It was developed by reversed engineered http requests and can stop working at anytime!**
  
## Speedport-API
[![PyPI - Status](https://img.shields.io/pypi/status/speedport-api)](https://pypi.org/project/speedport-api)
[![PyPI](https://img.shields.io/pypi/v/speedport-api?color=blue)](https://pypi.org/project/speedport-api)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/speedport-api)](https://www.python.org/)
[![PyPI - License](https://img.shields.io/pypi/l/speedport-api)](https://github.com/Andre0512/speedport-api/blob/main/LICENSE)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/speedport-api)](https://pypistats.org/packages/speedport-api)  
Control Telekom Speedport routers with Python!

### Installation
```commandline
pip install speedport-api
```

### Supported Devices
* Speedport Smart 4

### Commandline tool
With this shipped commandline tool can a speedport in your network be controlled.

#### Turn wifi off
```commandline
$ speedport wifi off
Turn off wifi...
```

#### Turn guest wifi on
```commandline
$ speedport guest-wifi on
Turn on guest wifi...
```

#### Reconnect for new ip address
```commandline
$ speedport reconnect
123.45.67.89 / 5403:f3:35aa:12f:7287:41cf:fb1c:3c83
Reconnect with internet provider...
123.45.67.12 / 5403:f3:35fe:12f:7287:41cf:fb1c:3c83
```

#### Enable wps connect
```commandline
$ speedport wps
Enable wps connect...
wps connect enabled for 113s...
```

#### Reboot device
```commandline
$ speedport reboot
Reboot speedport...
```

#### Print devices
```commandline
$ speedport devices
+-------------+---------------------+-------+-----------+
| ipv4        | name                | type  | connected |
+-------------+---------------------+-------+-----------+
| 10.5.12.32  | Google-Home-Mini-1  | wlan  | 1         |
| 10.5.12.157 | PC10-5-12-157       | lan   | 0         |
| 10.5.12.227 | andre-xps           | wlan5 | 1         |
```


#### Print calls
```commandline
$ speedport calls
+-------------+--------+----------+---------------------+
| number      | type   | duration | date                |
+-------------+--------+----------+---------------------+
| 01578212345 | missed | 0        | 2024-04-04 09:34:35 |
| 026361245   | taken  | 1337     | 2024-04-06 05:12:53 |
| 7866        | dialed | 20       | 2024-04-06 18:39:00 |
```

### Library

#### Reconnect example
```python
import asyncio
from speedport import Speedport

async def reconnect():
    speedport =  Speedport("192.168.1.1")
    await speedport.login("password123")
    await speedport.reconnect()

asyncio.run(reconnect())
```

#### Devices example
```python
import asyncio
from speedport import Speedport

devices = asyncio.run(Speedport().devices)
for device in devices:
    print(device.ipv4, device.connected)
```
