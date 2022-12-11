**This python package is unofficial and is not related in any way to Telekom. It was developed by reversed engineered http requests and can stop working at anytime!**
  
## Speedport-API
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

### Library

#### Reconnect example
```python
import asyncio
from speedport import Speedport

async def reconnect():
    speedport =  Speedport("192.168.178.1")
    await speedport.login("password123")
    await speedport.reconnect()

asyncio.run(reconnect())
```
