#!/usr/bin/env python

import argparse
import asyncio
import logging
import sys
import time
from getpass import getpass
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

from speedport.speedport import Speedport

_LOGGER = logging.getLogger("speedport")


def set_logger(args):
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    if args["debug"]:
        _LOGGER.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(levelname)s - %(message)s")
    elif args["quiet"]:
        _LOGGER.setLevel(logging.WARNING)
        formatter = logging.Formatter("%(message)s")
    else:
        _LOGGER.setLevel(logging.INFO)
        formatter = logging.Formatter("%(message)s")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    _LOGGER.addHandler(console_handler)


def data_table(data, keys):
    columns = {}
    for key in keys:
        columns[key] = max([len(str(d[key])) for d in data] + [len(key)])
    line = (
        "+-"
        + "-+-".join([f"{'-' * length}" for key, length in columns.items()])
        + "-+\n"
    )
    text = (
        f"{line}| "
        + " | ".join([f"{key:<{length}}" for key, length in columns.items()])
        + f" |\n{line}"
    )
    for d in data:
        text += (
            "| "
            + " | ".join(
                [f"{str(d[key]):<{length}}" for key, length in columns.items()]
            )
            + " |\n"
        )
    return text + line


def batch_output(devices):
    for device in devices.values():
        print(
            int(device.connected),
            device.ipv4,
            device.type,
            device.name,
            sep="\t",
        )


def get_arguments():
    """Get parsed arguments."""
    parser = argparse.ArgumentParser(description="Speedport: Command Line Utility")
    parser.add_argument(
        "-H",
        "--host",
        help="ip address or hostname of Speedport webinterface",
        default="speedport.ip",
    )
    parser.add_argument(
        "-s", "--https", help="use https connection", action="store_true"
    )
    parser.add_argument("-p", "--password", help="password of Speedport webinterface")
    parser.add_argument(
        "-d", "--debug", help="enable debug logging", action="store_true"
    )
    parser.add_argument("-q", "--quiet", help="output only errors", action="store_true")
    parser.add_argument(
        "-b", "--batch", help="print output for batch processing", action="store_true"
    )
    parser.add_argument(
        "-t", "--table", help="print output as table (default)", action="store_true"
    )
    subparser = parser.add_subparsers(
        title="commands", metavar="COMMAND", required=True
    )
    for network in ["", "guest-", "office-"]:
        wifi = subparser.add_parser(f"{network}wifi", help=f"Turn on/off {network}wifi")
        wifi.add_argument(
            f"{network}wifi", choices=["on", "off"], help=f"Turn on/off {network}wifi"
        )
    reconnect = subparser.add_parser(
        "reconnect", help="Reconnect internet and receive new ip"
    )
    reconnect.add_argument(
        "reconnect", help="Reconnect internet and receive new ip", action="store_true"
    )
    reboot = subparser.add_parser("reboot", help="Reboot device")
    reboot.add_argument("reboot", help="Reboot device", action="store_true")
    wps = subparser.add_parser("wps", help="Turn on wps for 2 minutes")
    wps.add_argument("wps", help="Turn on wps for 2 minutes", action="store_true")
    devices = subparser.add_parser("devices", help="Output devices")
    devices.add_argument("devices", help="List connected devices", action="store_true")
    calls = subparser.add_parser("calls", help="Output calls")
    calls.add_argument("calls", help="List last calls", action="store_true")
    return vars(parser.parse_args())


async def check_args(speedport, args):
    if args.get("wps"):
        await wps_enable(args, speedport)
    if args.get("reconnect"):
        await reconnect(args, speedport)
    if args.get("reboot"):
        await speedport.reboot()
    if args.get("devices"):
        if args.get("batch"):
            batch_output(await speedport.devices)
        else:
            print(
                data_table(
                    (await speedport.devices).values(),
                    ["ipv4", "name", "type", "connected"],
                )
            )
    if args.get("calls"):
        if args.get("batch"):
            batch_output(await speedport.devices)
        else:
            print(
                data_table(
                    await speedport.calls,
                    ["number", "type", "duration", "date"],
                )
            )


async def check_wifi_args(speedport, args):
    if args.get("wifi") and args["wifi"] == "on":
        await speedport.wifi_on()
    elif args.get("wifi") and args["wifi"] == "off":
        await speedport.wifi_off()
    if args.get("guest-wifi") and args["guest-wifi"] == "on":
        await speedport.wifi_guest_on()
    elif args.get("guest-wifi") and args["guest-wifi"] == "off":
        await speedport.wifi_guest_off()
    if args.get("office-wifi") and args["office-wifi"] == "on":
        await speedport.wifi_office_on()
    elif args.get("office-wifi") and args["office-wifi"] == "off":
        await speedport.wifi_office_off()


async def main():
    args = get_arguments()
    set_logger(args)
    password = ""
    if not args.get("devices"):
        if not (password := args["password"]):
            password = getpass("Password of Speedports webinterface: ")
    async with Speedport(args["host"], password, args.get("https")) as speedport:
        await check_wifi_args(speedport, args)
        await check_args(speedport, args)


async def reconnect(args, speedport):
    if not args.get("quiet"):
        await speedport.update_ip_data()
        _LOGGER.info(f"{speedport.public_ip_v4} / {speedport.public_ip_v6}")
    await speedport.reconnect()
    if not args.get("quiet"):
        for i in range(240):
            await speedport.update_ip_data()
            if await speedport.online_status == "online":
                _LOGGER.info(f"{speedport.public_ip_v4} / {speedport.public_ip_v6}")
                break
            await asyncio.sleep(0.5)
            print(f"Connecting.{'.' * (i % 3)}  ", end="\r", flush=True)


async def wps_enable(args, speedport):
    await speedport.wps_on()
    if not args.get("quiet"):
        event = time.time()
        next_time = event
        while await speedport.wps_state == 1:
            await asyncio.sleep(next_time - time.time())
            next_time = time.time() + 1
            print(
                f"wps connect enabled for {120 - int(time.time() - event)}s...",
                end="\r",
                flush=True,
            )


def start():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Aborted.")


if __name__ == "__main__":
    start()
