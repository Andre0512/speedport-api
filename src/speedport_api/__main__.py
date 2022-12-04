#!/usr/bin/env python
import argparse
import logging
import sys
import time
from getpass import getpass

from .speedport import Speedport

_LOGGER = logging.getLogger("")


def set_logger(args):
    logging.getLogger("requests").setLevel(logging.WARNING)
    if args["debug"]:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(levelname)s - %(message)s")
    elif args["quiet"]:
        logging.basicConfig(stream=sys.stdout, level=logging.WARNING, format="%(message)s")
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")


def get_arguments():
    """Get parsed arguments."""
    parser = argparse.ArgumentParser(description="Speedport: Command Line Utility")
    parser.add_argument("-H", "--host", help="ip address or hostname of Speedport webinterface", default="speedport.ip")
    parser.add_argument("-p", "--password", help="password of Speedport webinterface")
    parser.add_argument("-d", "--debug", help="enable debug logging", action="store_true")
    parser.add_argument("-q", "--quiet", help="output only errors", action="store_true")
    subparser = parser.add_subparsers(title="commands", metavar="COMMAND")
    wifi = subparser.add_parser("wifi", help="Turn on/off wifi")
    wifi.add_argument("wifi", choices=["on", "off"], help="Turn on/off wifi")
    guest = subparser.add_parser("guest-wifi", help="Turn on/off guest wifi")
    guest.add_argument("guest-wifi", choices=["on", "off"], help="Turn on/off guest wifi")
    reconnect = subparser.add_parser("reconnect", help="Reconnect internet and receive new ip")
    reconnect.add_argument("reconnect", help="Reconnect internet and receive new ip", action="store_true")
    wps = subparser.add_parser("wps", help="Turn on wps for 2 minutes")
    wps.add_argument("wps", help="Turn on wps for 2 minutes", action="store_true")
    return vars(parser.parse_args())


def main():
    args = get_arguments()
    set_logger(args)
    speedport = Speedport(args["host"])
    if not (password := args["password"]):
        password = getpass("Password of Speedports webinterface: ")
    speedport.login(password=password)
    if args.get("wifi") and args["wifi"] == "on":
        speedport.wifi_on()
    elif args.get("wifi") and args["wifi"] == "off":
        speedport.wifi_off()
    if args.get("guest_wifi") and args["guest_wifi"] == "on":
        speedport.wifi_on()
    elif args.get("guest_wifi") and args["guest_wifi"] == "off":
        speedport.wifi_off()
    if args.get("wps"):
        speedport.wps_on()
    if args.get("reconnect"):
        _LOGGER.info(f"ipv4 {(ip_data := speedport.ip_data)['public_ip_v4']}\nipv6 {ip_data['public_ip_v6']}")
        speedport.reconnect()
        while not (ip_data := speedport.ip_data)["onlinestatus"] == "online":
            time.sleep(0.5)
        _LOGGER.info(f"ipv4 {ip_data['public_ip_v4']}\nipv6 {ip_data['public_ip_v6']}")


if __name__ == '__main__':
    main()
