#!/usr/bin/env python
import argparse
import time

from main import Speedport


def get_arguments():
    """Get parsed arguments."""
    parser = argparse.ArgumentParser("Speedport Smart 4: Command Line Utility")
    parser.add_argument("-H", "--host-ip", help="Router ip", default="speedport.ip")
    parser.add_argument("-p", "--password", help="Password", required=True)
    parser.add_argument("-w", "--wifi", choices=["on", "off"], help="Turn on/off wifi")
    parser.add_argument("-g", "--guest-wifi", choices=["on", "off"], help="Turn on/off guest wifi")
    parser.add_argument("-r", "--reconnect", help="Reconnect internet and receive new ip", action="store_true")
    parser.add_argument("--wps", help="Turn on wps for 2 minutes", action="store_true")
    return parser.parse_args()


def main():
    args = get_arguments()
    speedport = Speedport(args.host_ip)
    speedport.login(password=args.password)
    if args.wifi and args.wifi == "on":
        speedport.wifi_on()
    elif args.wifi and args.wifi == "off":
        speedport.wifi_off()
    if args.guest_wifi and args.wifi == "on":
        speedport.wifi_on()
    elif args.guest_wifi and args.wifi == "off":
        speedport.wifi_off()
    if args.wps:
        speedport.wps_on()
    if args.reconnect:
        print(f"ipv4 {(ip_data := speedport.ip_data)['public_ip_v4']}\nipv6 {ip_data['public_ip_v6']}")
        speedport.reconnect()
        print("Connecting...", end="")
        while not (ip_data := speedport.ip_data)["onlinestatus"] == "online":
            print(".", end="")
            time.sleep(0.5)
        print(f"\nipv4 {ip_data['public_ip_v4']}\nipv6 {ip_data['public_ip_v6']}")


if __name__ == '__main__':
    main()
