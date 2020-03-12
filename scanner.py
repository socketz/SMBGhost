#!/bin/python3
#-*- coding: utf-8 -*-

import socket
import struct
import sys
import ipaddress
import argparse
from argparse import RawTextHelpFormatter
from netaddr import IPNetwork

# This payload get all dialect versions of SMB
pkt = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00'
pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00'
pkt += b'\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02'
pkt += b'\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00'
pkt += b'\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
pkt += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00'
pkt += b'\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

def check_valid_ip(ip):
    try:
        socket.getaddrinfo(ip, 445, 0, 0, socket.IPPROTO_TCP)
    except BaseException:
        return False
    return True

def check_version(subnet_list):
    for subnet in subnet_list:
        for ip in IPNetwork(subnet):
            if check_valid_ip(str(ip)):
                pass
            else:
                # print("Host Invalid: {}".format(str(ip)))
                continue

            sock = socket.socket(socket.AF_INET)
            sock.settimeout(3)

            try:
                sock.connect((str(ip),  445))
            except:
                print(f"Connection error. Closing connection with: {ip}")
                sock.close()
                continue

            try:
                sock.send(pkt)
                nb, = struct.unpack(">I", sock.recv(4))
                res = sock.recv(nb)

                if res[68:70] != b"\x11\x03" or res[70:72] != b"\x02\x00":
                    print(f"{ip} is NOT ulnerable.")
                else:
                    print(f"{ip} is Vulnerable")
            except socket.timeout:
                print(f"{ip} response timeout.")
            except ConnectionResetError:
                print(f"{ip} is NOT ulnerable.")

if __name__ == "__main__":
    # Parsing Command Line Arguments
    parser = argparse.ArgumentParser(
        description='Tool to check SMBv3 compression and version for CVE-2020-0796 exploitability.\nVersion 0.2',
        formatter_class=RawTextHelpFormatter)
    parser.add_argument(
        'subnet',
        type=str,
        help='Host or hosts to scan',
        nargs='+')

    args = parser.parse_args()
    subnet = args.subnet
    check_version(subnet)

