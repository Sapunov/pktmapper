"""
Common functions
---

Package: PACKET-MAPPER
Author: Sapunov Nikita <kiton1994@gmail.com>
"""

import netaddr
import socket


def ip2str(address):
    """
    Print out an IP address given a string

    Args:
        address (inet struct): inet network address
    Returns:
        str: Printable/readable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)


def ip2long(ip):
    """
    Convert an IP string to long.

    Args:
        ip: readable IP address
    Returns:
        long: IP address in long format
    """
    return long(netaddr.IPAddress(ip))
