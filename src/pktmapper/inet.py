"""
Functions for working with interfaces
---

Package: PACKET-MAPPER
Author: Sapunov Nikita <kiton1994@gmail.com>
"""


from common import ip2str
import array
import fcntl
import socket
import struct


def interface_list():
    """
    Get an suitable interface list of the current device with ip addresses.

    Returns:
        list: list of tuples - [(interface_name, ip_addr), ...]
    """
    by = 128 * 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    names = array.array('B', '\0' * by)

    outbytes = struct.unpack('iL', fcntl.ioctl(
        s.fileno(),
        0x8912,
        struct.pack('iL', by, names.buffer_info()[0])
    ))[0]

    namestr = names.tostring()
    lst = []
    for i in range(0, outbytes, 40):
        name = namestr[i:i + 16].split('\0', 1)[0]
        ip = namestr[i + 20:i + 24]
        lst.append((name, ip2str(ip)))

    return lst


def current_metrics(ifaces):
    """
    Get info from /proc/net/dev. This function returns only current value of
        packets transmitted from the interface up.

    Args:
        ifaces: list of interested interfaces
    Returns:
        list: list with interface names and corresponding amount of packets.
    """
    proc_net_dev = open("/proc/net/dev")
    data = proc_net_dev.readlines()[2:]
    proc_net_dev.close()
    out = []

    for i in data:
        metrics = i.split()
        iface = metrics[0][:-1]
        if iface in ifaces:
            out.append((iface, int(metrics[1]) + int(metrics[9])))

    return out
