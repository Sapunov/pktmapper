"""
Functions for preprocessing
---

Package: PACKET-MAPPER
Author: Sapunov Nikita <kiton1994@gmail.com>
"""


from common import ip2long
from common import ip2str
from dpkt.tcp import TCP
from dpkt.udp import UDP
from hashlib import md5

import dpkt
import json
import os
import subprocess
import tempfile


def flow_hash(ip_a, ip_b, port_a, port_b, proto):
    """
    Creates specific hash that determines uniq flow.
    Ip addresses always sort ASC.

    Args:
        ip_a: source ip address
        ip_b: destination ip address
        port_a: source port
        port_b: destination port
        proto: protocol of the transport layer
    Returns:
        str: hash value
    """
    a = ip2long(ip_a)
    b = ip2long(ip_b)
    hsh = ""

    # Minimal ip address first
    if a > b:
        hsh = ip_b
    else:
        hsh = ip_a

    hsh += str(port_a + port_b)
    hsh += proto.lower()

    return md5(hsh).hexdigest()


def _process_ndpijson(json_raw):
    """
    Precess json file from nDPI to self.DPI dictionary
    with md5 key and name of the application as a value.
    """
    jon = json.loads(json_raw)
    dpi = {"general": {}, "flows": {}}
    protos = ("TCP", "UDP")

    for key, value in jon.items():
        if key == "detected.protos":
            pkts = 0
            byts = 0
            flws = 0
            for i in value:
                if i["name"] == "Unknown":
                    dpi["general"].update(
                        {"unknown": (
                            i["packets"], i["bytes"], i["flows"]
                        )}
                    )
                else:
                    pkts += i["packets"]
                    byts += i["bytes"]
                    flws += i["flows"]
            dpi["general"].update({"known": (pkts, byts, flws)})

        elif key == "known.flows":
            for i in value:
                if i["protocol"] in protos:
                    fid = flow_hash(
                        i["host_a.name"],
                        i["host_b.name"],
                        i["host_a.port"],
                        i["host_b.port"],
                        i["protocol"]
                    )

                    name = i["detected.protocol.name"].split(".")[0]
                    dpi["flows"].update(
                        {fid: name}
                    )
    return dpi


def ndpi_processing(filename):
    """
    Filling self.DPI dict with data from nDPI.
    """
    tmp_file = tempfile.mktemp()

    cmd = ["ndpiReader", "-i", filename, "-v", "1", "-j", tmp_file]

    dnull = open(os.devnull, 'w')
    proc = subprocess.Popen(cmd, stdout=dnull)
    dnull.close()
    proc.wait()

    with open(tmp_file) as jon:
        dpi = _process_ndpijson(jon.read())

    os.remove(tmp_file)

    return dpi


def _flow_recalc(fid, payload, timestamp, ip_a, flows):
    """
    Recalculate metrics for each flow.
    """
    f = flows[fid]
    direct = bool(ip_a == f[33])
    #
    # general metrics
    #
    app = f[0]
    if direct:
        count_dir = f[1] + 1
        count_back = f[2]

        overall_dir = f[3] + payload
        overall_back = f[4]
    else:
        count_dir = f[1]
        count_back = f[2] + 1

        overall_dir = f[3]
        overall_back = f[4] + payload
    #
    # inter arrival time
    #
    if direct:
        if count_dir >= 2:
            _itime = timestamp - f[29]
        else:
            _itime = 0

        # intermediate values
        _overall_itime_dir = f[31] + _itime
        _overall_itime_back = f[32]

        max_itime_back = f[6]
        if count_dir == 2:
            max_itime_dir = _itime
            min_itime_dir = _itime
        else:
            max_itime_dir = max([_itime, f[5]])
            min_itime_dir = min([_itime, f[7]])
        min_itime_back = f[8]

        avg_itime_dir = _overall_itime_dir / count_dir
        avg_itime_back = f[10]

        # intermediate value
        _std_itime_dir = (_itime - avg_itime_dir) ** 2
        _std_itime_back = f[26]

        std_itime_dir = (_std_itime_dir / count_dir) ** 0.5
        std_itime_back = f[12]

        var_itime_dir = max_itime_dir - min_itime_dir
        var_itime_back = f[14]
    else:
        if count_back >= 2:
            _itime = timestamp - f[30]
        else:
            _itime = 0

        # intermediate values
        _overall_itime_back = f[32] + _itime
        _overall_itime_dir = f[31]

        max_itime_dir = f[5]
        min_itime_dir = f[7]
        max_itime_back = max([_itime, f[6]])
        if count_back == 2:
            min_itime_back = _itime
        else:
            min_itime_back = min([_itime, f[7]])

        avg_itime_dir = f[9]
        avg_itime_back = _overall_itime_back / count_back

        # intermediate value
        _std_itime_dir = f[25]
        _std_itime_back = (_itime - avg_itime_back) ** 2

        std_itime_dir = f[11]
        std_itime_back = (_std_itime_back / count_back) ** 0.5

        var_itime_dir = f[13]
        var_itime_back = max_itime_back - min_itime_back
    #
    # payload
    #
    if direct:
        max_payload_dir = max([payload, f[15]])
        max_payload_back = f[16]

        min_payload_dir = min([payload, f[17]])
        min_payload_back = f[18]

        avg_payload_dir = overall_dir / count_dir
        avg_payload_back = f[20]

        # intermediate value
        _std_payload_dir = (payload - avg_payload_dir) ** 2
        _std_payload_back = f[28]

        std_payload_dir = (_std_payload_dir / count_dir) ** 0.5
        std_payload_back = f[22]

        var_payload_dir = max_payload_dir - min_payload_dir
        var_payload_back = f[24]
    else:
        max_payload_dir = f[15]
        max_payload_back = max([payload, f[16]])

        min_payload_dir = f[17]
        if count_back == 1:
            min_payload_back = payload
        else:
            min_payload_back = min([payload, f[18]])

        avg_payload_dir = f[19]
        avg_payload_back = overall_back / count_back

        # intermediate value
        _std_payload_dir = f[27]
        _std_payload_back = (payload - avg_payload_back) ** 2

        std_payload_dir = f[21]
        std_payload_back = (_std_payload_back / count_back) ** 0.5

        var_payload_dir = f[23]
        var_payload_back = max_payload_back - min_payload_back
    #
    # intermediate values for calculations
    #
    if direct:
        _current_timestamp_dir = timestamp
        _current_timestamp_back = f[30]
    else:
        _current_timestamp_dir = f[29]
        _current_timestamp_back = timestamp
    _last_used_ip = ip_a

    flows[fid] = (
        app,
        count_dir,
        count_back,
        overall_dir,
        overall_back,
        max_itime_dir,
        max_itime_back,
        min_itime_dir,
        min_itime_back,
        avg_itime_dir,
        avg_itime_back,
        std_itime_dir,
        std_itime_back,
        var_itime_dir,
        var_itime_back,
        max_payload_dir,
        max_payload_back,
        min_payload_dir,
        min_payload_back,
        avg_payload_dir,
        avg_payload_back,
        std_payload_dir,
        std_payload_back,
        var_payload_dir,
        var_payload_back,
        _std_itime_dir,
        _std_itime_back,
        _std_payload_dir,
        _std_payload_back,
        _current_timestamp_dir,
        _current_timestamp_back,
        _overall_itime_dir,
        _overall_itime_back,
        _last_used_ip
    )


def soft_recalc(fid, payload, ip_a, flows):
    """
    Update only counters. Without math.
    """
    ip = flows[fid][-1]
    count_dir = flows[fid][1]
    count_back = flows[fid][2]
    overall_dir = flows[fid][3]
    overall_back = flows[fid][4]

    if ip == ip_a:
        count_dir += 1
        overall_dir += payload
    else:
        count_back += 1
        overall_back += payload

    flows[fid] = (
        flows[fid][0],
        count_dir,
        count_back,
        overall_dir,
        overall_back
    ) + flows[fid][5:-1] + (ip_a,)


def flow_processing(fid, payload, timestamp, ip_a, flows, app):
    """
    Flow processing.
    """
    if fid not in flows:
        flows[fid] = (
            #
            # general metrics
            #
            app,        # [0]  application
            1,          # [1]  count_dir
            0,          # [2]  count_back
            payload,    # [3]  overall_dir
            0,          # [4]  overall_back
            #
            # inter arrival time
            #
            0,          # [5]  max_itime_dir
            0,          # [6]  max_itime_back
            0,          # [7]  min_itime_dir
            0,          # [8]  min_itime_back
            0,          # [9]  avg_itime_dir
            0,          # [10] avg_itime_back
            0,          # [11] std_itime_dir
            0,          # [12] std_itime_back
            0,          # [13] var_itime_dir
            0,          # [14] var_itime_back
            #
            # payload
            #
            payload,    # [15] max_payload_dir
            0,          # [16] max_payload_back
            payload,    # [17] min_payload_dir
            0,          # [18] min_payload_back
            payload,    # [19] avg_payload_dir
            0,          # [20] avg_payload_back
            0,          # [21] std_payload_dir
            0,          # [22] std_payload_back
            0,          # [23] var_payload_dir
            0,          # [24] var_payload_back
            #
            # intermediate values for calculations
            #
            0,          # [25] _std_itime_dir
            0,          # [26] _std_itime_back
            0,          # [27] _std_payload_dir
            0,          # [28] _std_payload_back
            timestamp,  # [29] _current_timestamp_dir
            0,          # [30] _current_timestamp_back
            0,          # [31] _overall_itime_dir
            0,          # [32] _overall_itime_back
            ip_a        # [33] _last_used_ip. For determining dir or back
        )
    else:
        _flow_recalc(fid, payload, timestamp, ip_a, flows)


def packet_data(data):
    """
    Common packet processing.

    Args:
        data - packet content
    Returns:
        (transport, ip_a, ip_b, port_a, port_b, payload)
    """
    if not data:
        return None

    eth = dpkt.ethernet.Ethernet(data)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return None

    ip_packet = eth.data
    trans_packet = ip_packet.data

    if type(ip_packet.data) == UDP:
        transport = "udp"
    elif type(ip_packet.data) == TCP:
        transport = "tcp"
    else:
        return None

    return (
        transport,
        ip2str(ip_packet.dst),
        ip2str(ip_packet.src),
        trans_packet.dport,
        trans_packet.sport,
        len(trans_packet.data)
    )
