#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import os


def _get_legend():
    fields = [
        "count_dir",
        "count_back",
        "overall_dir",
        "overall_back",
        "max_itime_dir",
        "max_itime_back",
        "min_itime_dir",
        "min_itime_back",
        "avg_itime_dir",
        "avg_itime_back",
        "std_itime_dir",
        "std_itime_back",
        "var_itime_dir",
        "var_itime_back",
        "max_payload_dir",
        "max_payload_back",
        "min_payload_dir",
        "min_payload_back",
        "avg_payload_dir",
        "avg_payload_back",
        "std_payload_dir",
        "std_payload_back",
        "var_payload_dir",
        "var_payload_back",
        "application"
    ]
    return ",".join(fields)


def main(savedir):
    files = {}

    for i in sys.stdin.readlines():
        sp = i.split(",")
        if len(sp) != 25:
            print "Error:", sp
            continue

        app = sp[-1].strip().lower()
        sfile = os.path.join(savedir, app + ".csv")

        if app not in files:
            files[app] = open(sfile, "a")
            # files[app].write(_get_legend() + "\n")

        files[app].write(i)

    for f in files.values():
        f.close()

main("save/")
