#!/usr/bin/env python

"""
Script for making learning sets.
"""

import argparse
import os


class ProtocolsFileNotFound(Exception):
    def __init__(self, filename):
        Exception.__init__(self, filename)


class NoMuchData(Exception):
    def __init(self, filename):
        Exception.__init__(self, filename)


def _get_legend():
    arr = [
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

    return ",".join(arr) + "\n"


def create(number, protocols, output, datadir):
    if len(protocols) == 1:
        protocols = protocols[0].split(",")
    protocols = sorted(list(set(i for i in protocols if i != "")))

    if datadir is None:
        datadir = "save/"

    output_file = open(output, "w")

    output_file.write(_get_legend())

    for proto in protocols:
        fullpath = os.path.join(datadir, proto + ".csv")
        if not os.path.exists(fullpath):
            raise ProtocolsFileNotFound(fullpath)

        with open(fullpath) as fid:
            for i, line in enumerate(fid.readlines()):
                output_file.write(line)

                if i + 1 >= number:
                    break

        if i + 1 < number:
            raise NoMuchData(fullpath)

    output_file.close()


parser = argparse.ArgumentParser(description="Make your own learing dataset.")
parser.add_argument(
    "-n",
    type=int,
    required=True,
    help="How many items from each protocol to use."
)
parser.add_argument(
    "-p", "--protocols",
    nargs="*",
    required=True,
    type=str,
    help="Specify protocols to include in learn dataset."
)
parser.add_argument(
    "-o", "--output",
    required=True,
    type=str,
    help="Output file with training dataset."
)
parser.add_argument(
    "-d", "--datadir",
    type=str,
    help="Directory with data files. It's [save/] by default."
)


def main():
    args = parser.parse_args()
    create(args.n, args.protocols, args.output, args.datadir)


if __name__ == "__main__":
    main()
