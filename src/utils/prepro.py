#!/usr/bin/env python

from datetime import datetime
from multiprocessing import Process, Value, Lock
from pktmapper import preprocessing

import argparse
import dpkt
import os
import sys
import time


class Prepro:

    def __init__(self, threshold, processes):
        self.DPI = {}
        self.FLOWS = {}

        self.tasks = Value("d", 0.0)
        self.completed = Value("d", 0.0)
        self.ndpi = Value("i", 0)
        self.lock = Lock()

        if processes is not None:
            self.max_processes = processes
        else:
            self.max_processes = 15

        if threshold is not None:
            self.threshold = threshold
        else:
            self.threshold = 8

        print "[{0}] Program started. Threshold: {1}, Processes: {2}".format(
            self._print_time(), self.threshold, self.max_processes)

    def _packets_processing(self, pcap):
        """
        Packet processing.
        """
        for timestamp, data in pcap:
            pkt = preprocessing.packet_data(data)

            with self.lock:
                self.completed.value += 1

            if pkt is not None:
                transport, ip_a, ip_b, port_a, port_b, payload = pkt
            else:
                continue

            fid = preprocessing.flow_hash(
                ip_a, ip_b, port_a, port_b, transport
            )

            if fid in self.DPI["flows"]:
                app = self.DPI["flows"][fid]
            else:
                continue

            if fid in self.FLOWS and \
                    (self.FLOWS[fid][1] + self.FLOWS[fid][2]) >= \
                    self.threshold:
                        preprocessing.soft_recalc(
                            fid, payload, ip_a, self.FLOWS
                        )
            else:
                preprocessing.flow_processing(
                    fid,
                    payload,
                    timestamp,
                    ip_a,
                    self.FLOWS,
                    app
                )

    def _count(self, filename):
        with open(filename) as fiid:
            pcap = dpkt.pcap.Reader(fiid)
            c = 0
            for i in pcap:
                c += 1
        return c

    def _pcap(self, filename):
        """
        Read pcap file and create ground truth file.
        """
        with self.lock:
            self.ndpi.value += 1
            self.DPI = preprocessing.ndpi_processing(filename)
            self.ndpi.value -= 1
        with self.lock:
            self.tasks.value += self._count(filename)
        with open(filename) as fiid:
            pcap = dpkt.pcap.Reader(fiid)
            self._packets_processing(pcap)

    def _print_time(self):
        """
        Internal use.
        """
        return datetime.now()

    def _lock_file(self, filename):
        with open(filename + ".lock", "w"):
            pass

    def _unlock_file(self, filename):
        if os.path.exists(filename):
            os.remove(filename + ".lock")

    def _is_locked(self, filename):
        if os.path.exists(filename + ".lock"):
            return True
        else:
            return False

    def _status(self):
        try:
            if self.ndpi.value > 0:
                proc = 0.0
            else:
                proc = round(self.completed.value / self.tasks.value * 100, 2)
        except ZeroDivisionError:
            proc = 0

        sys.stdout.write(
            "\rCompleted: {0}%".format(
                proc
            )
        )
        sys.stdout.flush()

    def export(self, filename, output):
        """
        Save flows in an appropriate format
        """
        while self._is_locked(output):
            time.sleep(1)

        self._lock_file(output)
        f = open(output, "a")

        for metrics in self.FLOWS.values():
            tmp = metrics[1:25]
            app = metrics[0]

            def _round(val):
                if isinstance(val, float):
                    if val == 0.0:
                        return "0"
                    return str(round(val, 6))
                else:
                    return str(val)

            tmp = map(_round, tmp)
            f.write("{0},{1}\n".format(",".join(tmp), app))

        self._unlock_file(output)

    def pcap(self, filename, output):
        print "\r[{0}] Start processing [{1}]".format(
            self._print_time(), filename
        )
        self._pcap(filename)
        self.export(filename, output)
        print "\r[{0}] Finish processing [{1}]".format(
            self._print_time(), filename
        )

    def multi(self, datainput, output):
        if os.path.isdir(datainput):
            queue = [os.path.join(datainput, pa) for pa in os.listdir(datainput)]
        else:
            queue = [datainput]

        queue = [i for i in queue if os.path.isfile(i)]
        processes = []

        if len(queue) > 0:
            while len(queue) > 0:
                for fu in queue:
                    if len(processes) < self.max_processes:
                        processes.append(
                            Process(target=self.pcap, args=(fu, output,))
                        )
                        processes[-1].start()
                        queue.remove(fu)

                while len(processes) > 0:
                    self._status()
                    for i in processes:
                        if not i.is_alive():
                            i.join()
                            processes.remove(i)

                    time.sleep(0.1)
                    if len(queue) > 0:
                        break
        print


parser = argparse.ArgumentParser(description="PCAP preprocessing.")
parser.add_argument(
    "file",
    help="Dump file of directory with that."
)
parser.add_argument(
    "result",
    help="Output file."
)
parser.add_argument(
    "-t", "--threshold",
    type=int,
    help="How many packets of the flow will be calculated."
)
parser.add_argument(
    "-p", "--processes",
    type=int,
    help="How many processes can be used for processing."
)


def main():
    args = parser.parse_args()

    prepros = Prepro(args.threshold, args.processes)

    prepros.multi(args.file, args.result)

if __name__ == "__main__":
    main()
