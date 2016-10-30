#!/usr/bin/env python

from pktmapper import preprocessing
from pktmapper.inet import interface_list
from threading import Thread
from time import sleep
import cPickle as pickle

import argparse
import logging
import os
import pcap
import sys


log_format = u"%(asctime)s %(message)s"
logging.basicConfig(level=logging.INFO, datefmt="%d.%m.%y_%H:%M:%S",
                    format=log_format)


class ModelNotSpecified(Exception):
    def __init__(self):
        Exception.__init__(self, "Model is not specified.")


def _interface_list():
    print "+", "-" * 30, "+"
    for iface, ip in interface_list():
        print "|", iface.ljust(12), ip.ljust(17), "|"
    print "+", "-" * 30, "+"


class Mapper:
    def __init__(self, threshold, model, features, results):
        self.__stop = False
        if features is not None:
            if len(features) == 1 and "," in features[0]:
                features = features[0].split(",")
            self.features = sorted(set(int(i) for i in features if i != ""))
        else:
            self.features = []
        # Last good features set:
        # [17, 23, 7, 5, 15, 3, 1, 4, 2, 21, 9, 24]
        self.results = results
        self.flows = {}
        self.meta = {}
        self.pcounter = 0
        self.temp_flows = {}
        if threshold is not None:
            self.threshold = threshold
        else:
            self.threshold = 8
        if model is not None:
            self.model = model
        else:
            raise ModelNotSpecified()

    def _recalc_flow(self, fid, ip_a, payload):
        app, cd, cb, pd, pb, ip = self.flows[fid]
        if ip == ip_a:
            # dir
            self.flows[fid] = (app, cd + 1, cb, pd + payload, pb, ip_a)
        else:
            # back
            self.flows[fid] = (app, cd, cb + 1, pd, pb + payload, ip_a)

    def _load_classifier(self):
        logging.info("Loading model [{0}] ...".format(self.model))
        
        with open(self.model, "rb") as fid:
            model = pickle.load(fid)

        logging.info("Model [{0}] loaded. Availible classes: {1}".format(
            self.model, list(model.classes_)))

        return model

    def _fit_features(self, fid):
        new_flow = ()
        if len(self.features) > 0:
            for feat in self.features:
                new_flow += (self.temp_flows[fid][feat],)
        else:
            new_flow = self.temp_flows[fid][1:25]

        return new_flow

    def _collector(self):
        logging.info(
            "Collector started. Threshold: {0}. Features: {1}".format(
                self.threshold, self.features
            )
        )

        try:
            model = self._load_classifier()
        except Exception:
            logging.error("Bad model")
            self.__stop = True
        logging.info("Waiting for the first match")

        while not self.__stop:
            for i, metrics in self.temp_flows.items():
                if (metrics[1] + metrics[2]) >= self.threshold:
                    flow_tuple = self._fit_features(i)

                    app = list(model.predict(flow_tuple))[0]

                    self.flows[i] = (app,) + metrics[1:5] + (metrics[-1],)
                    del self.temp_flows[i]
                    print("\rFlow classified: {0} {1}".format(
                        self.flows[i][:-1],
                        (self.meta[i],)
                    ))

            sys.stdout.write(
                "\rReceived packets: {0}. Classified flows: {1}. Detected flows: {2}".format(
                    self.pcounter,
                    len(self.flows),
                    len(self.flows) + len(self.temp_flows)
                )
            )
            sys.stdout.flush()
            sleep(0.5)

    def _process_packet(self, payload, data, timestamp):
        if self.__stop:
            raise Exception

        pkt = preprocessing.packet_data(data)
        if pkt is not None:
            transport, ip_a, ip_b, port_a, port_b = pkt[:-1]
        else:
            return

        self.pcounter += 1

        fid = preprocessing.flow_hash(
            ip_a, ip_b, port_a, port_b, transport
        )

        if fid not in self.flows:
            preprocessing.flow_processing(
                fid, payload, timestamp, ip_a, self.temp_flows, None
            )
            self.meta[fid] = "{0}:{1}<->{2}:{3}_{4}".format(
                ip_a, port_a, ip_b, port_b, transport
            )
        else:
            # This recalc. Only +1 to the counters
            self._recalc_flow(fid, ip_a, payload)

    def _export_json(self, filename):
        header = "type,proto,count_dir,count_back,overall_dir,overall_back,meta\n"
        with open(filename, "w"):
            pass
        with open(filename, "a") as fid:
            fid.write(header)

            for i, data in self.flows.items():
                t = "classified,{0},{1}\n".format(
                    ",".join(map(str, data[:5])), self.meta[i])
                fid.write(t)

            for i, data in self.temp_flows.items():
                t = "unclassified,{0},{1}\n".format(
                    ",".join(map(str, data[:5])), self.meta[i])
                fid.write(t)

    def start(self, interface):
        p = pcap.pcapObject()

        p.open_live(interface, 500, True, 0)

        collector_thread = Thread(target=self._collector)
        collector_thread.start()

        try:
            p.loop(0, self._process_packet)
        except KeyboardInterrupt:
            logging.info("\r\nReceived interrupt. Closing...")
            self.__stop = True
            collector_thread.join()

            if self.results is not None:
                self._export_json(self.results)
                logging.info("\rResults saved in [{0}]".format(self.results))


parser = argparse.ArgumentParser(description="Protocol mapper.")
parser.add_argument(
    "-l", "--list",
    action="store_true",
    help="List of active interfaces."
)
parser.add_argument(
    "-i", "--interface",
    type=str,
    help="Interface to collect traffic."
)
parser.add_argument(
    "-m", "--model",
    type=str,
    help="Trained classification model."
)
parser.add_argument(
    "-t", "--threshold",
    type=int,
    help="How many packets of the flow will be calculated."
)
parser.add_argument(
    "-f", "--features",
    nargs="*",
    help="Specify indexes of features."
)
parser.add_argument(
    "-r", "--results",
    type=str,
    help="Results file. If None results not beeing save."
)


def main():
    args = parser.parse_args()
    if args.list:
        _interface_list()
    elif args.interface is not None:
        mapper = Mapper(args.threshold, args.model, args.features, args.results)
        mapper.start(args.interface)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
