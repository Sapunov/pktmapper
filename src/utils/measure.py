#!/usr/bin/env python

from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from pktmapper import metrics

import argparse
import logging
import os

log_format = u"%(asctime)s LINE:%(lineno)-3d %(levelname)-8s %(message)s"
logging.basicConfig(level=logging.DEBUG,
                    datefmt="%d.%m.%y %H:%M:%S",
                    format=log_format
                    )

CLFS = [
    AdaBoostClassifier(n_estimators=39),
    RandomForestClassifier(n_estimators=123),
    GaussianNB(),
    LinearSVC(),
    DecisionTreeClassifier(),
]


class NotDirecory(Exception):
    def __init__(self, dirname):
        Exception.__init__(self, dirname)


def output(name, trainingset_size, clf, measure_type, app, value, output_file):
    if isinstance(app, list):
        for i in range(len(app)):
            output(
                name, trainingset_size, clf, measure_type,
                app[i], value[i], output_file)
    else:
        if app == "avg" and not isinstance(value, (int, float)):
            value = value.mean()

        out_str = "{0},{1},{2},{3},{4},{5}\n".format(
            trainingset_size, clf, measure_type,
            app.lower(), name, round(value, 4))

        if output_file is not None:
            with open(output_file, "a") as fid:
                fid.write(out_str)


def rewrite_columns_names(df):
    cols = df.columns
    to_delete = []

    for colname in cols:
        if colname.startswith("_"):
            realname = colname[1:]
            df = df.rename_axis({colname: realname}, axis="columns")
            to_delete.append(realname)

    logging.info((df.columns, to_delete))

    return df, to_delete


def measure(sets_directory, output_file):
    if not os.path.isdir(sets_directory):
        raise NotDirecory(sets_directory)

    task = []
    for i in os.listdir(sets_directory):
        if i.find(".csv") < 0:
            continue

        name = i.split("_")
        if name[0].startswith("testset"):
            testing_x, testing_y = metrics.load_data(os.path.join(sets_directory, i))
            testing_x, to_delete = rewrite_columns_names(testing_x)

            in_bytes = testing_x["overall_dir"] + testing_x["overall_back"]

            # Delete excess columns
            for delname in to_delete:
                testing_x = testing_x.drop([delname], axis=1)

            logging.info("Testset loaded and ready to go.")
        else:
            task.append((name[0], name[1], os.path.join(sets_directory, i)))

    logging.info("Task has {0}".format(task))

    while len(task) > 0:
        cset = task.pop()

        learning_x, learning_y = metrics.load_data(cset[2])
        learning_x, to_delete = rewrite_columns_names(learning_x)

        # Delete excess columns
        for delname in to_delete:
            learning_x = learning_x.drop([delname], axis=1)

        logging.info("Set {0} loaded and ready to go.".format(cset[2]))
        for c in CLFS:
            model, m_name, fittime = metrics.fit(
                c, learning_x, learning_y
            )
            output("fittime", cset[1], m_name, "general", "avg", fittime, output_file)
            logging.info("Model with {0} fitted in {1} seconds.".format(
                m_name, fittime))

            labels = sorted(testing_y.unique())
            predicted = model.predict(testing_x)
            logging.info("Prediction completed")

            """
            by_flows
            """
            met = metrics.measure(
                testing_y, predicted, labels=labels)

            output("accuracy", cset[1], m_name, "by_flows", "avg", met[0], output_file)

            output("precision", cset[1], m_name, "by_flows", labels, met[1], output_file)
            output("precision", cset[1], m_name, "by_flows", "avg", met[1], output_file)

            output("recall", cset[1], m_name, "by_flows", labels, met[2], output_file)
            output("recall", cset[1], m_name, "by_flows", "avg", met[2], output_file)

            output("fscore", cset[1], m_name, "by_flows", labels, met[3], output_file)
            output("fscore", cset[1], m_name, "by_flows", "avg", met[3], output_file)

            """
            by_bytes
            """
            met = metrics.measure(
                testing_y, predicted, in_bytes, labels=labels)

            output("accuracy", cset[1], m_name, "by_bytes", "avg", met[0], output_file)

            output("precision", cset[1], m_name, "by_bytes", labels, met[1], output_file)
            output("precision", cset[1], m_name, "by_bytes", "avg", met[1], output_file)

            output("recall", cset[1], m_name, "by_bytes", labels, met[2], output_file)
            output("recall", cset[1], m_name, "by_bytes", "avg", met[2], output_file)

            output("fscore", cset[1], m_name, "by_bytes", labels, met[3], output_file)
            output("fscore", cset[1], m_name, "by_bytes", "avg", met[3], output_file)


def measure_n_estimators(sets_directory, output_file, max_estimators):
    if not os.path.isdir(sets_directory):
        raise NotDirecory(sets_directory)

    counter = 0

    for i in os.listdir(sets_directory):
        if i.find(".csv") < 0:
            continue

        if counter >= 2:
            break

        counter += 1
        filepath = os.path.join(sets_directory, i)

        name = i.split("_")
        if name[0].startswith("testset"):
            testing_x, testing_y = metrics.load_data(filepath)

            in_bytes = testing_x["overall_dir"] + testing_x["overall_back"]

            logging.info("Testset loaded and ready to go.")
        else:
            learning_x, learning_y = metrics.load_data(filepath)

    if max_estimators is None:
        max_estimators = 200

    for n_estimators in xrange(1, max_estimators, 2):
        for clr in (
            AdaBoostClassifier(n_estimators=n_estimators),
            RandomForestClassifier(n_estimators=n_estimators)
        ):
            model, m_name, fittime = metrics.fit(
                clr, learning_x, learning_y
            )
            output("fittime", n_estimators, m_name, "general", "avg", fittime, output_file)
            logging.info("Model with {0} fitted in {1} seconds.".format(
                m_name, fittime))

            labels = sorted(testing_y.unique())
            predicted = model.predict(testing_x)
            logging.info("Prediction completed")

            """
            by_flows
            """
            met = metrics.measure(
                testing_y, predicted, labels=labels)

            output("accuracy", n_estimators, m_name, "by_flows", "avg", met[0], output_file)

            output("fscore", n_estimators, m_name, "by_flows", labels, met[3], output_file)
            output("fscore", n_estimators, m_name, "by_flows", "avg", met[3], output_file)

            """
            by_bytes
            """
            met = metrics.measure(
                testing_y, predicted, in_bytes, labels=labels)

            output("accuracy", n_estimators, m_name, "by_bytes", "avg", met[0], output_file)

            output("fscore", n_estimators, m_name, "by_bytes", labels, met[3], output_file)
            output("fscore", n_estimators, m_name, "by_bytes", "avg", met[3], output_file)


parser = argparse.ArgumentParser(description="Packet-mapper measurement tool.")
parser.add_argument(
    "-s", "--sets",
    type=str,
    help="Sets directory."
)
parser.add_argument(
    "-o", "--output",
    type=str,
    help="File with output results."
)
parser.add_argument(
    "--estimators",
    action="store_true",
    help="Measure how many estimators AdaBoost and Random Forest need.")
parser.add_argument(
    "-n", "--n_estimators",
    type=int,
    help="Number of estimators to find optimal number.")


def main():
    args = parser.parse_args()
    if args.sets is not None:
        if args.estimators:
            measure_n_estimators(args.sets, args.output, args.n_estimators)
        else:
            measure(args.sets, args.output)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
