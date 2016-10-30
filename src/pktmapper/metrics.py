"""
Measure metrics
---

Package: PACKET-MAPPER
Author: Sapunov Nikita <kiton1994@gmail.com>
"""

from sklearn import metrics
import logging
import os
import pandas as pd
import time


log_format = u"%(asctime)s LINE:%(lineno)-3d %(levelname)-8s %(message)s"
logging.basicConfig(level=logging.INFO,
                    datefmt="%d.%m.%y %H:%M:%S",
                    format=log_format
                    )


class FileNotFound(Exception):
    def __init__(self, filename):
        Exception.__init__(self, filename)


def load_data(path):
    """
    Load and split imput data on features and target class (X and y).

    Args:
        path: path to the data
    Returns:
        tuple: features and target class (pandas DataFrame)
    """
    if not os.path.exists(path):
        raise FileNotFound(path)
    data = pd.read_csv(path)

    cols = data.columns.tolist()
    cols.remove("application")

    return data[cols], data["application"]


def fit(clf, x_train, y_train):
    """
    Wrapper for sklearn.<Claasificator>.fit() method.

    Args:
        clf: Classifier instance
        X_train: features
        y_train: targets
    Returns:
        model, name_of_classifier, model_fit_time
    """
    _clr_name_map = {
        "adaboostclassifier": "AdaBoost",
        "decisiontreeclassifier": "CART",
        "gaussiannb": "GaussianNB",
        "linearsvc": "LinearSVC",
        "randomforestclassifier": "RandomForest"
    }

    _clr_name = clf.__str__().split("(")[0].lower()
    clr_name = _clr_name_map[_clr_name]

    starttime = time.time()
    logging.info("Start fitting {0}. Training set size is {1}".format(
        clr_name, len(y_train)))
    model = clf.fit(x_train, y_train)
    stoptime = time.time()

    return model, clr_name, round(stoptime - starttime, 4)


def measure(y_true, y_pred, weights=None, labels=None):
    """
    Measure accuracy, precision, f1-measure and recall.

    Args:
        y_true: predicred values vector
        y_pred: ground truth
        weights: Sample weights
        labels: list of labels
    Returns:
        tuple: accuracy, precision, recall, fscore, support
    """
    logging.info("Start measurement by_bytes={0}".format(weights is not None))

    p, r, f1, s = metrics.precision_recall_fscore_support(
        y_true, y_pred, average=None, sample_weight=weights, labels=labels)
    a = metrics.accuracy_score(y_true, y_pred, sample_weight=weights)

    return a, p, r, f1, s
