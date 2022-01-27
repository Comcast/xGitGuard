"""
Copyright 2021 Comcast Cable Communications Management, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
"""
import logging
import os
import sys
from datetime import datetime

from sklearn import metrics
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(MODULE_DIR)
sys.path.append(parent_dir)

from utilities.file_utilities import read_csv_file, write_pickle_file

logger = logging.getLogger("xgg_logger")


def get_training_data(file_name):
    """
    Read the given training data file or default training data file and return the training data
    params: training_data_file - string - Training data file path
    returns: training_data - Datafrmae
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if file_name:
        config_dir = os.path.abspath(
            os.path.join(os.path.dirname(MODULE_DIR), ".", "config")
        )
        training_data_file = os.path.join(config_dir, file_name)
        if os.path.exists(training_data_file):
            logger.debug(f"Reading Training data from file: {training_data_file}")
            training_data = read_csv_file(training_data_file, output="dataframe")
        else:
            logger.error(
                f"Training_data_file given is not present. Please check the file path: {training_data_file}"
            )
            raise Exception(
                f"Training_data_file given is not present. Please check the file path: {training_data_file}"
            )
    else:
        logger.error(
            "Training data file is not given. Please pass the input training Data file"
        )
        raise Exception(
            "Training data file is not given. Please pass the input training Data file"
        )

    return training_data


def train_and_test_model(training_data):
    """
    Train the model with training data and test the model.
    params: training_data - dataframe - Training Data
    returns: rf - object - Trained model
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Get Training Data
    x = training_data.drop(columns="Label", axis=1)
    # target variable
    y = training_data["Label"]

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.3, random_state=123
    )

    rf = RandomForestClassifier(n_estimators=500, max_depth=3)
    rf.fit(x_train, y_train)

    y_pred = rf.predict(x_test)

    logger.debug("Detection Validation model is trained.")
    logger.debug(f"Random Forest Accuracy:{metrics.accuracy_score(y_test, y_pred)}")
    logger.debug(f"Precision: {metrics.precision_score(y_test, y_pred)}")
    logger.debug(f"Recall: {metrics.recall_score(y_test, y_pred)}")
    logger.debug(f"F1 Score: {metrics.f1_score(y_test, y_pred)}")

    return rf


def xgg_train_model(training_data_file, model_name=""):
    """
    Get trainind data and Train the Model. Test and persist the model
    params: training_data_file - string - file path
    returns: None
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    logger.info("xGitGuard Model Training started")
    training_data = get_training_data(training_data_file)
    ml_model = train_and_test_model(training_data)
    config_dir = os.path.abspath(
        os.path.join(os.path.dirname(MODULE_DIR), ".", "config")
    )
    model_file = os.path.join(config_dir, model_name + "model_object.pickle")
    write_pickle_file(object=ml_model, object_file=model_file)
    logger.info("xGitGuard Model Training Ended")


def setup_logger(log_level=10, console_logging=True):
    """
    Call logger create module and setup the logger for current run
    params: log_level - int - optional - Default - 20 - INFO
    params: console_logging - Boolean - optional - Enable console logging - default True
    """
    from common.logger import create_logger

    log_dir = os.path.abspath(os.path.join(os.path.dirname(MODULE_DIR), ".", "config"))
    log_file_name = f"{os.path.basename(__file__).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    global logger
    # Creates a logger
    logger = create_logger(
        log_level, console_logging, log_dir=log_dir, log_file_name=log_file_name
    )


def arg_parser():
    """
    Parse the command line Arguments and return the values
    params: None
    returns: data_type - string
    returns: train_model - Boolean - Default - Yes
    returns: log_level - int - Default - 20  - INFO
    returns: console_logging - Boolean - Default - True
    """
    import argparse

    argparser = argparse.ArgumentParser()
    flag_choices = ["Y", "y", "Yes", "YES", "yes", "N", "n", "No", "NO", "no"]
    log_level_choices = [10, 20, 30, 40, 50]
    argparser.add_argument(
        "data_type",
        metavar="Data_Type",
        action="store",
        type=str,
        choices=["key", "cred"],
        help="Pass the Data_Type as cred or key",
    )
    argparser.add_argument(
        "-t",
        "--train_model",
        metavar="Train Model",
        action="store",
        type=str,
        default="Yes",
        choices=flag_choices,
        help="Pass the Train Model as Yes or No. Default is Yes",
    )
    argparser.add_argument(
        "-l",
        "--log_level",
        metavar="Logger Level",
        action="store",
        type=int,
        default=20,
        choices=log_level_choices,
        help="Pass the Logging level as for CRITICAL - 50, ERROR - 40  WARNING - 30  INFO  - 20  DEBUG - 10. Default is 20",
    )
    argparser.add_argument(
        "-c",
        "--console_logging",
        metavar="Console Logging",
        action="store",
        type=str,
        default="Yes",
        choices=flag_choices,
        help="Pass the Console Logging as Yes or No. Default is Yes",
    )

    args = argparser.parse_args()

    if args.data_type:
        data_type = args.data_type.lower()
    else:
        logger.error(f"No Data Type is passed in comand line.")
        sys.exit(1)
    if args.train_model.lower() in flag_choices[:5]:
        train_model = True
    else:
        train_model = False
    if args.log_level in log_level_choices:
        log_level = args.log_level
    else:
        log_level = 20
    if args.console_logging.lower() in flag_choices[:5]:
        console_logging = True
    else:
        console_logging = False

    return data_type, train_model, log_level, console_logging


if __name__ == "__main__":

    data_type, train_model, log_level, console_logging = arg_parser()

    setup_logger(log_level, console_logging)

    logger.info("Training Model process Started")

    if train_model:
        if data_type == "cred":
            xgg_train_model(
                training_data_file="cred_train.csv", model_name="xgg_cred_rf_"
            )
        elif data_type == "key":
            xgg_train_model(
                training_data_file="key_train.csv", model_name="xgg_key_rf_"
            )
    else:
        logger.info("Train model Flag was sent as No. So skipping the training")

    logger.info("Training, Testing and Persisting the xgg Model Completed")
