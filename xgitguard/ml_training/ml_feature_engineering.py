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

import argparse
import logging
import os
import sys
from datetime import datetime

import pandas as pd

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(MODULE_DIR)
sys.path.append(parent_dir)

from common.logger import create_logger
from utilities.common_utilities import is_num_present, is_uppercase_present
from utilities.file_utilities import read_csv_file, write_to_csv_file

logger = logging.getLogger("xgg_logger")


def get_training_data(file_name):
    """
    Read the given training data file or default training data file and return the training data
    params: training_data_file - string - Training data file path
    returns: training_data - Datafrmae
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if file_name:
        output_dir = os.path.abspath(
            os.path.join(os.path.dirname(MODULE_DIR), ".", "output")
        )
        training_data_file = os.path.join(output_dir, file_name)
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


def xgg_engineer_model(training_source_data_file, training_data_file=""):
    """
    Get clean data and Engineer the Model.
    params: training_source_data_file - string - file path
    params: training_data_file - string - file path - optional
    returns: None
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    logger.info("xGitGuard Feature Engineering started")
    train_data = get_training_data(training_source_data_file)
    train_data["Len_Key"] = train_data.apply(lambda x: len(x["Secret"]), axis=1)
    train_data["Len_Code"] = train_data.apply(lambda x: len(x["Code"]), axis=1)
    train_data["Has_Digit"] = train_data.apply(
        lambda x: is_num_present(x["Secret"]), axis=1
    )
    train_data["Has_Cap"] = train_data.apply(
        lambda x: is_uppercase_present(x["Secret"]), axis=1
    )
    train_data = train_data.drop(["Secret", "Code"], axis=1)

    train_data = pd.get_dummies(train_data)
    if not train_data.empty:
        try:
            output_dir = os.path.abspath(
                os.path.join(os.path.dirname(MODULE_DIR), ".", "output")
            )
            training_src_file = os.path.join(output_dir, training_data_file)
            write_to_csv_file(train_data, training_src_file, write_mode="overwrite")
        except Exception as e:
            logger.error(f"Process Error: {e}")
    else:
        logger.error(f"Empty Training source data")
    logger.info("xGitGuard Feature Engineering Ended")


def setup_logger(run_mode="training", log_level=10, console_logging=True):
    """
    Call logger create module and setup the logger for current run
    params: run_mode - str - optional - Default - training
    params: log_level - int - optional - Default - 20 - INFO
    params: console_logging - Boolean - optional - Enable console logging - default True
    """

    log_dir = os.path.abspath(os.path.join(os.path.dirname(MODULE_DIR), ".", "logs"))
    log_file_name = f"{run_mode}_{os.path.basename(__file__).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

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
    returns: source_data - string - Default - enterprise
    returns: log_level - int - Default - 20  - INFO
    returns: console_logging - Boolean - Default - True
    """

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
        "-s",
        "--source_data",
        metavar="Source Data",
        action="store",
        type=str,
        default="enterprise",
        choices=["enterprise", "public"],
        help="Pass the source of data as public or enterprise. Default is enterprise",
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

    if args.source_data:
        source_data = args.source_data.lower()
    else:
        logger.error(f"No Source Data is passed in command line.")
        sys.exit(1)

    if args.log_level in log_level_choices:
        log_level = args.log_level
    else:
        log_level = 20
    if args.console_logging.lower() in flag_choices[:5]:
        console_logging = True
    else:
        console_logging = False

    return data_type, source_data, log_level, console_logging


if __name__ == "__main__":

    (
        data_type,
        source_data,
        log_level,
        console_logging,
    ) = arg_parser()

    run_mode = source_data + "_" + data_type
    setup_logger(run_mode, log_level, console_logging)

    logger.info(f"{run_mode.upper()} Feature Engineering process Started")
    output_dir = os.path.abspath(
        os.path.join(os.path.dirname(MODULE_DIR), ".", "output")
    )
    training_source_data_file, training_data_file = "", ""
    if source_data == "public":
        if data_type == "cred":

            public_cred_src_file = os.path.join(
                output_dir, "public_cred_train_source.csv"
            )
            if os.path.exists(public_cred_src_file):
                logger.info(
                    "Using public cred source data to engineer for public model"
                )
                training_source_data_file = "public_cred_train_source.csv"
                training_data_file = "public_cred_train.csv"

            else:
                logger.error(
                    f"Cred Training source data file for engineering not found"
                )
        elif data_type == "key":
            public_key_src_file = os.path.join(
                output_dir, "public_key_train_source.csv"
            )
            if os.path.exists(public_key_src_file):
                logger.info("Using public key source data to engineer for public model")

                training_source_data_file = "public_key_train_source.csv"
                training_data_file = "public_key_train.csv"
            else:
                logger.error(f"Key Training source data file for engineering not found")
    else:
        if data_type == "cred":
            logger.info(
                "Using enterprise cred source data to engineer for enterprise model"
            )
            training_source_data_file = "cred_train_source.csv"
            training_data_file = "cred_train.csv"

        elif data_type == "key":
            logger.info(
                "Using enterprise key source data to engineer for enterprise model"
            )
            training_source_data_file = "key_train_source.csv"
            training_data_file = "key_train.csv"

    if training_source_data_file and training_data_file:
        xgg_engineer_model(
            training_source_data_file=training_source_data_file,
            training_data_file=training_data_file,
        )
