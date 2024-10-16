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
import numpy as np
import pandas as pd
from scipy.stats import entropy

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(MODULE_DIR)
sys.path.append(parent_dir)

from common.configs_read import ConfigsData
from utilities.common_utilities import is_num_present, is_uppercase_present
from utilities.file_utilities import read_pickle_file

logger = logging.getLogger("xgg_logger")


def ml_prediction_process(model_name, training_data, detection_data, git_env=""):
    """
    for the given training data and detection data
        Format the detections snf training data as model needed
        Predict the detection using model
        Return the Dataframe of actual detections
    params: training_data - dataframe
    params: detection_data - dataframe - Detection Data
    returns: post_prediction_data - Dataframe - Actual detections
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    pre_prediction_data = detection_data.copy()
    if git_env:
        if git_env == "public":
            detection_data = detection_data.drop(
                [
                    "Source",
                    "Primary_Key",
                    "Commit_Details",
                    "URL",
                    "Owner",
                    "Repo_Name",
                    "Detected_Timestamp",
                    "Year",
                    "Month",
                    "Day",
                ],
                axis=1,
            )
        else:
            detection_data = detection_data.drop(
                [
                    "Source",
                    "Commit_Details",
                    "URL",
                    "Owner",
                    "Repo_Name",
                    "Detected_Timestamp",
                    "Year",
                    "Month",
                    "Day",
                ],
                axis=1,
            )
    else:
        detection_data = detection_data.drop(
            [
                "Source",
                "URL",
                "Detected_Timestamp",
                "Year",
                "Month",
                "Day",
            ],
            axis=1,
        )
    try:
        detection_data["Len_Key"] = detection_data.apply(
            lambda x: len(x["Secret"]), axis=1
        )
        detection_data["Len_Code"] = detection_data.apply(
            lambda x: len(x["Code"]), axis=1
        )
        detection_data["Has_Digit"] = detection_data.apply(
            lambda x: is_num_present(x["Secret"]), axis=1
        )
        detection_data["Has_Cap"] = detection_data.apply(
            lambda x: is_uppercase_present(x["Secret"]), axis=1
        )

        detection_data = detection_data.drop(["Secret", "Code"], axis=1)
        train_dummies = pd.get_dummies(training_data)
        detection_dummies = pd.get_dummies(detection_data)
        train_dummies, detection_dummies = train_dummies.align(
            detection_dummies, join="left", axis=1
        )
        detection_dummies = detection_dummies.fillna(0)

        config_dir = os.path.abspath(
            os.path.join(os.path.dirname(MODULE_DIR), ".", "output")
        )
        model_file = os.path.join(config_dir, model_name)
        # Read pre trained Model object
        rf = read_pickle_file(model_file)
        # Predict the current detection
        predictions = rf.predict(detection_dummies)
        indexes = [i for i, e in enumerate(predictions) if e != 0]
        post_prediction_data = pre_prediction_data.iloc[indexes, :]
        return post_prediction_data
    except Exception as e:
        print(f"Error in predicting through model: {e}")
        post_prediction_data = pd.DataFrame()
        return post_prediction_data


def entropy_calc(labels, base=None):
    """
    Calculates Shannon Entropy for given labels
    params: labels - list
    params: base - Optional
    returns: entropy values - list
    """
    # logger.debug("<<<< 'Current Executing Function' >>>>")
    _, counts = np.unique(labels, return_counts=True)
    return entropy(counts, base=base)
