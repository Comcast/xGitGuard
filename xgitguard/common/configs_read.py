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
import pickle

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(MODULE_DIR)
sys.path.append(parent_dir)

from utilities.file_utilities import read_yaml_file, read_csv_file


logger = logging.getLogger("xgg_logger")


class ConfigsData:
    """
    Initialize and Read all the configuration files needed for the xGitGuard process
    """

    def __init__(self):
        logger.debug("Initializing Configuration Data")
        self.config_dir = os.path.abspath(
            os.path.join(os.path.dirname(MODULE_DIR), ".", "config")
        )
        self.output_dir = os.path.abspath(
            os.path.join(os.path.dirname(MODULE_DIR), ".", "output")
        )
        self.read_xgg_configs(file_name="xgg_configs.yaml")

    def read_xgg_configs(self, file_name):
        """
        Read the given xgg_configs yaml file in config path
        Set the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Loading xgg_configs from xgg_configs_file
        self.xgg_configs_file = os.path.join(self.config_dir, file_name)
        if os.path.exists(self.xgg_configs_file):
            self.xgg_configs = read_yaml_file(self.xgg_configs_file)
            logger.debug(f"xgg_configs: {self.xgg_configs}")
        else:
            logger.error(
                f"Exiting as xGitGuard Configuration file not found: {self.xgg_configs_file}"
            )
            raise Exception(
                f"Exiting as xGitGuard Configuration file not found: {self.xgg_configs_file}"
            )

    def read_primary_keywords(self, file_name):
        """
        Read the given primary keywords csv file in config path
        Set the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Loading primary keywords from primary keywords file
        self.primary_keywords_file = os.path.join(self.config_dir, file_name)
        self.primary_keywords = read_csv_file(
            self.primary_keywords_file, output="list", header=0
        )
        self.primary_keywords = [
            item for sublist in self.primary_keywords for item in sublist
        ]
        # logger.debug(f"primary_keywords: {self.primary_keywords}")

    def read_secondary_keywords(self, file_name):
        """
        Read the given secondary keywords csv file in config path
        Set the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Loading secondary keywords from secondary keywords file
        self.secondary_keywords_file = os.path.join(self.config_dir, file_name)
        self.secondary_keywords = read_csv_file(
            self.secondary_keywords_file, output="list", header=0
        )
        self.secondary_keywords = [
            item for sublist in self.secondary_keywords for item in sublist
        ]
        # logger.debug(f"secondary_keywords: {self.secondary_keywords}")

    def read_extensions(self, file_name="extensions.csv"):
        """
        Read the given extensions csv file in config path
        Set the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Get the extensions from extensions file
        self.extensions_file = os.path.join(self.config_dir, file_name)
        self.extensions = read_csv_file(self.extensions_file, output="list", header=0)
        self.extensions = [item for sublist in self.extensions for item in sublist]
        # logger.debug(f"Extensions: {self.extensions}")

    def read_hashed_url(self, file_name):
        """
        Read the given hashed url csv file in output path
        Set the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Loading Existing url hash detections
        self.hashed_url_file = os.path.join(self.output_dir, file_name)
        hashed_key_urls = read_csv_file(self.hashed_url_file, output="list", header=0)
        self.hashed_urls = [row[0] for row in hashed_key_urls]
        # logger.debug(f"hashed_urls: {self.hashed_urls}")

    def read_training_data(self, file_name):
        """
        Read the given training data csv file in output path
        Set the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        self.training_data_file = os.path.join(self.output_dir, file_name)
        self.training_data = read_csv_file(
            self.training_data_file, output="dataframe", header=0
        )
        if not self.training_data.empty:
            self.training_data = self.training_data.drop(columns="Label", axis=1)
        else:
            logger.error(
                f"Training Data is Empty. Add proper data and rerun: {self.training_data_file}"
            )
            raise Exception(
                f"Training Data is Empty. Add proper data and rerun: {self.training_data_file}"
            )

    def read_confidence_values(self, file_name="confidence_values.csv"):
        """
        Read the given confidence values csv file in config path
        Set the key as index and the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Loading confidence levels from file
        self.confidence_values_file = os.path.join(self.config_dir, file_name)

        self.confidence_values = read_csv_file(
            self.confidence_values_file, output="dataframe", header=0
        )
        if not self.confidence_values.empty:
            try:
                self.confidence_values = self.confidence_values.set_index("key")
            except Exception as e:
                logger.error(f"Confidence Values Setting Index Error: {e}")
                raise Exception(f"Confidence Values Setting Index Error: {e}")
        else:
            logger.error(
                f"confidence_values file is not present/readable: {self.confidence_values_file}"
            )
            raise Exception(
                f"confidence_values file is not present/readable: {self.confidence_values_file}"
            )


    def read_cached_dictionary_words(self, file_name="dictionary_words.csv"):
        """
        Read the given dictionary words csv file in config path
        Create dictionary similarity values
        Set the Class Variables for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Creating dictionary similarity values
        self.dictionary_words_file = os.path.join(self.config_dir, file_name)
        self.dictionary_words = read_csv_file(
            self.dictionary_words_file, output="dataframe", header=0
        )
        # logger.debug("Dictionary_words file Read")
        if not self.dictionary_words.empty:
            try:
                with open('/Users/sparri919/Documents/GitHub/xGitGuard/xgitguard/config/vectorizer.pkl', 'rb') as file:
                    self.dict_words_vc = pickle.load(file)
                with open('/Users/sparri919/Documents/GitHub/xGitGuard/xgitguard/config/count_matrix.pkl', 'rb') as file:
                    count = pickle.load(file)
                self.dict_words_ct = np.log10(count.sum(axis=0).getA1())
            except Exception as e:
                logger.error(f"Count Vectorizer Error: {e}")
                raise Exception(f"Count Vectorizer Error: {e}")
        else:
            logger.error(
                f"confidence_values file is not present/readable: {self.dictionary_words_file}"
            )
            raise Exception(
                f"confidence_values file is not present/readable: {self.dictionary_words_file}"
            )

    def read_dictionary_words(self, file_name="dictionary_words.csv"):
        """
        Read the given dictionary words csv file in config path
        Create dictionary similarity values
        Set the Class Variables for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Creating dictionary similarity values
        self.dictionary_words_file = os.path.join(self.config_dir, file_name)
        self.dictionary_words = read_csv_file(
            self.dictionary_words_file, output="dataframe", header=0
        )
        # logger.debug("Dictionary_words file Read")
        # run Count Vectorizer
        if not self.dictionary_words.empty:
            try:
                self.dict_words_vc = CountVectorizer(
                    analyzer="char", ngram_range=(3, 5), min_df=1e-5, max_df=1.0
                )
                count = self.dict_words_vc.fit_transform(
                    self.dictionary_words["dic_word"].apply(
                        lambda count: np.str_(count)
                    )
                )
                self.dict_words_ct = np.log10(count.sum(axis=0).getA1())
                # logger.debug("Dictionary_words data Count Vectorized")
            except Exception as e:
                logger.error(f"Count Vectorizer Error: {e}")
                raise Exception(f"Count Vectorizer Error: {e}")
        else:
            logger.error(
                f"confidence_values file is not present/readable: {self.dictionary_words_file}"
            )
            raise Exception(
                f"confidence_values file is not present/readable: {self.dictionary_words_file}"
            )

    def read_stop_words(self, file_name="stop_words.csv"):
        """
        Read the given stop words csv file in config path
        Set the Class Variable for further use
        params: file_name - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        # Get the programming language stop words
        self.stop_words_file = os.path.join(self.config_dir, file_name)
        self.stop_words = read_csv_file(self.stop_words_file, output="list", header=0)
        self.stop_words = [item for sublist in self.stop_words for item in sublist]
        # logger.debug(f"Total Stop Words: {len(self.stop_words)}")


if __name__ == "__main__":

    from datetime import datetime
    from common.logger import create_logger

    log_dir = os.path.abspath(os.path.join(os.path.dirname(MODULE_DIR), ".", "logs"))
    log_file_name = f"{os.path.basename(__file__).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    # Creates a logger
    logger = create_logger(
        log_level=10, console_logging=True, log_dir=log_dir, log_file_name=log_file_name
    )
    configs = ConfigsData()