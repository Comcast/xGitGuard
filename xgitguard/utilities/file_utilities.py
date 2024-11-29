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
import pickle

import pandas as pd
import yaml

logger = logging.getLogger("xgg_logger")


def read_text_file(file_path):
    """
    Read text file utility.

    This function performs the following steps:
        - Read the text file from the given path.
        - If the file is not present, exit.

    Args:
        file_path (str): The path to the text file.

    Returns:
        list: The content of the file as a list of lines.
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if os.path.exists(file_path):
        logger.info(f"Reading text data from file path: {file_path}")
        try:
            with open(file_path, "r") as infile:
                file_data = infile.readlines()
            return file_data or []
        except Exception as e:
            logger.error(f"File Read Error: {e}")
            return []
    else:
        logger.warning(f"File not present in : {file_path}")
        return []


def read_yaml_file(file_path):
    """
    Read YAML file utility.

    This function performs the following steps:
        - Read the YAML file from the given path.
        - If the file is not present, return empty data.

    Args:
        file_path (str): The path to the YAML file.

    Returns:
        dict: The content of the YAML file as a dictionary, or an empty dictionary if the file is not present.
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if os.path.exists(file_path):
        logger.info(f"Reading yaml data from file path: {file_path}")
        try:
            with open(file_path, "r") as infile:
                file_data = yaml.safe_load(infile)
            return file_data or []
        except Exception as e:
            logger.error(f"File Read Error: {e}")
            return []
    else:
        logger.warning(f"File not present in : {file_path}")
        return []


def read_csv_file(file_path, output="list", header=0):
    """
    Read CSV file utility.

    This function performs the following steps:
        - Read the CSV file from the given path.
        - If the file is not present, return empty data.

    Args:
        file_path (str): The path to the CSV file.
        output (str): The format of the output, either "dataframe" or "list". Default is "list".

    Returns:
        file_data: The content of the CSV file as a DataFrame or a list, or an empty DataFrame or list if the file is not present.
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if os.path.exists(file_path):
        logger.info(f"Reading CSV data from file path: {file_path}")
        try:
            file_dataframe = pd.read_csv(file_path, header=header)
            if output == "list":
                file_data = file_dataframe.values.tolist()
                # file_data = [item for sublist in file_data for item in sublist]
                return file_data
            else:
                return file_dataframe
        except Exception as e:
            logger.error(f"Reading CSV file Error: {e}")
            file_dataframe = pd.DataFrame()
            return [] if output == "list" else file_dataframe
    else:
        logger.warning(f"File not present in : {file_path}")
        file_dataframe = pd.DataFrame()
        return [] if output == "list" else file_dataframe


def write_to_csv_file(dataframe, csv_file_path, sep=",", write_mode="append"):
    """
    Write to CSV file utility.

    This function performs the following steps:
        - Write the DataFrame to the given path if the file is not present.
        - Raise an exception if the column order and counts do not match.
        - Append to the existing file if the file is already present.

    Args:
        dataframe (pd.DataFrame): The Pandas DataFrame to write.
        csv_file_path (str): The path to the CSV file.
        sep (str, optional): The separator to use. Default is ",".

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    logger.info(f"Write Called on: {csv_file_path}")
    if not os.path.isfile(csv_file_path):
        dataframe.to_csv(csv_file_path, mode="a", index=False, sep=sep)
        return True
    try:
        if write_mode == "overwrite":
            dataframe.to_csv(csv_file_path, mode="w", index=False, sep=sep)
            return True
        elif len(dataframe.columns) != len(
            pd.read_csv(csv_file_path, nrows=1, sep=sep).columns
        ):
            logger.error(
                f"Columns do not match!! \
                Dataframe has {len(dataframe.columns)} columns. \
                CSV file has {len(pd.read_csv(csv_file_path, nrows=1, sep=sep).columns)} columns."
            )
            raise Exception(
                f"Columns do not match!! \
                Dataframe has {len(dataframe.columns)} columns. \
                CSV file has {len(pd.read_csv(csv_file_path, nrows=1, sep=sep).columns)} columns."
            )
        elif not (
            dataframe.columns == pd.read_csv(csv_file_path, nrows=1, sep=sep).columns
        ).all():
            logger.error(
                "Columns and column order of dataframe and csv file do not match!!"
            )
            raise Exception(
                "Columns and column order of dataframe and csv file do not match!!"
            )
        else:
            dataframe.to_csv(
                csv_file_path, mode="a", index=False, sep=sep, header=False
            )
            logger.debug("CSV file Write Successful")
            return True
    except pd.errors.EmptyDataError as e:
        logger.error(f"CSV file is Empty. So writing like a new File. Error: {e}")
        dataframe.to_csv(csv_file_path, mode="a", index=False, sep=sep, header=False)
        logger.debug("CSV file Write Successful")
        return True


def write_pickle_file(object, object_file):
    """
    Write the given object as a pickle file.

    Args:
        obj (object): The object to write.
        object_file (str): The path to the pickle file.

    Returns:
        bool: True if the operation was successful.
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    logger.info(f"Writing object as pickle file: {object_file}")
    try:
        with open(object_file, "wb") as out_file:
            pickle.dump(object, out_file)
        logger.debug(f"Given object written to file as: {object_file}")
    except Exception as e:
        logger.error(f"Given object Write Failed. Error: {e}")
        raise Exception(f"Given object Write Failed. Error: {e}")
    return True


def read_pickle_file(object_file=""):
    """
    Read the pickle object file and return the object.

    Args:
        object_path (str): The path to the pickle file.

    Returns:
        object: The deserialized object from the pickle file.
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if object_file:
        logger.info(f"Reading pickle file object: {object_file}")
        try:
            with open(object_file, "rb") as in_file:
                object = pickle.load(in_file)
        except Exception as e:
            logger.error(f"Error in reading Model object: {e}")
            raise Exception(f"Error in reading Model object: {e}")
    else:
        logger.error(f"Object File not present in : {object_file}")
        raise Exception(f"Object File not present in : {object_file}")
    return object


def read_file_content(file_path, output="list"):
    """
    Read file utility.

    This function performs the following steps:
        - Read the file from the given path.
        - If the file is not present, exit.

    Args:
        file_path (str): The path to the file.
        output (str, optional): The format of the output, either "string" or "list". Default is "list".

    Returns:
        file_data (str or list): The content of the file as a string or a list of lines.
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if os.path.exists(file_path):
        logger.debug(f"Reading data from file path: {file_path}")
        try:
            with open(file_path, "r") as file:
                if output == "list":
                    file_data = file.readlines()
                else:
                    file_data = file.read()
            return file_data or ([] if output == "list" else "")
        except Exception as e:
            logger.error(f"File Read Error: {e} for file:{file_path}")
            return [] if output == "list" else ""
    else:
        logger.warning(f"File not present in : {file_path}")
        return [] if output == "list" else ""
