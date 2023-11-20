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
"""
xGitGuard Enterprise GitHub Credential Detection Process
    xGitGuard detects the secret keys and tokens present in a locally stage git changes before ocmmitting.
    When Primary Keyword is given, use the Primary Keyword
    Else, run search with Secondary Keywords and Extension combination
    Steps:
        - Get Secondary Keywords and Extension file data from config path
        - Prepare the search query list by combining Primary Keyword with each Secondary Keyword
        - Loop over each Extension for each search query
            -- Take current commmit data for the difference between staged and last commit
            -- Clean the code content and extract Secrets
            -- Detect the Secrets using RegEx and format Secret records
            -- Predict the Secret data using ML model
    Example Commands:
    By default all configuration keys will be taken from config files.

    # Run with Secondary Keywords and Extensions from config files:
    python precommit_cred_detections.py

    # Run with Secondary Keywords from config file and given list of Extensions:
    python precommit_cred_detections.py -e "py,txt"

    # Run for given Secondary Keyword and Extension without ML prediction:
    python precommit_cred_detections.py -s "password" -e "py"

    # Run for given Secondary Keyword and Extension with ML prediction and debug console logging:
    python precommit_cred_detections.py -s "password" -e "py" -m Yes -l 10 -c Yes
"""

import argparse
import hashlib
import math
import os
import re
import sys
import time
from datetime import datetime
import subprocess
import concurrent.futures


import pandas as pd

MODULE_DIR = os.path.dirname(os.path.realpath('__file__'))

parent_dir = os.path.dirname(MODULE_DIR)
sys.path.insert(0, '/Users/sparri919/Documents/GitHub/xGitGuard/xgitguard')


from common.configs_read import ConfigsData
from common.data_format import (
    credential_extractor,
    format_commit_details,
    clean_cred
)
from common.logger import create_logger
from common.ml_process import entropy_calc, ml_prediction_process
from ml_training.model import xgg_train_model
from utilities.common_utilities import mask_data
from utilities.file_utilities import write_to_csv_file
from utilities.common_utilities import check_github_token_env

file_prefix = "xgg_"


def calculate_confidence(secondary_keyword, secret, configs):
    """
    Calculates confidence scores for given Keywords
    params: secondary_keyword - string
    params: extension - string
    params: secret - string - Detected secret
    returns: confidence score
    """
    # logger.debug("<<<< 'Current Executing Function' >>>>")
    secondary_keyword_value = int(
        configs.confidence_values.loc[secondary_keyword]["value"]
    )
    try:
        extension_value = int(configs.confidence_values.loc[extension]["value"])
    except:
        extension = 0
        extension_value = 0

    entro = entropy_calc(list(secret))
    d_match = configs.dict_words_ct * configs.dict_words_vc.transform([secret]).T

    return [sum([secondary_keyword_value, extension_value]), entro, d_match[0]]


def format_detection(file, skeyword, code_contents, secrets, skeyword_count, configs):
    """
    Format the secret data from the given code content and other data
        Format the secrets data in the required format
        Get the commit details from github
        Calculate the secrets confidence values
        Mask the secret if present
        Return the final formatted detections

    params: skeyword - string - Secondary Keyword
    params: code_contents - list - User code content
    params: secrets - list - Detected secrets list
    params: skeyword_count - int - secondary keyword count
    returns: secrets_data_list - list - List of formatted detections
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    valid_secret = False
    secrets_data_list = []
    secret_data = []
    global unmask_secret

    logger.debug("<<<< 'Current Executing Function calculate_confidence loop' >>>>")
    for secret in secrets:
        # Calculate confidence values for detected secrets
        confidence_score = calculate_confidence(skeyword, secret, configs)
        if confidence_score[1] > 1.5:
            valid_secret_row = [value for value in secret_data]
            secret_lines = re.findall(".*" + secret + ".*$", code_contents, re.MULTILINE)
            # code_line = secret
            for secret_line in secret_lines:
                if (
                    (
                        (skeyword in secret_line)
                        and (secret_line != secret)
                        and not (
                            [
                                element
                                for element in ["http", "www", "uuid"]
                                if (element in secret_line)
                            ]
                        )
                        and (secret_line.find(skeyword) < secret_line.find(secret))
                    )
                    and (
                        (
                            secret_line.find(":") < secret_line.find(secret)
                            and secret_line.find(":") > secret_line.find(skeyword)
                        )
                        or (
                            secret_line.find("=") < secret_line.find(secret)
                            and secret_line.find("=") > secret_line.find(skeyword)
                        )
                    )
                    and (
                        bool(re.match("^(?=.*[0-9])(?=.*[a-zA-Z])", secret))
                        or (confidence_score[2] < 20)
                    )
                ):
                    if len(secret_line) < 300:
                        code_line = secret_line
                        valid_secret_row.append(file)
                        valid_secret_row.append(secret)
                        valid_secret = True
                        break
            if valid_secret:
                if unmask_secret:
                    masked_secret = code_line
                else:
                    # Mask the current secret
                    masked_secret = mask_data(code_line, secret)
                valid_secret_row.append(masked_secret)
                valid_secret_row.append(confidence_score[0])
                count_score = math.log2(50) / (math.log2(skeyword_count + 1) + 1)
                valid_secret_row.append(count_score)
                valid_secret_row.append(confidence_score[1])
                d_match = math.log2(100) / (math.log2(confidence_score[2] + 1) + 1)
                valid_secret_row.append(d_match)
                valid_secret_row.append(
                    confidence_score[0] + confidence_score[1] + count_score + d_match
                )
                now = datetime.now()
                secrets_data_list.append(valid_secret_row)
                valid_secret = False
    logger.debug(f"Current formatted secrets_data_list count: {len(secrets_data_list)}")
    # logger.debug(f"secrets_data_list: {secrets_data_list}")
    return secrets_data_list


def process_file_diffs(code_contents, search_query, configs, index):
    """
        Extract secret values using regex
        Format the secrets detected
        Return the secrets detected
    params: search_query - string
    returns: secrets_data_list - list - Detected secrets data
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Processes search findings
    skeyword = search_query.split('"')[1].strip()
    secrets_data_list = []

    file = ""
    for line in code_contents.split("\n"):
        start = time.time()
        if(line):
            if(line.strip().startswith("+++")):
                file = line[6:]
            else:
                parsed_line = clean_cred(line, skeyword, index, start)
                if(parsed_line):
                    try:
                        try:
                            # for Reading Data only one time
                            if configs.stop_words:
                                pass
                        except:
                            configs.read_stop_words(file_name="stop_words.csv")
                        secrets_data = credential_extractor(parsed_line, configs.stop_words)

                        skeyword_count = " ".join(parsed_line).lower().count(skeyword.lower())
                        if len(secrets_data) >= 1 and len(secrets_data) <= 20:
                            clean_line = "".join(line).lower()[1:].strip()
                            secret_data_list = format_detection(file,
                                skeyword, "".join(clean_line).lower(), secrets_data, skeyword_count, configs
                            )
                            if secret_data_list:
                                for secret_data in secret_data_list:
                                    secrets_data_list.append(secret_data)
                        else:
                            logger.debug(
                                f"Skipping secrets_data as length is not between 1 to 20. Length: {len(secrets_data)}"
                            )
                    except Exception as e:
                        logger.error(f"Total Process Search (Exception Error): {e}")
    return secrets_data_list


def process_search_results(index, git_changes, search_query, ml_prediction, total_secrets_map, configs):
    """
        For the user code content
        Format and clean the code content
        Find the secrets
        Format the detections
        Run the ML prediction on the detection
        If detection is predicted, write the detections

    params: git_changes - all lines of the current git changes
    params: search_query - string
    params: ml_prediction - boolean

    returns: detection_writes_per_query - int - Total detections written to file
    returns: detections_per_query - int - No of detections per search
    """
    #print("Thread: " + str(index) + " started")
    logger.debug("<<<< 'Current Executing Function' >>>>")
    detection_writes_per_query = 0
    detections_per_query = 0
    global file_prefix

    secrets_detected = process_file_diffs(git_changes, search_query, configs, index)
    detections = len(secrets_detected)
    if secrets_detected:
        detections_per_query = detections
        try:
            logger.debug(
                f"Current secrets_detected count: {len(secrets_detected)}"
            )
            # logger.debug(f"secrets_detected: {secrets_detected}")
            secrets_detected_df = pd.DataFrame(
                secrets_detected,
                columns=configs.xgg_configs["secrets"][
                    "precommit_data_collector_columns"
                ],
            )
        except Exception as e:
            logger.error(
                f"secrets_detected Dataframe creation failed. Error: {e}"
            )
            secrets_detected_df = pd.DataFrame(
                columns=configs.xgg_configs["secrets"][
                    "precommit_data_collector_columns"
                ],
            )
        if not secrets_detected_df.empty:
            if ml_prediction == True:
                # for Reading training Data only one time
                try:
                    if configs.training_data:
                        pass
                except:
                    configs.read_training_data(file_name="cred_train.csv")

                secrets_ml_predicted = ml_prediction_process(
                    model_name="xgg_cred_rf_model_object.pickle",
                    training_data=configs.training_data,
                    detection_data=secrets_detected_df,
                )

                if not secrets_ml_predicted.empty:
                    detection_writes_per_query += secrets_ml_predicted.shape[0]
                    secrets_ml_predicted = secrets_ml_predicted.drop(
                        "Secret", 1
                    )
                    logger.debug(
                        f"Current secrets_ml_predicted count: {secrets_ml_predicted.shape[0]}"
                    )
                    try:
                        secrets_detected_file = os.path.join(
                            configs.output_dir,
                            "xgg_ml_precommit_creds_detected.csv",
                        )
                        write_to_csv_file(
                            secrets_ml_predicted, secrets_detected_file
                        )
                    except Exception as e:
                        logger.error(f"Process Error: {e}")
            else:
                if not secrets_detected_df.empty:
                    detection_writes_per_query += secrets_detected_df.shape[0]
                    secrets_detected_df = secrets_detected_df.drop(
                        "Secret", axis=1
                    )

                    logger.debug(
                        f"Current secrets_detected_df count: {secrets_detected_df.shape[0]}"
                    )
                    try:
                        secrets_detected_file = os.path.join(
                            configs.output_dir,
                            "xgg_precommit_creds_detected.csv",
                        )
                        specific_secrets_attributes = secrets_detected_df.loc[:,['File','Code','Score']]
                        file = ""
                        for index, row in specific_secrets_attributes.iterrows():
                            if row['Code'] not in total_secrets_map:
                                total_secrets_map[row['Code']] = 1
                                if(row['File'] != file):
                                    print("The following credentials have been detected:\n")
                                    print(f"File: {row['File']}")
                                file = row['File']
                                print(f"Code: {row['Code']}\nScore: {row['Score']}\n")
                        write_to_csv_file(
                            secrets_detected_df, secrets_detected_file
                        )
                    except Exception as e:
                        logger.error(f"Process Error: {e}")
        else:
            logger.debug(
                "secrets_detected_df is empty. So skipping collection/prediction."
            )
    else:
        logger.info("No Secrets in current search results")
    return index, detection_writes_per_query, detections_per_query


def format_search_query_list(secondary_keywords):
    """
    Create the search query list using Secondary Keywords
    params: secondary_keywords - list
    returns: search_query_list - list
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    search_query_list = []
    # Format GitHub Search Query
    for secondary_keyword in secondary_keywords:
        search_query_list.append('"' + secondary_keyword + '"')
    logger.info(f"Total search_query_list count: {len(search_query_list)}")
    return search_query_list

def timed(func):
    def _w(*a, **k):
        then = time.time()
        res = func(*a, **k)
        elapsed = time.time() - then
        return elapsed, res
    return _w

def run_detection(secondary_keywords=[], extensions=[], ml_prediction=False):
    """
    Run GitHub detections
    Run search with Secondary Keywords and extension combination
    Steps:
        Get Secondary Keywords and Extension file data from config path
        Prepare the search query list by combining Primary Keyword with each Secondary Keyword
        Loop over each extension for each search query
            Get the code content for the current git diff
            Clean the code content and extract secrets
            Detect the secrets using RegEx and format secret records
            Predict the secret data using ML model
            Write the cleaned and detected secret data

    params: secondary_keywords - list - optional
    params: extensions - list - optional
    params: ml_prediction - Boolean - optional - Default: False
    returns: True or False

    Examples:
    Run for xGG Scan with ML
        run_detection(ml_prediction=True)

    Run for given Secondary Keyword and extension With ML Prediction
        run_detection(secondary_keywords=["auth"], extensions=["py"], ml_prediction=True)

    Run for given Secondary Keyword and extension Without ML Prediction
        run_detection(secondary_keywords=["auth"], extensions=["py"])

    Run without Secondary Keywords and extensions from config files
        run_detection()

    Run without Secondary Keywords from config file and given list of extensions
        run_detection(extension = ["py","txt"])
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Read and Setup Configuration Data to reference
    configs = ConfigsData()
    configs.read_dictionary_words()
    configs.read_confidence_values(file_name="confidence_values.csv")

    if secondary_keywords:
        if isinstance(secondary_keywords, list):
            configs.secondary_keywords = secondary_keywords
        else:
            logger.error(f"Please pass secondary_keywords in List like '['password',]'")
            sys.exit(1)
    else:
        # Get the secondary_keywords from secondary_keywords file
        configs.read_secondary_keywords(file_name="secondary_keys_creds.csv")
    logger.info(f"Total Secondary Keywords: {len(configs.secondary_keywords)}")

    if extensions:
        if isinstance(secondary_keywords, list):
            configs.extensions = extensions
        else:
            logger.error(f"Please pass extensions in List like '['py',]'")
            sys.exit()
    else:
        # Get the extensions from extensions file
        configs.read_extensions(file_name="extensions.csv")
    logger.info(f"Total Extensions: {len(configs.extensions)}")

    total_search_pairs = len(configs.secondary_keywords) * len(configs.extensions)
    logger.info(f"Total Search Pairs: {total_search_pairs}")

    total_processed_search, total_detection_writes = 0, 0
    search_query_list = []
    # Format GitHub Search Query List
    search_query_list = format_search_query_list(configs.secondary_keywords)
    if search_query_list:
        if ml_prediction:
            # Train Model if not present Already
            model_file = os.path.join(
                configs.output_dir, "xgg_cred_rf_model_object.pickle"
            )
            if os.path.exists(model_file):
                logger.info(
                    f"Detection process will use Already persisted Trained Model present in: {model_file}"
                )
            else:
                logger.info(
                    f"No persisted Trained Model present. So training and persisting a model now"
                )
                xgg_train_model(
                    training_data_file="cred_train.csv", model_name="xgg_cred_rf_"
                )
    else:
        logger.info(f"No Search query to process. Ending.")
        sys.exit(1)

    total_secrets_map = dict()
    # Loop over each extension for each search query
    #for extension in configs.extensions:
    futures = list()
    git_changes = subprocess.check_output(["git", "diff", "--staged"]).decode("utf-8")

    with concurrent.futures.ThreadPoolExecutor(100) as executor:
        i = 0
        for search_query in search_query_list:
            i = i + 1
            detection_writes_per_query = 0
            detections_per_query = 0
            logger.info(
                f"*******  Processing Search Query: '{search_query}"
            )
            try:
                # Search GitHub and return search response confidence_score
                total_processed_search += 1
                # If search has detections, process the code changes
                if git_changes:
                    futures.append(executor.submit(timed(process_search_results), i, git_changes, search_query, ml_prediction, total_secrets_map, configs))
                else:
                    # time.sleep(2)
                    logger.info(
                        f"Search '{search_query}' returns no results. Continuing..."
                    )
                    continue
            except Exception as e:
                logger.error(f"Process Error: {e}")

    for future in concurrent.futures.as_completed(futures):
        (elapsed, (index, detection_writes_per_query, detections_per_query)) = future.result()
        #print("Thread: " + str(index) + " finished. Time spent: " + str(elapsed) + " seconds")
        logger.info(
            f"Detection writes in current search query: {detection_writes_per_query}"
        )
        total_detection_writes += detection_writes_per_query

    logger.info(f"Current Total Processed Search: {total_processed_search}")
    logger.info(f"Current Total Detections Write: {total_detection_writes}")

    logger.info(
        f"Total: {total_search_pairs} "
        + f"Processed: {total_processed_search} "
        + f"Detected: {detections_per_query} "
        + f"Total Writes: {detection_writes_per_query} "
    )

    logger.info(f"Total Processed Search: {total_processed_search}")
    logger.info(f"Total Detections Write: {total_detection_writes}")

    if total_detection_writes > 0:
        print("\nIf these are not credentials, use --no-verify to bypass this check:")
        print("\ngit commit -m 'message' --no-verify")

    return True


def setup_logger(log_level=10, console_logging=True):
    """
    Call logger create module and setup the logger for current run
    params: log_level - int - optional - Default - 20 - INFO
    params: console_logging - Boolean - optional - Enable console logging - default True
    """
    log_dir = os.path.abspath(os.path.join(os.path.dirname(MODULE_DIR), ".", "logs"))
    log_file_name = f"{os.path.basename('__file__').split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    global logger
    # Creates a logger
    logger = create_logger(
        log_level, console_logging, log_dir=log_dir, log_file_name=log_file_name, show_current_run_logs=False
    )


def arg_parser():
    """
    Parse the command line Arguments and return the values
    params: None
    returns: secondary_keywords - list
    returns: extensions - list
    returns: ml_prediction - Boolean - Default - False
    returns: unmask_secret - Boolean - Default - False
    returns: log_level - int - Default - 20  - INFO
    returns: console_logging - Boolean - Default - True
    """
    global file_prefix
    global ml_prediction
    global unmask_secret

    argparser = argparse.ArgumentParser()
    flag_choices = ["Y", "y", "Yes", "YES", "yes", "N", "n", "No", "NO", "no"]
    log_level_choices = [10, 20, 30, 40, 50]
    argparser.add_argument(
        "-s",
        "--secondary_keywords",
        metavar="Secondary Keywords",
        action="store",
        type=str,
        default="",
        help="Pass the Secondary Keywords list as comma separated string",
    )
    argparser.add_argument(
        "-e",
        "--extensions",
        metavar="Extensions",
        action="store",
        type=str,
        default="",
        help="Pass the Extensions list as comma separated string",
    )

    argparser.add_argument(
        "-m",
        "--ml_prediction",
        metavar="Validate using ML",
        action="store",
        type=str,
        default="No",
        choices=flag_choices,
        help="Validate detections using ML",
    )

    argparser.add_argument(
        "-u",
        "--unmask_secret",
        metavar="To write secret unmasked",
        action="store",
        type=str,
        default="No",
        choices=flag_choices,
        help="To write secret unmasked",
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

    if args.secondary_keywords:
        secondary_keywords = args.secondary_keywords.split(",")
    else:
        secondary_keywords = []
    if args.extensions:
        extensions = args.extensions.split(",")
    else:
        extensions = []

    if args.ml_prediction.lower() in flag_choices[:5]:
        ml_prediction = True
        file_prefix = "xgg_ml_"
    else:
        ml_prediction = False

    if args.unmask_secret.lower() in flag_choices[:5]:
        unmask_secret = True
    else:
        unmask_secret = False

    if args.log_level in log_level_choices:
        log_level = args.log_level
    else:
        log_level = 20
    if args.console_logging.lower() in flag_choices[:5]:
        console_logging = True
    else:
        console_logging = False

    return (
        secondary_keywords,
        extensions,
        ml_prediction,
        unmask_secret,
        log_level,
        console_logging,
    )

if __name__ == "__main__":
    # Argument Parsing
    (
        secondary_keywords,
        extensions,
        ml_prediction,
        unmask_secret,
        log_level,
        console_logging,
    ) = arg_parser()

    # Setting up Logger
    setup_logger(log_level, console_logging)

    logger.info("xGitGuard Credentials Detection Process Started")
    if ml_prediction:
        logger.info("Running the xGitGuard detection with ML Prediction filter")
    else:
        logger.info("Running the xGitGuard detection without ML Prediction filter")

    run_detection(secondary_keywords, extensions, ml_prediction)

    logger.info("xGitGuard Credentials Detection Process Completed")
