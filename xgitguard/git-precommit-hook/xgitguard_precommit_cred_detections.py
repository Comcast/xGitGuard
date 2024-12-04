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
import dill
import multiprocessing


import pandas as pd

MODULE_DIR = os.path.dirname(os.path.realpath('__file__'))

parent_dir = os.path.dirname(MODULE_DIR)
sys.path.insert(0, '/Users/sparri919/Documents/GitHub/xGitGuard/xgitguard')


from common.configs_read import ConfigsData
from common.data_format import (
    credential_extractor,
    format_commit_details,
    clean_credentials
)
from common.logger import create_logger
from common.ml_process import entropy_calc, ml_prediction_process
from ml_training.model import xgg_train_model
from utilities.common_utilities import mask_data
from utilities.file_utilities import write_to_csv_file
from utilities.common_utilities import check_github_token_env

file_prefix = "xgg_"

specialCharacterRegex = re.compile("^(?=.*[0-9])(?=.*[a-zA-Z])")


def calculate_confidence(secondary_keyword, secret, configs):
    """
    Calculates confidence scores for given Keywords
    params: secondary_keyword - string
    params: secret - string - Detected secret
    params: configs - class - configuration settings
    returns: confidence score
    """
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


def format_detection(file, skeyword, code_contents, parsed_line, secrets, skeyword_count, configs):
    """
    Format the secret data from the given code content and other data
        Format the secrets data in the required format
        Get the commit details from github
        Calculate the secrets confidence values
        Mask the secret if present
        Return the final formatted detections

    params: file - string - File name
    params: skeyword - string - Secondary Keyword
    params: code_contents - string - User code content untouched
    params: parsed_line - list - Line of code broken down into words
    params: secrets - list - Detected secrets list in line of code
    params: skeyword_count - int - secondary keyword count
    returns: secrets_data_list - list - List of formatted detections
    """
    valid_secret = False
    secrets_data_list = []
    secret_data = []
    unmask_secret = True

    for secret in secrets:
        secret_lower = secret.lower()
        confidence_score = calculate_confidence(skeyword, secret_lower, configs)
        if confidence_score[1] > 1.5:
            valid_secret_row = [value for value in secret_data]
            try:
                index_keyword = -1
                for i in range(len(parsed_line)):
                    if skeyword in parsed_line[i]:
                        index_keyword = i
                        break
                index_secret = parsed_line.index(secret)
                try:
                    index_colon = parsed_line.index(":")
                except:
                    index_colon = -1
                try:
                    index_equals = parsed_line.index("=")
                except:
                    index_equals = -1

                if (
                    (
                        (skeyword in code_contents)
                        and (code_contents != secret_lower)
                        and not (
                            [
                                element
                                for element in ["http", "www", "uuid", "guid", "postman-token", "cachekey", "authenticatorid", "authorizationid"]
                                if (element in code_contents)
                            ]
                        )
                        and (index_keyword < index_secret)
                        and index_secret - index_keyword < 3
                    )
                    and (
                        (
                            code_contents.find(":") < code_contents.find(secret_lower)
                            and code_contents.find(":") > code_contents.find(skeyword)
                        )
                        or (
                            code_contents.find("=") < code_contents.find(secret_lower)
                            and code_contents.find("=") > code_contents.find(skeyword)
                        )
                    )
                    and (

                        bool(specialCharacterRegex.match(secret_lower))
                        or (confidence_score[2] < 20)
                    )
                ):
                    if len(code_contents) < 300:
                        valid_secret_row.append(file)
                        valid_secret_row.append(secret)
                        valid_secret = True
            except:
                pass

            if valid_secret:
                if unmask_secret:
                    masked_secret = code_contents
                else:
                    masked_secret = mask_data(code_contents, secret)
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
    return secrets_data_list

def search_for_secrets(parsed_line, skeyword, configs, file, clean_line, secrets_data):
    formatted_secrets_data_aggregate = []
    skeyword_count = " ".join(parsed_line).lower().count(skeyword.lower())
    secrets_data_list = format_detection(file,
        skeyword, "".join(clean_line).lower(), parsed_line, secrets_data, skeyword_count, configs
    )

    if secrets_data_list:
        for secret_data in secrets_data_list:
            formatted_secrets_data_aggregate.append(secret_data)
    return formatted_secrets_data_aggregate

def correlate_secrets_to_keywords(secrets_data_list, keyword, ml_prediction, configs):
    """
        For the user code content
        Format and clean the code content
        Find the secrets
        Format the detections
        Run the ML prediction on the detection
        If detection is predicted, write the detections

    params: git_changes - all lines of the current git changes
    params: keyword - string
    params: ml_prediction - boolean

    returns: detection_writes_per_query - int - Total detections written to file
    returns: detections_per_query - int - No of detections per search
    """
    detection_writes_per_query = 0
    detections_per_query = 0
    total_secrets_map = {}
    global file_prefix

    secrets_detected = []
    skeyword = keyword.split('"')[1].strip()
    for (clean_line, parsed_line, secrets_data, file) in secrets_data_list:
        secrets_detected.extend(search_for_secrets(parsed_line, skeyword, configs, file, clean_line, secrets_data))

    detections = len(secrets_detected)
    if secrets_detected and len(secrets_detected) > 0:
        detections_per_query = detections
        try:
            secrets_detected_df = pd.DataFrame(
                secrets_detected,
                columns=configs.xgg_configs["secrets"][
                    "precommit_data_collector_columns"
                ],
            )
        except Exception as e:
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
            else:
                if not secrets_detected_df.empty:
                    detection_writes_per_query += secrets_detected_df.shape[0]
                    secrets_detected_file = os.path.join(
                        configs.output_dir,
                        "xgg_precommit_creds_detected.csv",
                    )
                    specific_secrets_attributes = secrets_detected_df.loc[:,['File','Code','Score', 'Secret']]

                    for index, row in specific_secrets_attributes.iterrows():
                        if row['Code'] not in total_secrets_map:
                            total_secrets_map[row['Code']] = (row['Code'], row['Score'], row['File'], row["Secret"])
    return detection_writes_per_query, detections_per_query, total_secrets_map


def format_keywords(secondary_keywords):
    """
    Create the search query list using Secondary Keywords
    params: secondary_keywords - list
    returns: formatted_keyword_list - list
    """
    formatted_keyword_list = []
    for secondary_keyword in secondary_keywords:
        formatted_keyword_list.append('"' + secondary_keyword + '"')
    return formatted_keyword_list

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
    then = time.time()
    git_changes = subprocess.check_output(["git", "diff", "--staged"]).decode("utf-8")
    # Read and Setup Configuration Data to reference
    configs = ConfigsData()
    configs.read_cached_dictionary_words()
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


    total_detection_writes = 0
    formatted_keyword_list = []

    # Format GitHub Search Query List
    formatted_keyword_list = format_keywords(configs.secondary_keywords)
    if formatted_keyword_list:
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

    configs.read_stop_words(file_name="stop_words.csv")
    futures = list()
    secrets_data_list = []
    file = ""
    total_secrets_found = 0
    for line in git_changes.split("\n"):
        if(line):
            if(line.strip().startswith("+++")):
                file = line[6:]
            else:
                parsed_line = clean_credentials(line)
                if(parsed_line):
                    try:
                        secrets_data = credential_extractor(parsed_line, configs.stop_words)
                        if len(secrets_data) >= 1 and len(secrets_data) <= 20:
                            clean_line = "".join(line).lower()[1:].strip()
                            secrets_data_list.append((clean_line, parsed_line, secrets_data, file))
                            total_secrets_found = total_secrets_found + 1
                        else:
                            logger.debug(
                                f"Skipping secrets_data as length is not between 1 to 20. Length: {len(secrets_data)}"
                            )
                    except Exception as e:
                        logger.error(f"Total Process Search (Exception Error): {e}")

    #Threading is only fast if the changes are large enough
    if len(git_changes) > 100000:
        with concurrent.futures.ProcessPoolExecutor(multiprocessing.cpu_count()) as executor:
            for keyword in formatted_keyword_list:
                logger.info(
                    f"*******  Processing Keyword: '{keyword}"
                )
                try:
                    if git_changes:
                        futures.append(executor.submit(correlate_secrets_to_keywords, secrets_data_list, keyword, ml_prediction, configs))
                    else:
                        logger.info(
                            f"Search '{keyword}' returns no results. Continuing..."
                        )
                        continue
                except Exception as e:
                    logger.error(f"Process Error: {e}")
        for future in concurrent.futures.as_completed(futures):
            (detection_writes_per_query, detections_per_query, current_run_secrets_map) = future.result()
            for index, (code, score, file, secret) in current_run_secrets_map.items():
                if code + file not in total_secrets_map:
                    total_secrets_map[code + file] = (code, score, file, secret)
    else:
        i = 0
        for keyword in formatted_keyword_list:
            i = i + 1
            logger.info(
                f"*******  Processing Keyword: '{keyword}"
            )
            try:
                if git_changes:
                    (detection_writes_per_query, detections_per_query, current_run_secrets_map) = correlate_secrets_to_keywords(secrets_data_list, keyword, ml_prediction, configs)
                    for index, (code, score, file, secret) in current_run_secrets_map.items():
                        if code + file not in total_secrets_map:
                            total_secrets_map[code + file] = (code, score, file, secret)
                else:
                    logger.info(
                        f"Search '{keyword}' returns no results. Continuing..."
                    )
                    continue
            except Exception as e:
                logger.error(f"Process Error: {e}")

            logger.info(
                f"Detection writes for current keyword: {detection_writes_per_query}"
            )
            total_detection_writes += detection_writes_per_query

    elapsed = time.time() - then
    output_results(total_secrets_map, total_secrets_found, elapsed)
    return True

def output_results(total_secrets_map, total_secrets_found, elapsed):
    total_secrets_with_keywords = 0
    output = ""
    for index, (code, score, file, secret) in total_secrets_map.items():
        output = output + (f"The following credentials have been detected in {file}\n")
        output = output + (f"Code: {code}\nScore: {score}\n")
        output = output + (f"Secret: {secret}\n\n")
        total_secrets_with_keywords = total_secrets_with_keywords + 1
    if output != "":
        print(output)
    logger.info(f"Total Secrets Found: {total_secrets_found}")
    logger.info(f"Total Secrets Matching Keywords: {total_secrets_with_keywords}")
    if total_secrets_with_keywords > 0:
        print("\nIf these are not credentials, use --no-verify to bypass this check:")
        print("\ngit commit -m 'message' --no-verify")
    print("\nThis detection took: " + str(int(elapsed)) + " seconds")

def setup_logger(log_level=10, console_logging=True):
    """
    Call logger create module and setup the logger for current run
    params: log_level - int - optional - Default - 20 - INFO
    params: console_logging - Boolean - optional - Enable console logging - default True
    """
    log_dir = os.path.abspath(os.path.join(os.path.dirname(MODULE_DIR), ".", "logs"))
    log_file_name = f"{os.path.basename('__file__').split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    global logger
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
        default=40,
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
        log_level = 40
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
    multiprocessing.freeze_support()
    (
        secondary_keywords,
        extensions,
        ml_prediction,
        unmask_secret,
        log_level,
        console_logging,
    ) = arg_parser()

    setup_logger(log_level, console_logging)

    logger.info("xGitGuard Credentials Detection Process Started")
    if ml_prediction:
        logger.info("Running the xGitGuard detection with ML Prediction filter")
    else:
        logger.info("Running the xGitGuard detection without ML Prediction filter")

    run_detection(secondary_keywords, extensions, ml_prediction)

    logger.info("xGitGuard Credentials Detection Process Completed")
