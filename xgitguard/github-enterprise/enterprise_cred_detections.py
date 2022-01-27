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
xGitGuard Enterprise GitHub Credential Detection process
    xGitGuard detects the secret keys and tokens present in the Enterprise Github Repository
    For the Given run GitHub search with Primary Keyword
    Else run search with Seconday Keywords and extension combination
    Steps:
        Get Secondary Keywords and Extension file data from config path
        Prepare the search query list by combining Primary Keyword with each Secondary Keyword
        Loop over each extension for each search query
            Search GitHub and get response data
            Process the response urls
            If url is already proessed in previous runs, skip the same
            Get the code content for the html urls
            Clean the code content and extract Secrets
            Detect the Secrets using RegEx and format Secret records
            Predict the Secret data using ML model
            Write the cleaned and detected url data
    calling Examples:
    By default the all configuration keys will be taken from config files

    # Run for given Secondary Keyword and extension with training with Debug Console logging
    python enterprise_cred_detections.py -s "password" -e "py" -t Yes -l 10 -c Yes

    # Run for given Secondary Keyword and extension without training
    python enterprise_cred_detections.py -s "password" -e "py"

    # Run with Secondary Keywords from config file and given list of extensions
    python enterprise_cred_detections.py -e "py,txt"

    # Run with Secondary Keywords and extensions from config files
    python enterprise_cred_detections.py
"""

import argparse
import hashlib
import math
import os
import re
import sys
from datetime import datetime

import pandas as pd
from urlextract import URLExtract

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(MODULE_DIR)
sys.path.insert(0, parent_dir)

from common.configs_read import ConfigsData
from common.data_format import (
    credential_extractor,
    format_commit_details,
    remove_url_from_creds,
)
from common.github_calls import (
    enterprise_url_content_get,
    get_github_enterprise_commits,
    run_github_search,
)
from common.logger import create_logger
from common.ml_process import entropy_calc, ml_prediction_process
from models.model import xgg_train_model
from utilities.common_utilities import mask_data
from utilities.file_utilities import write_to_csv_file


def calculate_confidence(secondary_keyword, extension, secret):
    """
    Calculates confidence scores for given Keywords
    params: secondary_keyword - string
    params: extension - string
    params: secret - string - Detected secret
    returns: confidence score
    """
    # logger.debug("<<<< 'Current Executing Function' >>>>")
    try:
        if not configs.confidence_values.empty:
            pass
    except:
        configs.read_confidence_values(file_name="confidence_values.csv")

    try:
        if not configs.dictionary_words.empty:
            pass
    except:
        # Get the dictionary_words from dictionary words file
        configs.read_dictionary_words(file_name="dictionary_words.csv")

    secondary_keyword_value = int(
        configs.confidence_values.loc[secondary_keyword]["value"]
    )

    try:
        extension_value = int(configs.confidence_values.loc[extension]["value"])
    except:
        extension = 0

    entro = entropy_calc(list(secret))
    d_match = configs.dict_words_ct * configs.dict_words_vc.transform([secret]).T

    return [sum([secondary_keyword_value, extension_value]), entro, d_match[0]]


def format_detection(skeyword, org_url, url, code_content, secrets, skeyword_count):
    """
    Format the secret data from the given code content and other data
        Format the secrets data in the required format
        Get the commit details from github
        Calculate the secrets confidence values
        Mask the secret if present
        Return the final formatted detections

    params: skeyword - string - Secondary Keyword
    params: org_url - string - github url
    params: url - string - github url
    params: code_content - list - User code content
    params: secrets - list - Detected secrets list
    params: skeyword_count - int - secondary keyword count
    returns: secrets_data_list - list - List of formatted detections
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    valid_secret = False
    secrets_data_list = []
    secret_data = []

    extension = org_url.split(".")[-1]
    user_name = org_url.split("/")[3]
    repo_name = org_url.split("/")[4]

    try:
        file_path = url.split("/contents/")[1]
        commits_api_url = configs.xgg_configs["github"]["entprise_commits_url"].format(
            user_name=user_name, repo_name=repo_name, file_path=file_path
        )
        header = configs.xgg_configs["github"]["enterprise_header"]
        api_response_commit_data = get_github_enterprise_commits(
            commits_api_url, header
        )
    except:
        commit_details = {}
    commit_details = format_commit_details(api_response_commit_data)

    secret_data.insert(0, commit_details)
    secret_data.insert(0, repo_name)
    secret_data.insert(0, user_name)
    secret_data.insert(0, org_url)
    secret_data.insert(0, extension)
    secret_data.insert(0, skeyword)
    secret_data.insert(0, "xGG_Enterprise_Credential")
    logger.debug("<<<< 'Current Executing Function calculate_confidence loop' >>>>")
    for secret in secrets:
        # Calculate confidence values for detected secrets
        confidence_score = calculate_confidence(skeyword, extension, secret)

        if confidence_score[1] > 1.5:
            valid_secret_row = [value for value in secret_data]
            secret_lines = re.findall(".*" + secret + ".*$", code_content, re.MULTILINE)
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
                        valid_secret_row.append(secret)
                        valid_secret = True
                break
            if valid_secret:
                # Mask the current secret
                masked_secret = mask_data(code_line, secret)
                valid_secret_row.append(masked_secret)
                valid_secret_row.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
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
                valid_secret_row.append(now.year)
                valid_secret_row.append(now.month)
                valid_secret_row.append(now.day)
                valid_secret_row.append(now.hour)
                secrets_data_list.append(valid_secret_row)
                valid_secret = False
    logger.debug(f"Current formatted secrets_data_list count: {len(secrets_data_list)}")
    # logger.debug(f"secrets_data_list: {secrets_data_list}")
    return secrets_data_list


def process_search_urls(org_urls_list, url_list, search_query):
    """
    Process the Search html url as below
        Get code content from GitHub for the html url
        Remove Url data from code content
        Extract secret values using regex
        Format the secrets detected
        Return the secrets detected

    params: org_urls_list - list - list of html urls to get code content
    params: url_list - list - list of html urls to get code content
    params: search_query - string
    returns: secrets_data_list - list - Detected secrets data
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Processes search findings
    skeyword = search_query.split('"')[1].strip()
    secrets_data_list = []
    extractor = URLExtract()
    try:
        for url in url_list:
            header = configs.xgg_configs["github"]["enterprise_header"]
            code_content_response = enterprise_url_content_get(url, header)
            if code_content_response:
                code_content = code_content_response.text
            else:
                logger.debug("No response for url content get call")
                continue

            try:
                url_file_extension = url.split(".")[-1]
                url_counts = extractor.find_urls(code_content)
                if len(url_counts) > 30 or url_file_extension == "md":
                    logger.debug(
                        f"Skip processing URL extract from code content as at url counts is beyond 30: {len(url_counts)}"
                    )
                    continue
            except Exception as e:
                logger.debug(
                    f"Skip processing URL extract from code content at first 10000 URL limits"
                )
                # url_counts = e.data
                continue

            lines = code_content.split("\n")
            if len(lines) <= 2:
                logger.debug(
                    f"Skiping processing URL extract from code content as url lines is beyond 2: {len(lines)}"
                )
                continue

            code_contents = remove_url_from_creds(code_content, skeyword)

            try:
                # for Reading Data only one time
                if configs.stop_words:
                    pass
            except:
                configs.read_stop_words(file_name="stop_words.csv")

            secrets_data = credential_extractor(code_contents, configs.stop_words)

            skeyword_count = code_content.lower().count(skeyword.lower())
            if len(secrets_data) >= 1 and len(secrets_data) <= 20:
                org_url = org_urls_list[url_list.index(url)]
                secret_data_list = format_detection(
                    skeyword, org_url, url, code_content, secrets_data, skeyword_count
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


def check_existing_detections(org_url_list, url_list, search_query):
    """
    Check whether the current urs where processed in previous runs
    for each url in url list
        create hex hash value for the url
        check the url hash in previous detected urls
        if not present add them to further process
        skip if its already present in detected urls

    params: url_list - List - List of search result urls
    params: search_query - String - Search query string

    returns: new_urls_list - List - New url list
    returns: new_hashed_urls - List - New Url Hash detected
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    new_org_url_list, new_urls_list, new_hashed_urls = [], [], []

    # Get the Already predicted hashed url list if present
    try:
        # for Reading training Data only one time
        if configs.hashed_urls:
            pass
    except:
        configs.read_hashed_url(file_name="enterprise_hashed_url_creds.csv")

    if url_list:
        for url in url_list:
            url_to_hash = url + search_query
            hashed_url = hashlib.md5(url_to_hash.encode()).hexdigest()
            new_hashed_url = []
            if not hashed_url in configs.hashed_urls:
                new_org_url_list.append(org_url_list[url_list.index(url)])
                new_urls_list.append(url)
                new_hashed_url.append(hashed_url)
                new_hashed_url.append(url)
            if new_hashed_url:
                new_hashed_urls.append(new_hashed_url)
    return new_org_url_list, new_urls_list, new_hashed_urls


def process_search_results(search_response_lines, search_query):
    """
    For each search response items, process as below
        Get the html urls from the search response
        Check if the current url is already processed
        if not processed, continue. else skip the url and proceed
        Get the user code content for the html url
        Format and clean the code content
        Find the secrets
        Format the detections
        Run the ML prediction on the detection
        If detection is predicted, write the detections
        Write the hashed urls to file

    params: search_response_lines - list
    params: search_query - string

    returns: detection_writes_per_query - int - Total detections written to file
    returns: new_results_per_query - int - No of new urls per query
    returns: detections_per_query - int - No of detections per search
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    detection_writes_per_query = 0
    new_results_per_query = 0
    detections_per_query = 0
    new_hashed_urls = []

    url_list, org_url_list = [], []
    for line in search_response_lines:
        html_url = line["html_url"]
        org_url_list.append(html_url)
        html_url = (
            configs.xgg_configs["github"]["enterprise_pre_url"]
            + line["repository"]["full_name"]
            + "/contents/"
            + line["path"]
        )
        url_list.append(html_url)

    if url_list:
        # Check if current url is processed in previous runs
        new_org_urls_list, new_urls_list, new_hashed_urls = check_existing_detections(
            org_url_list, url_list, search_query
        )
        new_results_per_query = len(new_urls_list)
        if new_hashed_urls:
            secrets_detected = process_search_urls(
                new_org_urls_list, new_urls_list, search_query
            )
            detections_per_query += len(secrets_detected)
            if secrets_detected:
                try:
                    logger.debug(
                        f"Current secrets_detected count: {len(secrets_detected)}"
                    )
                    # logger.debug(f"secrets_detected: {secrets_detected}")
                    secrets_detected_df = pd.DataFrame(
                        secrets_detected,
                        columns=configs.xgg_configs["secrets"][
                            "enterprise_data_columns"
                        ],
                    )
                except Exception as e:
                    logger.error(
                        f"secrets_detected Dataframe creation failed. Error: {e}"
                    )
                    secrets_detected_df = pd.DataFrame(
                        columns=configs.xgg_configs["secrets"][
                            "enterprise_data_columns"
                        ],
                    )
                if not secrets_detected_df.empty:
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
                        secrets_ml_predicted = secrets_ml_predicted.drop("Secret", 1)
                        logger.debug(
                            f"Current secrets_ml_predicted count: {secrets_ml_predicted.shape[0]}"
                        )
                        try:
                            secrets_detected_file = os.path.join(
                                configs.config_dir, "xgg_enterprise_creds_detected.csv"
                            )
                            write_to_csv_file(
                                secrets_ml_predicted, secrets_detected_file
                            )
                        except Exception as e:
                            logger.error(f"Process Error: {e}")
                else:
                    logger.debug(
                        "secrets_detected_df is empty. So skipping ML prediction."
                    )
            else:
                logger.info("No Secrets in current search results")
            hashed_urls_file = os.path.join(
                configs.config_dir, "enterprise_hashed_url_creds.csv"
            )
            try:
                new_hashed_urls_df = pd.DataFrame(
                    new_hashed_urls, columns=["hashed_url", "url"]
                )
                write_to_csv_file(new_hashed_urls_df, hashed_urls_file)
            except Exception as e:
                logger.error(f"File Write error: {e}")
                sys.exit(1)
        else:
            logger.info(
                f"All {len(url_list)} urls in current search is already processed and hashed"
            )
    else:
        logger.info(f"No valid html urls in the current serach results to process.")
    return detection_writes_per_query, new_results_per_query, detections_per_query


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


def run_detection(secondary_keywords=[], extensions=[], train_model=False):
    """
    Run GitHub detections
    Run search with Seconday Keywords and extension combination
    Steps:
        Get Secondary Keywords and Extension file data from config path
        Prepare the search query list by combining Primary Keyword with each Secondary Keyword
        Loop over each extension for each search query
            Search GitHub and get response data
            Process the response urls
            If url is already proessed in previous runs, skip the same
            Get the code content for the html urls
            Clean the code content and extract secrets
            Detect the secrets using RegEx and format secret records
            Predict the secret data using ML model
            Write the cleaned and detected secret data

    params: secondary_keywords - list - optional
    params: extensions - list - optional
    params: train_model - Boolean - optional - Default: False
    returns: True or False

    Examples:
    Run for given Secondary Keyword and extension with training
        run_detection(secondary_keywords=["auth"], extensions=["py"], train_model=True)

    Run for given Secondary Keyword and extension without training
        run_detection(secondary_keywords=["auth"], extensions=["py"])

    Run without Secondary Keywords and extensions from config files
        run_detection()

    Run without Secondary Keywords from config file and given list of extensions
        run_detection(extension = ["py","txt"])
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Read and Setup Global Configuaration Data to reference in all process
    try:
        global configs
        if configs:
            pass
    except:
        # Setting Global configuration Data
        configs = ConfigsData()

    if secondary_keywords:
        if isinstance(secondary_keywords, list):
            configs.secondary_keywords = secondary_keywords
        else:
            logger.error(f"Please pass secondary_keywords in List like '['password',]'")
            sys.exit(1)
    else:
        # Get the secondary_keywords from secondary_keywords file
        configs.read_secondary_keywords(file_name="secondary_creds.csv")
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
        if train_model:
            xgg_train_model(
                training_data_file="cred_train.csv", model_name="xgg_cred_rf_"
            )
        else:
            # Train Model if not present Already
            model_file = os.path.join(
                configs.config_dir, "xgg_cred_rf_model_object.pickle"
            )
            if os.path.exists(model_file):
                logger.info(
                    f"Detection process will use Already persisted Trained Model present in: {model_file}"
                )
            else:
                xgg_train_model(
                    training_data_file="cred_train.csv", model_name="xgg_cred_rf_"
                )
    else:
        logger.info(f"No Search query to process. Ending.")
        sys.exit(1)

    # Loop over each extension for each search query
    for extension in configs.extensions:
        for search_query in search_query_list:
            detection_writes_per_query = 0
            new_results_per_query = 0
            detections_per_query = 0
            logger.info(
                f"*******  Processing Search Query: '{search_query} extension:{extension}'  *******"
            )
            try:
                # Search GitHub and return search response confidence_score
                total_processed_search += 1
                search_response_lines = run_github_search(
                    configs.xgg_configs["github"]["enterprise_api_url"],
                    search_query,
                    extension,
                    "enterprise",
                )
                # If search has detections, process the result urls else continue next search
                if search_response_lines:
                    (
                        detection_writes_per_query,
                        new_results_per_query,
                        detections_per_query,
                    ) = process_search_results(search_response_lines, search_query)
                    logger.info(
                        f"Detection writes in current search query: {detection_writes_per_query}"
                    )
                    total_detection_writes += detection_writes_per_query
                else:
                    # time.sleep(2)
                    logger.info(
                        f"Search '{search_query}' returns no results. Continuing..."
                    )
                    continue
            except Exception as e:
                logger.error(f"Process Error: {e}")
        logger.info(f"Current Total Processed Search: {total_processed_search}")
        logger.info(f"Current Total Detections Write: {total_detection_writes}")

        if new_results_per_query >= 0:
            logger.info(
                f"Total: {total_search_pairs} "
                + f"Processed: {total_processed_search} "
                + f"Detected: {detections_per_query} "
                + f"Total Writes: {detection_writes_per_query} "
                + f"Count URL: {new_results_per_query}"
            )

    logger.info(f"Total Processed Search: {total_processed_search}")
    logger.info(f"Total Detections Write: {total_detection_writes}")
    return True


def setup_logger(log_level=10, console_logging=True):
    """
    Call logger create module and setup the logger for current run
    params: log_level - int - optional - Default - 20 - INFO
    params: console_logging - Boolean - optional - Enable console logging - default True
    """
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
    returns: secondary_keywords - list
    returns: extensions - list
    returns: train_model - Boolean - Default - False
    returns: log_level - int - Default - 20  - INFO
    returns: console_logging - Boolean - Default - True
    """

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
        "-t",
        "--train_model",
        metavar="Train Model",
        action="store",
        type=str,
        default="No",
        choices=flag_choices,
        help="Pass the Train Model as Yes or No. Default is No",
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

    return secondary_keywords, extensions, train_model, log_level, console_logging


if __name__ == "__main__":
    # Argument Parsing
    (
        secondary_keywords,
        extensions,
        train_model,
        log_level,
        console_logging,
    ) = arg_parser()

    # Setting up Logger
    setup_logger(log_level, console_logging)

    logger.info("xGitGuard Credentials Detection Prcoess Started")

    run_detection(secondary_keywords, extensions, train_model)

    logger.info("xGitGuard Credentials Detection Prcoess Completed")
