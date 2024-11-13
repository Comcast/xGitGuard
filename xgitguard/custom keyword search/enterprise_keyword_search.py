import argparse
import hashlib
import os
import sys
import pandas as pd
import time
from datetime import datetime

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))

parent_dir = os.path.dirname(MODULE_DIR)
sys.path.insert(0, parent_dir)

from common.configs_read import ConfigsData
from common.data_format import (
    format_commit_details,
)
from common.github_calls import GithubCalls
from common.logger import create_logger
from utilities.common_utilities import check_github_token_env
from utilities.file_utilities import write_to_csv_file

file_prefix = "xgg_"


def format_detection(skeyword, org_url, url):
    """
    Format the  data from the given  content and other data
    params: skeyword - string - Secondary Keyword
    params: org_url - string - github url
    params: url - string - github url
    returns: secrets_data_list - list - List of formatted detections
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    secrets_data_list = []
    secret_data = []

    user_name = org_url.split("/")[3]
    repo_name = org_url.split("/")[4]

    try:
        file_path = url.split("/contents/")[1]
        header = configs.xgg_configs["github"]["enterprise_header"]
        api_response_commit_data = githubCalls.get_github_enterprise_commits(
            user_name, repo_name, file_path, header
        )
        commit_details = format_commit_details(api_response_commit_data)
    except Exception as e:
        logger.warning(f"Github commit content formation error: {e}")
        commit_details = {}

    secret_data.insert(0, commit_details)
    secret_data.insert(0, repo_name)
    secret_data.insert(0, user_name)
    secret_data.insert(0, org_url)
    secret_data.insert(0, skeyword)
    secret_data.insert(0, "xGG_Enterprise")
    valid_secret_row = [value for value in secret_data]
    valid_secret_row.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    now = datetime.now()
    valid_secret_row.append(now.year)
    valid_secret_row.append(now.month)
    valid_secret_row.append(now.day)
    valid_secret_row.append(now.hour)
    secrets_data_list.append(valid_secret_row)
    return secrets_data_list


def process_search_urls(org_urls_list, url_list, search_query):
    """

    params: org_urls_list - list - list of html urls to get code content
    params: url_list - list - list of html urls to get code content
    params: search_query - string
    returns: secrets_data_list - list - Detected secrets data
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Processes search findings
    skeyword = search_query.split('"')[1].strip()
    secrets_data_list = []
    try:
        for url in url_list:
            org_url = org_urls_list[url_list.index(url)]
            secret_data_list = format_detection(skeyword, org_url, url)
            if secret_data_list:
                for secret_data in secret_data_list:
                    secrets_data_list.append(secret_data)
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
    params:org_url_list - List - List of search org urls
    params: url_list - List - List of search result urls
    params: search_query - String - Search query string

    returns: new_urls_list - List - New url list
    returns: new_hashed_urls - List - New Url Hash detected
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    new_org_url_list, new_urls_list, new_hashed_urls = [], [], []
    global file_prefix
    # Get the Already predicted hashed url list if present
    try:
        # for Reading training Data only one time
        if configs.hashed_urls:
            pass
    except:
        configs.read_hashed_url(
            file_name=file_prefix + "enterprise_hashed_url_custom_keywords.csv"
        )

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
    global file_prefix

    url_list, org_url_list = [], []

    hashed_urls_file = os.path.join(
        configs.output_dir, file_prefix + "enterprise_hashed_url_custom_keywords.csv"
    )
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
                    secrets_detected_df = pd.DataFrame(
                        secrets_detected,
                        columns=configs.xgg_configs["keywords"][
                            "enterprise_data_columns"
                        ],
                    )
                    detection_writes_per_query += secrets_detected_df.shape[0]
                    try:
                        secrets_detected_file = os.path.join(
                            configs.output_dir,
                            "xgg_enterprise_custom_keywords_detected.csv",
                        )
                        write_to_csv_file(secrets_detected_df, secrets_detected_file)
                    except Exception as e:
                        logger.error(f"Process Error: {e}")
                except Exception as e:
                    logger.error(f"keywords Dataframe creation failed. Error: {e}")
                    secrets_detected_df = pd.DataFrame(
                        columns=configs.xgg_configs["keywords"][
                            "enterprise_data_columns"
                        ],
                    )

            else:
                logger.info("No keywords in current search results")

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
        logger.info(f"No valid html urls in the current search results to process.")
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
    logger.info(f"Total number of items in search_query_list: {len(search_query_list)}")
    return search_query_list


def run_detection(enterprise_keywords=[], org=[], repo=[]):
    """
    Run GitHub search
    If a Enterprise keyword is provided, perform the search using the Enterprise keyword.
    params: enterprise_keywords - list - optional
    params: org - list - optional
    params: repo - list - optional
    returns: True or False

    """
    if enterprise_keywords:
        if isinstance(enterprise_keywords, list):
            configs.secondary_keywords = enterprise_keywords
        else:
            logger.error(
                f"Please pass Enterprise keywords in List like '['password',]'"
            )
            sys.exit(1)
    else:
        # Get the enterprise_keywords from enterprise_keywords file
        configs.read_secondary_keywords(file_name="enterprise_keywords.csv")
    logger.info(f"Total Enterprise keywords : {len(configs.secondary_keywords)}")

    total_search_pairs = len(configs.secondary_keywords)
    logger.info(f"Total Search Pairs: {total_search_pairs}")

    total_processed_search, total_detection_writes = 0, 0
    search_query_list = []
    # Format GitHub Search Query List
    search_query_list = format_search_query_list(configs.secondary_keywords)
    logger.info(f"Total search_query_list count: {len(search_query_list)}")

    # Loop over each extension for each search query
    for search_query in search_query_list:
        detection_writes_per_query = 0
        new_results_per_query = 0
        detections_per_query = 0
        logger.info(f"*******  Processing Search Query: {search_query}   *******")
        try:
            # Search GitHub and return search response confidence_score
            total_processed_search += 1
            # time.sleep(2)
            search_response_lines = githubCalls.run_github_search(
                search_query,
                "",
                org,
                repo,
            )
            # If search has detections, process the result urls else continue next search
            if search_response_lines:
                (
                    detection_writes_per_query,
                    new_results_per_query,
                    detections_per_query,
                ) = process_search_results(
                    search_response_lines,
                    search_query,
                )
                logger.info(
                    f"Detection writes in current search query: {detection_writes_per_query}"
                )
                total_detection_writes += detection_writes_per_query
            else:
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
            f"Total: {total_search_pairs} " + f"Processed: {total_processed_search} "
        )

    return True


def setup_logger(log_level=10, console_logging=True):
    """
    Call logger create module and setup the logger for current run
    params: log_level - int - optional - Default - 20 - INFO
    params: console_logging - Boolean - optional - Enable console logging - default True
    """
    log_dir = os.path.abspath(os.path.join(os.path.dirname(MODULE_DIR), ".", "logs"))
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
    returns: enterprise_keywords - list
    returns: org - list
    returns: repo - list
    returns: log_level - int - Default - 20  - INFO
    returns: console_logging - Boolean - Default - True
    """
    global file_prefix

    argparser = argparse.ArgumentParser()
    flag_choices = ["Y", "y", "Yes", "YES", "yes", "N", "n", "No", "NO", "no"]
    log_level_choices = [10, 20, 30, 40, 50]
    argparser.add_argument(
        "-e",
        "--enterprise_keywords",
        metavar="Enterprise Keywords",
        action="store",
        type=str,
        default="",
        help="Pass the Enterprise Keywords list as comma separated string",
    )

    argparser.add_argument(
        "-o",
        "--org",
        metavar="Owner",
        action="store",
        type=str,
        default="",
        help="Pass the Org name list as comma separated string",
    )

    argparser.add_argument(
        "-r",
        "--repo",
        metavar="Repo",
        action="store",
        type=str,
        default="",
        help="Pass the repo name list as comma separated string",
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

    if args.enterprise_keywords:
        enterprise_keywords = args.enterprise_keywords.split(",")
    else:
        enterprise_keywords = []

    if args.org:
        org = args.org.split(",")
    else:
        org = []

    if args.repo:
        if len(org) <= 0:
            repo = args.repo.split(",")
        else:
            repo = []
    else:
        repo = []

    if args.log_level in log_level_choices:
        log_level = args.log_level
    else:
        log_level = 20
    if args.console_logging.lower() in flag_choices[:5]:
        console_logging = True
    else:
        console_logging = False

    return (
        enterprise_keywords,
        org,
        repo,
        log_level,
        console_logging,
    )


if __name__ == "__main__":
    # Argument Parsing
    (
        enterprise_keywords,
        org,
        repo,
        log_level,
        console_logging,
    ) = arg_parser()

    # Setting up Logger
    setup_logger(log_level, console_logging)

    logger.info("xGitGuard Custom keyword search Process Started")

    # Read and Setup Global Configuration Data to reference in all process
    configs = ConfigsData()
    githubCalls = GithubCalls(
        configs.xgg_configs["github"]["enterprise_api_url"],
        "enterprise",
        configs.xgg_configs["github"]["enterprise_commits_url"],
    )

    # Check if the GitHub API token environment variable for "enterprise" is set
    valid_config, token_var = check_github_token_env("enterprise")
    if not valid_config:
        logger.error(
            f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)

    run_detection(enterprise_keywords, org, repo)
    logger.info("xGitGuard Custom keyword search Process  Completed")
