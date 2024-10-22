import argparse
import os
import sys
from datetime import datetime
import pandas as pd
import pathlib
import hashlib
import math
import re

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(MODULE_DIR)
sys.path.insert(0, parent_dir)

from common.configs_read import ConfigsData
from common.data_format import credential_extractor, remove_url_from_creds
from common.logger import create_logger
from common.ml_process import entropy_calc, ml_prediction_process
from utilities.common_utilities import mask_data
from utilities.file_utilities import read_file_content, write_to_csv_file

file_prefix = "creds"
total_processed_search, detection_writes_count = 0, 0


def check_existing_detections(file_path):
    """
    Check whether the current files where processed in previous runs
    for each path
        check timestamp chnage of the file
        check md5 sum for the file
        check the  hash in previous detected files
        if not present add them to further process
        skip if its already present in detected files

    params: file_path - String - file path string

    returns: new_hashed_files - List - New File Hash detected
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    new_hashed_files, new_hashed_file = [], []
    global file_prefix
    global configs

    # Get the Already predicted hashed file list if present
    try:
        # for Reading  Data only one time
        if configs.hash_file_path:
            pass
    except:
        configs.read_hashed_file(file_name=file_prefix + "_xgg_hashed_file.csv")

    if file_path not in configs.hash_file_path:
        file_mod_time = os.path.getmtime(file_path)
        hash_fm_string = file_path + str(file_mod_time)
        hash_object = hashlib.md5(hash_fm_string.encode()).hexdigest()
        try:
            if hash_object:
                if not hash_object in configs.hashed_file_modified_time:
                    new_hashed_file.append(file_path)
                    new_hashed_file.append(hash_object)
                    new_hashed_file.append("")
                    new_hashed_files.append(new_hashed_file)
        except Exception as e:
            logger.error(f"Hash File Write error: {e}")
            return new_hashed_files
    else:
        file_mod_time = os.path.getmtime(file_path)
        hash_fm_string = file_path + str(file_mod_time)
        hash_object = hashlib.md5(hash_fm_string.encode()).hexdigest()
        try:
            if hash_object:
                if not hash_object in configs.hashed_file_modified_time:
                    parse_checksum = hashlib.md5(
                        pathlib.Path(file_path).read_bytes()
                    ).hexdigest()
                    if parse_checksum:
                        if not parse_checksum in configs.hashed_files:
                            new_hashed_file.append(file_path)
                            new_hashed_file.append(hash_object)
                            new_hashed_file.append(parse_checksum)
                            new_hashed_files.append(new_hashed_file)
        except Exception as e:
            logger.error(f"Hash File Write error: {e}")
            return new_hashed_files

    return new_hashed_files


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
        logger.info(
            "Reading dictionary_words.csv file completed. Proceeding to processing results"
        )
    try:
        secondary_keyword_value = int(
            configs.confidence_values.loc[secondary_keyword]["value"]
        )
    except:
        secondary_keyword_value = 0

    try:
        extension_value = int(configs.confidence_values.loc[extension]["value"])
    except:
        extension = 0
        extension_value = 0

    entro = entropy_calc(list(secret))
    d_match = configs.dict_words_ct * configs.dict_words_vc.transform([secret]).T

    return [sum([secondary_keyword_value, extension_value]), entro, d_match[0]]


def format_detection(skeyword, org_url, code_content, secrets, skeyword_count):
    """
    Format the secret data from the given code content and other data
        Format the secrets data in the required format
        Calculate the secrets confidence values
        Mask the secret if present
        Return the final formatted detections

    params: skeyword - string - Secondary Keyword
    params: org_url - string - File Path
    params: code_content - list - User code content
    params: secrets - list - Detected secrets list
    params: skeyword_count - int - secondary keyword count
    returns: secrets_data_list - list - List of formatted detections
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    secrets_data_list = []
    secret_data = []

    extension = org_url.split(".")[-1]

    secret_data.insert(0, org_url)
    secret_data.insert(0, extension)
    secret_data.insert(0, skeyword)
    secret_data.insert(0, "xGG_Credential")
    # logger.debug("<<<< 'Current Executing Function calculate_confidence loop' >>>>")
    for secret in secrets:
        # Calculate confidence values for detected secrets
        confidence_score = calculate_confidence(skeyword, extension, secret)
        logger.debug("Confidence value process completed")

        if confidence_score[1] > 1.5:

            secret_content = re.escape(secret)
            secret_lines = re.findall(
                "^.*" + secret_content + ".*$", code_content, re.MULTILINE
            )
            # code_line = secret
            for secret_line in secret_lines:
                if (
                    (
                        (skeyword in secret_line.lower())
                        and (secret_line != secret)
                        and not (
                            [
                                element
                                for element in ["http", "www", "uuid"]
                                if (element in secret_line)
                            ]
                        )
                        and (
                            secret_line.lower().find(skeyword.lower())
                            < secret_line.find(secret)
                        )
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
                        valid_secret_row = [value for value in secret_data]
                        content = []
                        content.append(secret_line)
                        code_line = secret_line
                        valid_secret_row.append(secret)
                        # Mask the current secret
                        masked_secret = mask_data(code_line, secret)
                        valid_secret_row.append(masked_secret)
                        valid_secret_row.append(
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        )
                        valid_secret_row.append(confidence_score[0])
                        count_score = math.log2(50) / (
                            math.log2(skeyword_count + 1) + 1
                        )
                        valid_secret_row.append(count_score)
                        valid_secret_row.append(confidence_score[1])
                        d_match = math.log2(100) / (
                            math.log2(confidence_score[2] + 1) + 1
                        )
                        valid_secret_row.append(d_match)
                        valid_secret_row.append(
                            confidence_score[0]
                            + confidence_score[1]
                            + count_score
                            + d_match
                        )
                        now = datetime.now()
                        valid_secret_row.append(now.year)
                        valid_secret_row.append(now.month)
                        valid_secret_row.append(now.day)
                        valid_secret_row.append(now.hour)
                        secrets_data_list.append(valid_secret_row)

    logger.debug(f"Current formatted secrets_data_list count: {len(secrets_data_list)}")
    # logger.debug(f"secrets_data_list: {secrets_data_list}")
    return secrets_data_list


def process_file_content(
    file_path, code_content, secondary_keyword, extension, secrets_data=[]
):
    """
    Process the Search
        Remove unnecessary data from code content
        Extract secret values using regex
        Format the secrets detected
        Return the secrets detected

    params: file_path - string
    params: code_content - string
    params: secondary_keyword - string
    params: extension - string
    params: secrets_data - list
    returns: secrets_data_list - list - Detected secrets data
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Processes search findings
    file_path = file_path
    code_content = code_content
    skeyword = secondary_keyword
    extension = extension
    secrets_data_list = []
    lines = code_content

    if lines:

        skeyword_count = code_content.lower().count(skeyword.lower())

        if len(secrets_data) >= 1 and len(secrets_data) <= 100:
            if len(secrets_data) >= 40:
                secrets_data = secrets_data[:40]
            secret_data_list = format_detection(
                skeyword, file_path, code_content, secrets_data, skeyword_count
            )
            if secret_data_list:
                for secret_data in secret_data_list:
                    secrets_data_list.append(secret_data)
        else:
            logger.debug(
                f"Skipping secrets_data as length is not between 1 to 20. Length: {len(secrets_data)}"
            )
    else:
        logger.debug(
            f"Skiping processing code content is empty. Content length: {len(lines)}"
        )

    return secrets_data_list


def run_detection(
    file_path,
    secondary_keyword,
    extension,
    ml_prediction=True,
    code_content="",
    secrets_data=[],
):
    """
    Run search with Secondary Keyword and extension combination in the given file
    Steps:
        Get the code content for the given file
        Clean the code content and extract secrets
        Detect the secrets using RegEx and format secret records
        Predict the secret data using ML model
        Write the cleaned and detected secret data

    params: file_path - string
    params: secondary_keyword - string
    params: extension - string
    params: ml_prediction - Boolean - optional - Default: True
    params: code_content - string
    params: secrets_data - list
    returns: None
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    # Read and Setup Global Configuration Data to reference in all process
    try:
        global configs
        if configs:
            pass
    except:
        # Setting Global configuration Data
        configs = ConfigsData()

    global detection_writes_count

    if not secondary_keyword:
        logger.error(f"Please pass secondary_keyword like 'password'")
        sys.exit(1)

    if not extension:
        logger.error(f"Please pass extension like 'py'")
        sys.exit(1)

    if code_content:
        logger.debug(
            f"Processing Scan on secondary_keyword: '{secondary_keyword}' extension: '{extension}' file: '{file_path}'"
        )

        secrets_detected = process_file_content(
            file_path, code_content, secondary_keyword, extension, secrets_data
        )

        if secrets_detected:
            try:
                logger.debug(f"Current secrets_detected count: {len(secrets_detected)}")
                # logger.debug(f"secrets_detected: {secrets_detected}")
                secrets_detected_df = pd.DataFrame(
                    secrets_detected,
                    columns=configs.xgg_configs["secrets"][
                        "local_file_scan_detection_columns"
                    ],
                )
            except Exception as e:
                logger.error(f"secrets_detected Dataframe creation failed. Error: {e}")
                secrets_detected_df = pd.DataFrame(
                    columns=configs.xgg_configs["secrets"][
                        "local_file_scan_detection_columns"
                    ],
                )
            if not secrets_detected_df.empty:
                if ml_prediction == True:
                    # for Reading training Data only one time
                    try:
                        if configs.training_data:
                            pass
                    except:
                        configs.read_training_data(file_name="public_cred_train.csv")

                    secrets_ml_predicted = ml_prediction_process(
                        model_name="public_xgg_cred_rf_model_object.pickle",
                        training_data=configs.training_data,
                        detection_data=secrets_detected_df,
                    )
                    if not secrets_ml_predicted.empty:
                        detection_writes_count += secrets_ml_predicted.shape[0]
                        secrets_ml_predicted = secrets_ml_predicted.drop(
                            ["Secret"], axis=1
                        )
                        secrets_ml_predicted = secrets_ml_predicted.drop_duplicates(
                            configs.xgg_configs["secrets"]["unique_columns"]
                        )
                        logger.debug(
                            f"Current secrets_ml_predicted count: {secrets_ml_predicted.shape[0]}"
                        )
                        try:
                            secrets_detected_file = os.path.join(
                                configs.output_dir,
                                "xgg_ml_creds_detected.csv",
                            )
                            write_to_csv_file(
                                secrets_ml_predicted, secrets_detected_file
                            )
                        except Exception as e:
                            logger.error(f"Process Error: {e}")
                else:
                    if not secrets_detected_df.empty:
                        detection_writes_count += secrets_detected_df.shape[0]
                        secrets_detected_df = secrets_detected_df.drop(
                            ["Secret"], axis=1
                        )
                        secrets_detected_df = secrets_detected_df.drop_duplicates(
                            configs.xgg_configs["secrets"]["unique_columns"]
                        )

                        logger.debug(
                            f"Current secrets_detected_df count: {secrets_detected_df.shape[0]}"
                        )
                        try:
                            secrets_detected_file = os.path.join(
                                configs.output_dir,
                                "xgg_creds_detected.csv",
                            )
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
            logger.debug("No Secrets in current search results")

        logger.debug(f"Current Total Detections Write: {detection_writes_count}")

    return None


def validate_keyword(search_query_list, file_path):
    """
    Run Search  for given  file content
    and  return whether keywords presentor not

    params: keywords - List - secondary_keyword
    params: file_path - String - file/Directory path string

    returns: List
    """
    keyword_list = []
    try:
        with open(file_path, "r", encoding="utf8") as path_f:
            for line in path_f:
                search_query_list = list(set(search_query_list) - set(keyword_list))
                for keyword in search_query_list:
                    if keyword.lower() in line.lower():
                        keyword_list.append(keyword)
    except:
        return list(set(keyword_list))
    return list(set(keyword_list))


def run_search(
    secondary_keywords=[], extensions="", search_path="", ml_prediction=True
):
    """
    Run Search  for given  directory or file using secondary keywords & extensions
    and process return file path where this keywords present for prediction.

    params: secondary_keywords - list - secondary_keywords
    params: extensions - string - extensions
    params: search_path - String - file/Directory path string
    params: ML Prediction - Boolean - Default - True
    returns: Boolean
    """

    logger.debug("<<<< 'Current Executing Function' >>>>")
    global file_prefix
    global total_processed_search
    global detection_writes_count
    new_hashed_files = check_existing_detections(search_path)

    if len(new_hashed_files) <= 0:
        logger.debug(f"Skip writing the processed path due to duplicate check")
        return False
    else:
        try:
            hashed_path_file = os.path.join(
                configs.output_dir, file_prefix + "_xgg_hashed_file.csv"
            )
            new_hashed_files_df = pd.DataFrame(
                new_hashed_files,
                columns=["files", "file_modification_hash", "hashed_files"],
            ).drop_duplicates()
            write_to_csv_file(new_hashed_files_df, hashed_path_file)
        except Exception as e:
            logger.error(f"Hash File Write error: {e}")
            return False

    if not extensions:
        logger.error(f"Extension was not parsed")
        sys.exit(1)

    search_query_list = []
    # Format  Search Query List
    search_query_list = secondary_keywords
    if not search_query_list:
        logger.info(f"No Search query to process. Ending.")
        sys.exit(1)

    keyword_list = validate_keyword(search_query_list, search_path)
    if len(keyword_list) > 0:
        if search_path and os.path.exists(search_path):
            code_content = ""
            code_content = read_file_content(search_path, output="string")
            # print(f"code_content: {code_content}")
        else:
            logger.warning(f"Given file path: '{search_path}' is not valid/present")
            return False

        logger.debug("read file content completed")
        code_contents = remove_url_from_creds(code_content, [])
        secrets_data = []
        if code_contents:
            try:
                # for Reading Data only one time
                if configs.stop_words:
                    pass
            except:
                configs.read_stop_words(file_name="stop_words.csv")

            secrets_data = credential_extractor(code_contents, configs.stop_words)
        if secrets_data:
            # Loop over each search query
            for search_query in keyword_list:
                total_processed_search = total_processed_search + 1
                run_detection(
                    search_path,
                    search_query,
                    extensions,
                    ml_prediction,
                    code_content,
                    secrets_data,
                )

    return True


def setup_logger(run_mode="default", log_level=10, console_logging=True):
    """
    Call logger create module and setup the logger for current run
    params: run_mode - str - optional - Default - default
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
    returns: secondary_keywords - list
    returns: ML Prediction - Boolean - Default - True
    returns: file_path - string
    returns: log_level - int - Default - 20  - INFO
    returns: console_logging - Boolean - Default - True
    """

    argparser = argparse.ArgumentParser()
    flag_choices = ["Y", "y", "Yes", "YES", "yes", "N", "n", "No", "NO", "no"]
    log_level_choices = [10, 20, 30, 40, 50]
    global file_prefix

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
        "-m",
        "--ml_prediction",
        metavar="Validate using ML",
        action="store",
        type=str,
        default="Yes",
        choices=flag_choices,
        help="Validate detections using ML",
    )

    argparser.add_argument(
        "-p",
        "--file_path",
        metavar="file path",
        action="store",
        type=str,
        default="",
        help="Pass the file Path for scanner",
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

    if args.ml_prediction.lower() in flag_choices[:5]:
        ml_prediction = True
        file_prefix = "creds_ml"
    else:
        ml_prediction = False

    if args.file_path:
        search_path = args.file_path
    else:
        search_path = ""

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
        ml_prediction,
        search_path,
        log_level,
        console_logging,
    )


if __name__ == "__main__":
    # Argument Parsing
    (
        secondary_keywords,
        ml_prediction,
        search_path,
        log_level,
        console_logging,
    ) = arg_parser()

    # Setting up Logger
    run_mode = file_prefix
    setup_logger(run_mode, log_level, console_logging)

    logger.info("xGitGuard File Search Process Started")

    # Read and Setup Global Configuration Data to reference in all process
    configs = ConfigsData()
    configs.read_extensions(file_name="extensions.csv")
    logger.debug(f"Total Extensions: {len(configs.extensions)}")

    if secondary_keywords:
        if isinstance(secondary_keywords, list):
            configs.secondary_keywords = secondary_keywords
        else:
            logger.error(f"Please pass secondary_keywords in List like '['password',]'")
            sys.exit(1)
    else:
        configs.read_secondary_keywords(file_name="secondary_creds.csv")

    logger.info(f"Total Secondary Keywords: {len(configs.secondary_keywords)}")

    secondary_keywords = configs.secondary_keywords
    if search_path:
        if os.path.isfile(search_path):
            try:
                if search_path.endswith(".gitignore"):
                    extensions = ".gitignore"
                else:
                    file, ext = os.path.splitext(search_path)
                    extensions = ext[1:]
                if extensions not in configs.extensions:
                    logger.debug(f"File path extension not valid {search_path}")
                    sys.exit(1)
                total_search_pairs = len(configs.secondary_keywords) * len(
                    search_path.split(",")
                )
                logger.info(f"Total Search Pairs: {total_search_pairs}")
                run_search(secondary_keywords, extensions, search_path, ml_prediction)
            except:
                raise ValueError(
                    f"File path has Error in config file for path {search_path}"
                )
    else:
        configs.read_search_files(file_name="xgg_search_files.csv")
        search_paths = configs.search_files
        total_search_pairs = len(configs.secondary_keywords) * len(search_paths)
        logger.info(f"Total Search Pairs: {total_search_pairs}")
        if search_paths:
            for search_path in search_paths:
                if os.path.isfile(search_path):
                    try:
                        if search_path.endswith(".gitignore"):
                            extensions = ".gitignore"
                        else:
                            file, ext = os.path.splitext(search_path)
                            extensions = ext[1:]
                        if extensions not in configs.extensions:
                            logger.debug(f"File path extension not valid {search_path}")
                            continue
                        run_search(
                            secondary_keywords, extensions, search_path, ml_prediction
                        )
                    except:
                        if search_path.endswith(".gitignore"):
                            run_search(
                                secondary_keywords,
                                ".gitignore",
                                search_path,
                                ml_prediction,
                            )
                        else:
                            raise ValueError(
                                f"File path has Error in config file for path {search_path}"
                            )
                else:
                    logger.debug(f"File path not found path {search_path}")

        else:
            logger.info(f"No Search paths to process from config file. Ending.")
            sys.exit(1)
    logger.info(f"Total Processed Search: {total_processed_search}")
    logger.info(f"Total Detections Write: {detection_writes_count}")

    logger.info("xGitGuard File Search Process Completed")
