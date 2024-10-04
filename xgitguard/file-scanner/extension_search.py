import argparse
import csv
from datetime import datetime
import logging
import os
import sys
from pathlib import Path

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(MODULE_DIR)
sys.path.insert(0, parent_dir)

from common.configs_read import ConfigsData
from common.logger import create_logger

logger = logging.getLogger("xgg_logger")
new_search = 0


def write_data(data):
    """
    Write the the searched data for an extension

    params: data - string - file path

    returns: Boolean
    """
    global new_search
    try:
        detected_file = os.path.join(
            configs.output_dir,
            "xgg_search_files.csv",
        )
        if new_search != 0:
            with open(detected_file, "a") as f:
                writer = csv.writer(f)
                writer.writerow([data])
        else:
            with open(detected_file, "w") as f:
                writer = csv.writer(f)
                writer.writerow(["file_path"])
                writer.writerow([data])
                new_search = 1
    except Exception as e:
        logger.error(f"Content File Write error: {e}")
        return False
    return True


def find_files(extensions=[], search_path=""):
    """
    Run Search  for given  directory usings extensions
    and process return file path where this extensions present.

    params: extensions - list - extensions
    params: search_path - String - file/Directory path string
    returns: Boolean
    """
    if os.path.isfile(search_path):
        write_data([search_path])
        return True

    if extensions:
        if isinstance(extensions, list):
            configs.extensions = extensions
        else:
            logger.error(f"Please pass extensions in List like '['py',]'")
            sys.exit()
    else:
        # Get the extensions from extensions file
        configs.read_extensions(file_name="extensions.csv")
    logger.info(f"Total Extensions: {len(configs.extensions)}")

    try:
        BASE_DIR = Path(search_path)
        for path in BASE_DIR.glob(r"**/*"):
            if path.suffix[1:] in configs.extensions:
                if os.path.isfile(path):
                    write_data(path)
    except:
        logger.debug(f"File search exception")


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
    returns: extensions - list
    returns: search_path - string
    returns: log_level - int - Default - 20  - INFO
    returns: console_logging - Boolean - Default - True
    """

    argparser = argparse.ArgumentParser()
    flag_choices = ["Y", "y", "Yes", "YES", "yes", "N", "n", "No", "NO", "no"]
    log_level_choices = [10, 20, 30, 40, 50]

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
        "-p",
        "--search_path",
        metavar="Search path",
        action="store",
        type=str,
        default="",
        help="Pass the Search Path for scanner",
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

    if args.extensions:
        extensions = args.extensions.split(",")
    else:
        extensions = []

    if args.search_path:
        search_path = args.search_path
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
        extensions,
        search_path,
        log_level,
        console_logging,
    )


if __name__ == "__main__":
    # Argument Parsing
    (
        extensions,
        search_path,
        log_level,
        console_logging,
    ) = arg_parser()

    # Setting up Logger
    setup_logger(log_level, console_logging)

    logger.info("xGitGuard File Extension Process Started")
    # Read and Setup Global Configuration Data to reference in all process
    configs = ConfigsData()

    if search_path:
        find_files(extensions, search_path)
    else:
        configs.read_search_paths(file_name="xgg_search_paths.csv")
        search_paths = configs.search_paths
        if search_paths:
            for search_path in search_paths:
                find_files(extensions, search_path)
        else:
            logger.info(f"No Search paths to process from config file. Ending.")
            sys.exit(1)

    logger.info("xGitGuard File Extension Process Completed")
