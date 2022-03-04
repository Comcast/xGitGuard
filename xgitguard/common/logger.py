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
from datetime import datetime


def create_logger(log_level=20, console_logging=True, log_dir=None, log_file_name=None):
    """
    Create logging class and return
    params: log_level - int - Default - 10
    returns: console_logging - Boolean - Default - True
    returns: log_dir - string - optional
    returns: log_file_name - string - optional
    returns: logger - logging class
    """
    logger_name = "xgg_logger"
    # Gets or creates a logger
    logger = logging.getLogger(logger_name)

    # set log level
    logger.setLevel(log_level)

    formatter = logging.Formatter(
        "[%(asctime)s] [ %(levelname)8s ] [%(filename)40s:%(funcName)30s] : %(message)s"
    )

    # add file handler to logger
    logger.addHandler(set_file_handler(logger_name, formatter, log_dir, log_file_name))

    if console_logging:
        logger.addHandler(set_console_handler(formatter))

    return logger


def set_file_handler(logger_name, formatter, log_dir, log_file_name):
    """Setting File streaming Handler"""
    # define file handler and set formatter
    if log_dir and os.path.exists(log_dir):
        log_dir = log_dir
    else:
        module_dir = os.path.dirname(os.path.realpath(__file__))
        log_dir = os.path.abspath(
            os.path.join(os.path.dirname(module_dir), ".", "logs")
        )
    if not log_file_name:
        log_file_name = f"{logger_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_file = os.path.join(log_dir, log_file_name)
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    print(f"Current run logs file: {log_file}")
    return file_handler


def set_console_handler(formatter):
    """Setting Console logging Handler"""
    # define console handler and set formatter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    return console_handler


if __name__ == "__main__":
    from configs_read import ConfigsData

    configs = ConfigsData()
    module_dir = os.path.dirname(os.path.realpath(__file__))
    log_dir = os.path.abspath(os.path.join(os.path.dirname(module_dir), ".", "logs"))

    logger = create_logger(
        log_level=10,
        console_logging=False,
        log_dir=log_dir,
        log_file_name=f"{os.path.basename(__file__).split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    )

    logger.debug("A debug message")
    logger.info("An info message")
    logger.warning("Something is not right.")
    logger.error("A Major error has happened.")
    logger.critical("Fatal error. Cannot continue")
