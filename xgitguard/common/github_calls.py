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
import time

import requests

logger = logging.getLogger("xgg_logger")


def run_github_search(api_url, search_query, extension, token_env):
    """
    Run the GitHub API search with given search query
    Get the items from the response content and Return
    params: api_url - string - GitHub Search API url
    params: search_query - string - Search keyword
    params: extension - string - Search extension
    returns: search_response - list
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")

    if not extension and extension == "others":
        response = github_api_get_params(api_url, search_query, token_env)
    elif token_env == "public":
        response = github_api_get_params(
            api_url, (search_query + " extension:" + extension), token_env
        )
    else:
        response = github_api_get_params(
            api_url, (search_query + "+extension:" + extension), token_env
        )
    if response:
        if response.status_code == 200:
            content = response.json()
            search_response = content["items"]
            return search_response
        else:
            time.sleep(2)
            logger.error(f"Search Response code: {response.status_code}. Continuing...")
    else:
        logger.error(
            f"Search '{search_query}' api call failed as {response}. Continuing..."
        )
    return []


def github_api_get_params(api_url, search_query, token_env):
    """
    For the given GITHUB API url and search query, call the api
    Get and return the response
    ### Need GitHub Auth Token as Env variable named "GITHUB_TOKEN"

    params: api_url - string
    params: search_query - string
    returns: response - dict
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")
    if token_env == "public":
        token_var = "GITHUB_TOKEN"
        time.sleep(3)
    else:
        time.sleep(2)
        token_var = "GITHUB_ENTERPRISE_TOKEN"
        if "<< Enterprise Name >>" in api_url:
            logger.error(
                f"GitHub API URL not set for Enterprise in xgg_configs.yaml file in config folder. API Search will fail/return no results. Please Setup and retry"
            )
            sys.exit(1)

    if not os.getenv(token_var):
        logger.error(
            f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)

    try:

        response = requests.get(
            api_url,
            params={
                "q": search_query,
                "order": "desc",
                "sort": "indexed",
                "per_page": 100,
            },
            auth=("token", os.getenv(token_var)),
        )

        return response

    except Exception as e:
        logger.error(f"Github API call Error: {e}")

    return {}


def public_url_content_get(api_url):
    """
    For the given GitHub url, call the api
    Get and return the response
    ### Need GitHub Auth Token as Env variable named "GITHUB_TOKEN"

    params: api_url - string
    returns: response - string
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")

    token_var = "GITHUB_TOKEN"
    if not os.getenv(token_var):
        logger.error(
            f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)

    try:
        time.sleep(3)
        response = requests.get(
            api_url, auth=("token", os.getenv(token_var)), timeout=10
        )
        return response
    except Exception as e:
        logger.error(f"Github API file content get Error: {e}")

    return {}


def enterprise_url_content_get(api_url, header):
    """
    For the given GitHub url, call the api
    Get and return the response
    ### Need GitHub Auth Token as Env variable named "GITHUB_ENTERPRISE_TOKEN"

    params: api_url - string
    returns: response - string
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")

    token_var = "GITHUB_ENTERPRISE_TOKEN"
    if not os.getenv(token_var):
        logger.error(
            f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)
    elif "<< Enterprise Name >>" in api_url:
        logger.error(
            f"GitHub API Content URL not set for Enterprise in xgg_configs.yaml file in config folder. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)

    try:
        time.sleep(2)
        response = requests.get(
            api_url,
            auth=("token", os.getenv(token_var)),
            headers=header,
            timeout=10,
        )
        return response
    except Exception as e:
        logger.error(f"Github API file content get Error: {e}")

    return {}


def get_github_public_commits(commits_api_url):
    """
    For the given GitHub details, call the api and get commit details
    Get and return the response
    ### Need GitHub Auth Token as Env variable named "GITHUB_TOKEN"
    params: commits_api_url - string
    returns: response - string
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")

    token_var = "GITHUB_TOKEN"
    if not os.getenv(token_var):
        logger.error(
            f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)

    try:
        time.sleep(3)
        response = requests.get(
            commits_api_url, auth=("token", os.getenv(token_var)), timeout=25
        )
        return response
    except Exception as e:
        logger.error(f"Github API commit content get Error: {e}")
    return {}


def get_github_enterprise_commits(commits_api_url, header):
    """
    For the given GitHub details, call the api and get commit details
    Get and return the response
    ### Need GitHub Enterprise Auth Token as Env variable named "GITHUB_ENTERPRISE_TOKEN"
    params: commits_api_url - string
    params: header - dict
    returns: response - string
    """
    logger.debug("<<<< 'Current Executing Function' >>>>")

    token_var = "GITHUB_ENTERPRISE_TOKEN"
    if not os.getenv(token_var):
        logger.error(
            f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)
    elif "<< Enterprise Name >>" in commits_api_url:
        logger.error(
            f"GitHub API Commits URL not set for Enterprise in xgg_configs.yaml file in config folder. API Search will fail/return no results. Please Setup and retry"
        )
        sys.exit(1)

    try:
        time.sleep(3)
        response = requests.get(
            commits_api_url,
            auth=("token", os.getenv(token_var)),
            headers=header,
            timeout=25,
        )
        return response
    except Exception as e:
        logger.error(f"Github API commit content get Error: {e}")
    return {}
