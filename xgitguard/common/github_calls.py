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
from utilities.query_length_validator import query_length_validator

logger = logging.getLogger("xgg_logger")


class GithubCalls:

    def __init__(self, base_url, token_env, commits_api_url, throttle_time=2):
        assert (
            token_env == "public" or token_env == "enterprise"
        ), f"token_env must be either 'public' or 'enterprise'. current: {token_env}"
        self._base_url = base_url
        self._token_env = token_env
        self._commits_api_url = commits_api_url
        self._throttle_time = throttle_time

    def run_github_search(self, search_query, extension, org=[], repo=[]):
        """
        Run the GitHub API search with given search query
        Get the items from the response content and Return
        params: search_query - string - Search keyword
        params: extension - string - Search extension
        params: org - list
        params: repo - list
        returns: search_response - list
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")

        org_qualifiers = []
        repo_qualifiers = []

        if len(org) > 0:
            # Checks if the length of additional qualifiers has exceeded the character limit of 170.
            org_qualifiers = query_length_validator(org, "user")
            if org_qualifiers == -1:
                logger.error(
                    "Character Limit reached. Please consider limiting the number of characters in orgs."
                )
                sys.exit(1)

        elif len(repo) > 0:
            # Checks if the length of additional qualifiers has exceeded the character limit of 170.
            repo_qualifiers = query_length_validator(repo, "repo")
            if repo_qualifiers == -1:
                logger.error(
                    "Character Limit reached. Please consider limiting the number of characters in repo."
                )
                sys.exit(1)

        if not extension and extension == "others":
            response = self.__github_api_get_params(
                search_query, org_qualifiers, repo_qualifiers
            )
        elif self._token_env == "public":

            response = self.__github_api_get_params(
                (search_query + " extension:" + extension),
                org_qualifiers,
                repo_qualifiers,
            )
        else:
            response = self.__github_api_get_params(
                (search_query + " extension:" + extension),
                org_qualifiers,
                repo_qualifiers,
            )

        if response:
            return response

        return []

    def __github_api_get_params(
        self, search_query, org_qualifiers="", repo_qualifiers=""
    ):
        """
        For the given GITHUB API url and search query, call the api
        Get and return the response
        ### Need GitHub Auth Token as Env variable named "GITHUB_TOKEN"

        params: search_query - string
        params: org_qualifiers - string
        params: repo_qualifiers - string
        returns: response - dict
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        if self._token_env == "public":
            token_var = "GITHUB_TOKEN"
            time.sleep(self._throttle_time)
        else:
            time.sleep(self._throttle_time)
            token_var = "GITHUB_ENTERPRISE_TOKEN"
            if "<< Enterprise Name >>" in self._base_url:
                logger.error(
                    f"GitHub API URL not set for Enterprise in xgg_configs.yaml file in config folder. API Search will fail/return no results. Please Setup and retry"
                )
                sys.exit(1)

        if not os.getenv(token_var):
            logger.error(
                f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
            )
            sys.exit(1)

        additional_qualifiers = ""
        if len(org_qualifiers) > 0:
            additional_qualifiers = org_qualifiers
        elif len(repo_qualifiers) > 0:
            additional_qualifiers = repo_qualifiers

        search_response = []
        if additional_qualifiers:
            try:
                response = requests.get(
                    self._base_url,
                    params={
                        "q": f"{search_query} {additional_qualifiers}",
                        "order": "desc",
                        "sort": "indexed",
                        "per_page": 100,
                    },
                    auth=("token", os.getenv(token_var)),
                )
            except Exception as e:
                logger.error(f"Github API call Error: {e}")
        else:
            try:
                response = requests.get(
                    self._base_url,
                    params={
                        "q": f"{search_query}",
                        "order": "desc",
                        "sort": "indexed",
                        "per_page": 100,
                    },
                    auth=("token", os.getenv(token_var)),
                )
            except Exception as e:
                logger.error(f"Github API call Error: {e}")

        if response.status_code == 200:
            content = response.json()
            search_response.extend(content["items"])
            try:
                while "next" in response.links.keys():
                    time.sleep(6)
                    response = requests.get(
                        response.links["next"]["url"],
                        auth=("token", os.getenv(token_var)),
                    )

                    if response.status_code == 200:
                        content = response.json()
                        if len(content["items"]) < 1:
                            break
                        search_response.extend(content["items"])

                    else:
                        logger.info(
                            f"Encountered an error in processing request.Response Status Code:{response.status_code}"
                        )
                        break
            except Exception as e:
                logger.error(
                    f"Error occured while iterating through file contents: {e}"
                )
        else:
            logger.info(
                f"Encountered an error in processing request.Response Status Code:{response.status_code}"
            )
        return search_response

    def public_url_content_get(self, file_url):
        """
        For the given GitHub url, call the api
        Get and return the response
        ### Need GitHub Auth Token as Env variable named "GITHUB_TOKEN"

        params: api_url - string
        returns: response - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")

        token_key = "GITHUB_TOKEN"
        if not os.getenv(token_key):
            logger.error(
                f"GitHub API Token Environment variable '{token_key}' not set. API Search will fail/return no results. Please Setup and retry"
            )
            sys.exit(1)

        try:
            time.sleep(self._throttle_time)
            response = requests.get(
                file_url, auth=("token", os.getenv(token_key)), timeout=10
            )
            return response
        except Exception as e:
            logger.error(f"Github API file content get Error: {e}")

        return {}

    def enterprise_url_content_get(self, file_url, header):
        """
        For the given GitHub url, call the api
        Get and return the response
        ### Need GitHub Auth Token as Env variable named "GITHUB_ENTERPRISE_TOKEN"

        params: api_url - string
        returns: response - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")

        token_key = "GITHUB_ENTERPRISE_TOKEN"
        if not os.getenv(token_key):
            logger.error(
                f"GitHub API Token Environment variable '{token_key}' not set. API Search will fail/return no results. Please Setup and retry"
            )
            sys.exit(1)
        elif "<< Enterprise Name >>" in self._base_url:
            logger.error(
                f"GitHub API Content URL not set for Enterprise in xgg_configs.yaml file in config folder. API Search will fail/return no results. Please Setup and retry"
            )
            sys.exit(1)

        try:
            time.sleep(self._throttle_time)
            response = requests.get(
                file_url,
                auth=("token", os.getenv(token_key)),
                headers=header,
                timeout=10,
            )
            return response
        except Exception as e:
            logger.error(f"Github API file content get Error: {e}")

        return {}

    def get_github_public_commits(self, user_name, repo_name, file_path):
        """
        For the given GitHub details, call the api and get commit details
        Get and return the response
        ### Need GitHub Auth Token as Env variable named "GITHUB_TOKEN"
        params: commits_api_url - string
        returns: response - string
        """
        logger.debug("<<<< 'Current Executing Function' >>>>")
        full_commit_url = self._commits_api_url % (user_name, repo_name, file_path)
        token_var = "GITHUB_TOKEN"
        if not os.getenv(token_var):
            logger.error(
                f"GitHub API Token Environment variable '{token_var}' not set. API Search will fail/return no results. Please Setup and retry"
            )
            sys.exit(1)

        try:
            time.sleep(self._throttle_time)
            response = requests.get(
                full_commit_url, auth=("token", os.getenv(token_var)), timeout=25
            )
            return response
        except Exception as e:
            logger.error(f"Github API commit content get Error: {e}")
        return {}

    def get_github_enterprise_commits(self, user_name, repo_name, file_path, header):
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
        elif "<< Enterprise Name >>" in self._commits_api_url:
            logger.error(
                f"GitHub API Commits URL not set for Enterprise in xgg_configs.yaml file in config folder. API Search will fail/return no results. Please Setup and retry"
            )
            sys.exit(1)

        try:
            time.sleep(self._throttle_time)
            full_commit_url = self._commits_api_url.format(
                user_name=user_name, repo_name=repo_name, file_path=file_path
            )
            response = requests.get(
                full_commit_url,
                auth=("token", os.getenv(token_var)),
                headers=header,
                timeout=25,
            )
            return response
        except Exception as e:
            logger.error(f"Github API commit content get Error: {e}")
        return {}
