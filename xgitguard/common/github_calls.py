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
class GithubCalls:

    def __init__(
        self,
        base_url,
        token_env,
        commits_api_url,
        throttle_time=2
    ):
        assert token_env == "public" or token_env == "enterprise", f"token_env must be either 'public' or 'enterprise'. current: {token_env}"
        self._base_url = base_url
        self._token_env = token_env
        self._commits_api_url = commits_api_url
        self._throttle_time = throttle_time

    def run_github_search(self, search_query, extension):
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
            response = self.__github_api_get_params(search_query)
        elif self._token_env == "public":

            response = self.__github_api_get_params(
                (search_query + " extension:" + extension)
            )
        else:
            response = self.__github_api_get_params(
                (search_query + "+extension:" + extension)
            )
        if response:
            if response.status_code == 200:
                content = response.json()
                search_response = content["items"]
                return search_response
            else:
                time.sleep(self._throttle_time)
                logger.error(f"Search Response code: {response.status_code}. Continuing...")
        else:
            logger.error(
                f"Search '{search_query}' api call failed as {response}. Continuing..."
            )
        return []


    def __github_api_get_params(self, search_query):
        """
        For the given GITHUB API url and search query, call the api
        Get and return the response
        ### Need GitHub Auth Token as Env variable named "GITHUB_TOKEN"

        params: api_url - string
        params: search_query - string
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

        try:

            response = requests.get(
                self._base_url,
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
        full_commit_url = self._commits_api_url.format(
            user_name=user_name, repo_name=repo_name, file_path=file_path
        )
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
