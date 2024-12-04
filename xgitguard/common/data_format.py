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

import functools
import json
import re
from urlextract import URLExtract



specialCharacterRegex = re.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

def remove_url_from_keys(code_content):
    """
    Replace special chars in the given code content data
    params: code_content - string - code data with urls
    returns: data - string - Code data without url
    """
    # Remove url address if present
    code_data = re.sub(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        " ",
        code_content,
    )
    # Remove email address characters if present
    code_data = re.sub("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", " ", code_data)

    special_chars = [
        "'",
        "(",
        ")",
        ",",
        ".",
        "/",
        "0x",
        ";",
        "<",
        "=",
        ">",
        "@",
        "[",
        "\\",
        "]",
        "_",
        "{",
        "}",
        '"',
    ]
    # Remove special characters if present
    for special_char in special_chars:
        code_data = code_data.replace(special_char, " ")
    return code_data


def remove_url_from_creds(code_content, key):
    """
    Replace special chars in the given code content data
    params: code_content - string - code data with urls
    returns: data - string - Code data without url
    """
    extractor = URLExtract()
    blacklisted_urls = extractor.find_urls(code_content)

    code_data = re.sub(
        r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
        " ",
        code_content,
    )
    code_data = re.sub("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", " ", code_data)

    for url in blacklisted_urls:
        code_data = code_data.replace(url, " ")

    special_chars = [
        "'",
        '"',
        "#",
        "%",
        "&",
        "(",
        ")",
        "*",
        "+",
        ",",
        "-",
        ".",
        "/",
        ":",
        ";",
        "<",
        "=",
        ">",
        "?",
        "[",
        "\\",
        "]",
        "`",
        "{",
        "|",
        "}",
        "~",
    ]
    # Remove special characters if present
    for special_char in special_chars:
        code_data = code_data.replace(special_char, " ")
    codes_list = code_data.split()
    return codes_list

def clean_credentials(code_content):
    """
    Replace special chars in the given code content data
    params: code_content - string - code data
    returns: data - string - Cleaned up code data
    """
    code_data = specialCharacterRegex.sub(" ", code_content)

    special_chars = [
        "'",
        '"',
        "#",
        "%",
        "&",
        "(",
        ")",
        "*",
        "+",
        ",",
        "-",
        ".",
        "/",
        ":",
        ";",
        "<",
        "=",
        ">",
        "?",
        "[",
        "\\",
        "]",
        "`",
        "{",
        "|",
        "}",
        "~",
    ]
    # Remove special characters if present
    for special_char in special_chars:
        code_data = code_data.replace(special_char, " ")
    codes_list = code_data.split()
    return codes_list

def keys_extractor(code_content):
    """
    Extract keys from the given code content
    params: code_content - string
    returns: keys - List - List of secret keys
    """

    regexes = {
        "AWS Tokens": "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "AWS Access Key ID": "[0-9a-zA-Z/+=]{40}",
        "Google OAuth Secret": "[0-9a-zA-Zn\-_]{24}",
        "Google OAuth Auth Code": "4/[0-9A-Za-zn\-_]+",
        "Google OAuth Refresh Token": "1/[0-9A-Za-zn\-_]{43}|1/[0-9A-Za-zn\-_]{64}",
        "Google OAuth Access Token": "ya29n.[0-9A-Za-zn\-_]+",
        "Google API Key": "AIza[0-9A-Za-zn\-_]{35}",
        "RSA Private Key": "BEGIN RSA PRIVATE KEY",
        "EC Private Key": "BEGIN EC PRIVATE KEY",
        "PGP Private Key": "BEGIN PGP PRIVATE KEY BLOCK",
        "General Private Key": "BEGIN PRIVATE KEY",
        "Google YouTube OAuth ID Gmail, GCloud": "[0-9]+-[0-9A-Za-z_]f32gn.appsn.googleusercontentn.com",
        "Amazon MWS": "access_tokenn$productionn$[0-9a-z]f16gn$[0-9a-f]f32g",
        "PayPal": "amznn.mwsn.[0-9a-f]f8g-[0-9a-f]f4g-[0-9a-f]f4g-[0-9a-f]f4g-[0-9a-f]f12g",
        "Slack Token": "(xox[pbaor]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
        "AWS": "(?:.*awsSecretKey|.*aws_secret|.*api-key|.*aws_account_secret).*"
        "(?=.*[A-Z])(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "Slack Webook": "T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    }

    keys = []

    for regex_value in regexes.values():
        find_keys = re.findall(regex_value, code_content)
        if find_keys:
            keys.append(find_keys)
    if keys:
        keys = list(functools.reduce(set.union, [set(item) for item in keys]))
        keys = list(set(keys))
        keys = list(filter(None, keys))

    return keys


def credential_extractor(code_content, stop_words):
    """
    Extract Credentials from the given code content
    params: code_content - string
    returns: keys - List - List of secret keys
    """
    creds = []
    for word in code_content:
        if (
            len(word) >= 7
            and not (word in stop_words)
            and not (word.lower().startswith("u0"))
            and not (word.lower().startswith("0x"))
            and not (word.lower().startswith("rfc"))
            and not ("http" in word.lower())
            and (bool(re.match("^(?=.*[0-9])(?=.*[a-zA-Z])", word)))
        ):
            creds.append(word)

    """creds = [word for word in code_content if len(word) >= 7]
    creds = [word for word in creds if not word in stop_words]
    creds = [word for word in creds if not word.lower().startswith('u0')]
    creds = [word for word in creds if not word.lower().startswith('0x')]
    creds = [word for word in creds if not word.lower().startswith('rfc')]
    creds = [word for word in creds if "http" not in word.lower()]
    creds = [word for word in creds if bool(re.match('^(?=.*[0-9])(?=.*[a-zA-Z])', word))]"""

    creds = list(set(creds))
    creds = list(filter(None, creds))
    return creds


def format_commit_details(api_response_commit_data):
    """
    Format the commit details from the api response
    params: api_response_commit_data - dict
    returns: commit_details - json dictionary
    """
    try:
        response = api_response_commit_data
        if response.status_code == 200:
            commit_details = {}
            commit_data = []
            commits_response = response.json()
            commit_details["status"] = response.status_code

            for commit in commits_response:
                commit_detail = {}

                try:
                    commit_detail["commit_id"] = commit["sha"]
                except (IndexError, KeyError):
                    commit_detail["commit_id"] = ""

                try:
                    commit_detail["email"] = commit["commit"]["author"]["email"]
                except (IndexError, KeyError):
                    commit_detail["email"] = ""

                try:
                    commit_detail["commiter_name"] = commit["commit"]["author"]["name"]
                except (IndexError, KeyError):
                    commit_detail["commiter_name"] = ""

                try:
                    commit_detail["commit_date"] = commit["commit"]["author"]["date"]
                except (IndexError, KeyError):
                    commit_detail["commit_date"] = ""

                try:
                    if commit["author"] is not None:
                        commit_detail["user_id"] = commit["author"]["login"]
                    else:
                        commit_detail["user_id"] = ""
                except (IndexError, KeyError):
                    commit_detail["user_id"] = ""

                commit_data.append(commit_detail)
            commit_details["commits"] = commit_data
        else:
            commit_details = {}

    except (IndexError, KeyError):
        commit_details = {}

    commit_details = json.dumps(commit_details)
    return commit_details
