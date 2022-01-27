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
import re


def is_num_present(word):
    """
    Check if any number present in Given String
    params:  word - string
    returns:  0 or 1
    """
    check = any(letter.isdigit() for letter in word)
    return 1 if check else 0


def is_uppercase_present(word):
    """
    Check if any Upper Case Letter present in Given String
    params: word - string
    returns: 0 or 1
    """
    check = any(letter.isupper() for letter in word)
    return 1 if check else 0


def is_special_chars_present(word):
    """
    Check if any special characterss present in Given String
    params: word - string
    returns: 0 or 1
    """
    regex = re.compile("[@_!#$%^&*()<>?/\|}{~:]")
    check = regex.search(word)
    return 1 if check else 0


def mask_data(code, secret):
    """
    Mask the letters except first 4 chars
    params:  code - string - full key line
    params:  secret - string - Secret
    returns:  masked_code - string
    """
    try:
        match_group = re.search("(?<=:|=).*$", code)
        if match_group:
            match = match_group.group(0).strip()
            masked_code = re.sub(r"(?<=:|=).*$", "", code)
            if match[len(match) - 1] == '"':
                masked_code = masked_code + match[0:4] + "#" * (10) + '"'
            else:
                masked_code = masked_code + match[0:4] + "#" * (10)
        else:
            masked_code = re.sub(secret, "##########", code)
    except Exception as e:
        masked_code = re.sub(secret, "##########", code)
    return masked_code
