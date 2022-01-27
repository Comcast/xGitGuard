<h1 align="center"> xGitGuard </h1>

<p align="center">AI-based Secrets Detection Python Framework<br> 
<i><b>Detect Secrets (API tokens, Username, Passwords, etc.) exposed on GitHub Repos</b></i><br>
Designed and Developed by Comcast Cybersecurity Research and Development Team</p>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

---

## Contents

- [Overview](#overview)
- [xGitGuard Workflow](#xgitguard-workflow)
- [Features](#features)
  - [Credential-Detection-Workflow](#credential-detection-workflow)
  - [Keys/Token-Detection-Workflow](#keystoken-detection-workflow)
- [Install](#install)
- [Search Patterns](#search-patterns)
- [Usage](#usage)
  - [Enterprise Github Secrets Detection](#enterprise-github-secrets-detection)
  - [Public Github Secrets Detection](#public-github-secrets-detection)
- [License](#license)

## Overview

- **Detecting Publicly Exposed Secrets on GitHub at Scale**
  - xGitGuard is an AI-based system designed and developed by Comcast Cybersecurity Research and Development team that detects secrets (e.g., API tokens, username & passwords, etc.) exposed on the GitHub. xGitGuard uses advanced Natural Language Processing to detect secrets at scale and with appropriate velocity in GitHub repositories.
- What are Secrets?
  - **Credentials**
    - Username & passwords, Server credentials, Account credentials, etc.
  - **Keys/Tokens**
    - Service API tokens (AWS, Azure, etc), Encryption keys, etc.

## xGitGuard Workflow

![](assets/xgitguard_workflow.png)

## Features

### Credential Detection Workflow

- [Enterprise Credential Secrets Detection](#enterprise-credential-secrets-detection) - Run Secret detection on the given `GitHub Enterprise` Account
- [Public Credential Secrets Detection](#public-credential-secrets-detection) - Run Secret detection on the `GitHub Public` Account

  ![](assets/keys_Token_Detection_workflow.png)

### Keys&Token Detection Workflow

- [Enterprise Keys and Tokens Secrets Detection](#enterprise-keys-and-tokens-secrets-detection) - Run Secret detection on the given `GitHub Enterprise` Account
- [Public Keys and Tokens Secrets Detection](#public-keys-and-tokens-secrets-detection) - Run Secret detection on the `GitHub Public` Account

  ![](assets/keys_Token_Detection_workflow.png)

## Install

### Environment Setup

- Install [Python >= v3.6]
- Clone/Download the Repository from GitHub
- Traverse into the cloned `xGitGuard` folder

  ```
  cd xGitGuard
  ```

- Install Python Dependency Packages

  ```
  pip install -r requirements.txt
  ```

## Search Patterns

- xgitguard supports two ways to define configurations

  - Config Files
  - Command Line Inputs

- For **`Enterprise`** Github Detection **`(Secondary Keyword + Extension)`** under config directory
  - Secondary Keyword: Keys: secondary_keys.csv file or User Feed - list of Keys
  - Secondary Keyword: Credentials: secondary_creds.csv file or User Feed - list of Credentials
  - Extension: extensions.csv file or User Feed - List of file Extensions
- For **`Public`** Github Detection **`(Primary Keyword + Secondary Keyword + Extension)`** under config directory

  - Primary Keyword: primary_keywords.csv file or User Feed - list of Keys
  - Secondary Keyword: Keys: secondary_keys.csv file or User Feed - list of Keys
  - Secondary Keyword: Credentials: secondary_creds.csv file or User Feed - list of Credentials
  - Extension: extensions.csv file or User Feed - List of file Extensions

## Usage

- [Enterprise Github Secrets Detection](#enterprise-github-secrets-detection)
  - [Enterprise Credential Secrets Detection](#enterprise-credential-secrets-detection)
  - [Enterprise Keys and Tokens Secrets Detection](#enterprise-keys-and-tokens-secrets-detection)
  - [Enterprise Inputs and Outputs](#enterprise-inputs-and-outputs)
- [Public Github Secrets Detection](#public-github-secrets-detection)
  - [Public Credential Secrets Detection](#public-credential-secrets-detection)
  - [Public Keys and Tokens Secrets Detection](#public-keys-and-tokens-secrets-detection)
  - [Public Inputs and Outputs](#public-inputs-and-outputs)

### Enterprise Github Secrets Detection

#### Configuration Data Setup

- Setup below system Environment variables for accessing GitHub
  - **`GITHUB_ENTERPRISE_TOKEN`** - Enterprise GitHub API Token with full Scopes of repo and user.
    - Refer GitHub Docs [How To Get GitHub API Token] for help
- Update below configs with `your Enterprise Name` in Config file **`xgg_configs.yaml`** in config Data folder **`xgitguard\config\*`**
  - enterprise_api_url: `https://github.<<`**`Enterprise_Name`**`>>.com/api/v3/search/code`
  - enterprise_pre_url: `https://github.<<`**`Enterprise_Name`**`>>.com/api/v3/repos/`
  - url_validator: `https://github.<<`**`Enterprise_Name`**`>>.com/api/v3/search/code`
  - entprise_commits_url: `https://github.<<`**`Enterprise_Name`**`>>.com/api/v3/repos/{user_name}/{repo_name}/commits?path={file_path}`

#### ML Model Process

##### ML Model Training Data Preparion

- Create Training data in csv format for Credential and Keys&Tokens and place in **`xgitguard\config\*`** folder
- Data Preparation procedure
- key_train.csv - Keys and Tokens Training Data
- cred_train.csv - Credentials Training Data
- confidence_values.csv
  - All Primary, Seconday keywords and Extensions need to be added to this file in format of key and value pair.
  - Value for the keys needs to be decided by you and it represents the weight and importance of the keyword, the higher the value means higher validity score for the detection(confidence level).
  - e.g., key,value in a csv file.
    - abc.xyz.com,3
    - token,4
    - py,2

##### ML Model Training - Optional

- Pre-requisite: [ML Model Training Data Preparion](#ml-model-training-data-preparion)

- Training Procedure

  > **Note:** If persisted Model **xgg\_\*model\*.pickle** is not present in config folder, as part of the detections Run, ML model will be trained and persisted even if the train model flag set as 'No'.

- Traverse into the "models" folder

  ```
  cd models
  ```

- Run training with Cred Training Data and persist model

  ```
  python model.py cred
  ```

- Run training with Key Training Data and persist model

  ```
  python model.py key
  ```

- Command Line Arguments

  ```
  usage: model.py [-h] [-t Train Model] [-l Logger Level] [-c Console Logging] Data_Type

  positional arguments:
  Data_Type             Pass the Data_Type as cred or key

  optional arguments:
  -h, --help            show this help message and exit
  -t Train Model, --train_model Train Model
                          Pass the Train Model as Yes or No. Default is Yes
  -l Logger Level, --log_level Logger Level
                          Pass the Logging level as for CRITICAL - 50, ERROR - 40 WARNING - 30 INFO - 20 DEBUG - 10. Default is 20
  -c Console Logging, --console_logging Console Logging
                          Pass the Console Logging as Yes or No. Default is Yes
  ```

#### Running Enterprise Secret Detection

##### Pre-Setup

- Traverse into the `github-enterprise` script folder

  ```
  cd github-enterprise
  ```

##### Enterprise Credential Secrets Detection

- Running the Credential Secrets Detection script
  ```
  # Run with Default configs
  python enterprise_cred_detections.py
  ```
- Command Line Arguments

  ```
  Run usage:
  enterprise_cred_detections.py [-h] [-s Secondary Keywords] [-e Extensions] [-t Train Model] [-l Logger Level] [-c Console Logging]

  optional arguments:
    -h, --help            show this help message and exit
    -s Secondary Keywords, --secondary_keywords Secondary Keywords
                            Pass the Secondary Keywords list as comma separated string
    -e Extensions, --extensions Extensions
                            Pass the Extensions list as comma separated string
    -t Train Model, --train_model Train Model
                            Pass the Train Model as Yes or No. Default is No
    -l Logger Level, --log_level Logger Level
                            Pass the Logging level as for CRITICAL - 50, ERROR - 40 WARNING - 30 INFO - 20 DEBUG - 10. Default is 20
    -c Console Logging, --console_logging Console Logging
                            Pass the Console Logging as Yes or No. Default is Yes
  ```

- Run Variation Examples

  ```
  # Run for given Secondary Keyword and extension with training with Debug Console logging
  python enterprise_cred_detections.py -s "password" -e "py" -t Yes -l 10 -c Yes
  ```

  ```
  # Run for given Secondary Keyword and extension without training
  python enterprise_cred_detections.py -s "password" -e "py"
  ```

  ```
  # Run with Secondary Keywords from config file and given list of extensions
  python enterprise_cred_detections.py -e "py,txt"
  ```

  ```
  # Run with Secondary Keywords and extensions from config files
  python enterprise_cred_detections.py
  ```

- Inputs used for Search and Scan

  > **Note:** Command line argument keywords has precedence than config files (Default). If No keywords passed in cli, config files data will be used for search.

  - secondary_creds.csv file will have default list of credential relavent patterns for search
  - extensions.csv file has default list of file extension to be searched

- GitHub Search Pattern for above Examples: **`password +extension:py`**

##### Enterprise Keys and Tokens Secrets Detection

- Running the Keys and Tokens Secrets Detection script

  ```
  # Run with Default configs
  python enterprise_key_detections.py
  ```

- Command Line Arguments

  ```
  Run usage:
  enterprise_key_detections.py [-h] [-s Secondary Keywords] [-e Extensions] [-t Train Model] [-l Logger Level] [-c Console Logging]

  optional arguments:
    -h, --help            show this help message and exit
    -s Secondary Keywords, --secondary_keywords Secondary Keywords
                            Pass the Secondary Keywords list as comma separated string
    -e Extensions, --extensions Extensions
                            Pass the Extensions list as comma separated string
    -t Train Model, --train_model Train Model
                            Pass the Train Model as Yes or No. Default is No
    -l Logger Level, --log_level Logger Level
                            Pass the Logging level as for CRITICAL - 50, ERROR - 40 WARNING - 30 INFO - 20 DEBUG - 10. Default is 20
    -c Console Logging, --console_logging Console Logging
                            Pass the Console Logging as Yes or No. Default is Yes
  ```

- Run Variation Examples

  ```
  # Run for given Secondary Keyword and extension with training with Debug Console logging
  python enterprise_key_detections.py -s "token" -e "py" -t Yes -l 10 -c Yes
  ```

  ```
  # Run for given Secondary Keyword and extension without training
  python enterprise_key_detections.py -s "token" -e "py"
  ```

  ```
  # Run with Secondary Keywords from config file and given list of extensions
  python enterprise_key_detections.py -e "py,txt"
  ```

  ```
  # Run with Secondary Keywords and extensions from config files
  python enterprise_key_detections.py
  ```

#### Enterprise Inputs and Outputs

> **Note:**
> Command line argument keywords has precedence than config files (Default).
> If No keywords passed in cli, config files data will be used for search.

- GitHub Search Pattern for above Examples: **`token +extension:py`**

##### Input Files

```
1. secondary_keys.csv file will have default list of keys & tokens relavent patterns for search
2. extensions.csv file has default list of file extension to be searched
```

##### Output Files

- **Credentials**

  ```
    1. Hashed Url Files: xgitguard\config\enterprise_hashed_url_creds.csv
        - List pf previously Processed Search urls. Urls stored will be skipped in next run to avoid re processing.
    2. Secrets Detectec: xgitguard\config\xgg_enterprise_creds_detected.csv
    3. Log File: xgitguard\config\enterprise_key_detections_*current run time yyyymmdd_hhmmss*.log
  ```

- **Keys & Tokens**

  ```
    1. Hashed Url Files: xgitguard\config\enterprise_hashed_url_keys.csv
        - List pf previously Processed Search urls. Urls stored will be skipped in next run to avoid re processing.
    2. Secrets Detectec: xgitguard\config\xgg_enterprise_keys_detected.csv
    3. Log File: xgitguard\config\enterprise_key_detections_*yyyymmdd_hhmmss*.log
  ```

### Public Github Secrets Detection

#### Configuration Data Setup

- Setup below Environment variables for accessing GitHub
  - **`GITHUB_TOKEN`** - Public GitHub API Token with full Scopes of repo and user.
    - Refer GitHub Docs [How To Get GitHub API Token] for help
- Config Data folder **`xgitguard\config\*`**

#### ML Model Setup and Training

- ML Data Setup and Training- Follow [ML Model Process](#ml-model-process)

#### Running Public Secret Detection

##### Pre-Setup

- Traverse into the `github-public` script folder

```
cd github-public
```

##### Public Credential Secrets Detection

- Running the Credential Secrets Detection script

```
# Run with Default configs
python public_cred_detections.py
```

- Command Line Arguments

```
Run usage:
usage: public_cred_detections.py [-h] [-p Primary Keywords] [-s Secondary Keywords] [-e Extensions] [-t Train Model] [-l Logger Level] [-c Console Logging]

optional arguments:
-h, --help show this help message and exit
-p Primary Keywords, --primary_keywords Primary Keywords
Pass the Primary Keywords list as comma separated string
-s Secondary Keywords, --secondary_keywords Secondary Keywords
Pass the Secondary Keywords list as comma separated string
-e Extensions, --extensions Extensions
Pass the Extensions list as comma separated string
-t Train Model, --train_model Train Model
Pass the Train Model as Yes or No. Default is No
-l Logger Level, --log_level Logger Level
Pass the Logging level as for CRITICAL - 50, ERROR - 40 WARNING - 30 INFO - 20 DEBUG - 10. Default is 20
-c Console Logging, --console_logging Console Logging
Pass the Console Logging as Yes or No. Default is Yes
```

- Run Variation Examples

```
# Run for given Primary Keyword, Secondary Keyword and extension with training with Debug Console logging

python public_cred_detections.py -p "abc.xyz.com" -s "password" -e "py" -t Yes -l 10 -c Yes
```

```
# Run for given Primary Keyword, Secondary Keyword and extension without training
python public_cred_detections.py -p "abc.xyz.com" -s "password" -e "py
```

```
# Run with Primary Keywords, Secondary Keywords from config file and given list of extensions
python public_cred_detections.py -e "py,txt"
```

```
# Run with Primary Keywords, Secondary Keywords and extensions from config files
python public_cred_detections.py
```

- Inputs used for Search and Scan

  > **Note:**
  > Command line argument keywords has precedence than config files (Default).
  > If No keywords passed in cli, config files data will be used for search.

- primary_keywords.csv file will have default list of primary keyword relavent patterns for search
- secondary_creds.csv file will have default list of credential relavent patterns for search
- extensions.csv file has default list of file extension to be searched

- GitHub Search Pattern for above Examples: **`abc.xyz.com password +extension:py`**

##### Public Keys and Tokens Secrets Detection

- Running the Keys and Tokens Secrets Detection script

```
# Run with Default configs
python public_key_detections.py
```

- Command Line Arguments

```
usage:
public_key_detections.py [-h] [-s Secondary Keywords] [-e Extensions] [-t Train Model] [-l Logger Level] [-c Console Logging]

optional arguments:
-h, --help show this help message and exit
-s Secondary Keywords, --secondary_keywords Secondary Keywords
Pass the Secondary Keywords list as comma separated string
-e Extensions, --extensions Extensions
Pass the Extensions list as comma separated string
-t Train Model, --train_model Train Model
Pass the Train Model as Yes or No. Default is No
-l Logger Level, --log_level Logger Level
Pass the Logging level as for CRITICAL - 50, ERROR - 40 WARNING - 30 INFO - 20 DEBUG - 10. Default is 20
-c Console Logging, --console_logging Console Logging
Pass the Console Logging as Yes or No. Default is Yes
```

- Run Variation Examples

```
# Run for given Primary Keyword, Secondary Keyword and extension with training with Debug Console logging
python public_key_detections.py -p "abc.xyz.com" -s "token" -e "py" -t Yes -l 10 -c Yes
```

```
# Run for given Primary Keyword, Secondary Keyword and extension without training
python public_key_detections.py -p "abc.xyz.com" -s "token" -e "py"
```

```
# Run with Primary Keywords, Secondary Keywords from config file and given list of extensions
python public_key_detections.py -e "py,txt"
```

```
# Run with Primary Keywords, Secondary Keywords and extensions from config files
python public_key_detections.py
```

#### Public Inputs and Outputs

> **Note:**
> Command line argument keywords has precedence than config files (Default).
> If No keywords passed in cli, config files data will be used for search.

- GitHub Search Pattern for above Examples: **`token +extension:py`**

##### Input Files

```
1. primary_keywords.csv file will have default list of primary keyword relavent patterns for search
2. secondary_keys.csv file will have default list of keys & tokens relavent patterns for search
3. extensions.csv file has default list of file extension to be searched
```

##### Output Files

- **Credentials**

  ```
    1. Hashed Url Files: xgitguard\config\public_hashed_url_creds.csv
        - List pf previously Processed Search urls. Urls stored will be skipped in next run to avoid re processing.
    2. Secrets Detectec: xgitguard\config\xgg_public_creds_detected.csv
    3. Log File: xgitguard\config\public_key_detections_*current run time yyyymmdd_hhmmss*.log
  ```

- **Keys & Tokens**

  ```
    1. Hashed Url Files: xgitguard\config\public_hashed_url_keys.csv
        - List pf previously Processed Search urls. Urls stored will be skipped in next run to avoid re processing.
    2. Secrets Detectec: xgitguard\config\xgg_public_keys_detected.csv
    3. Log File: xgitguard\config\public_key_detections_*yyyymmdd_hhmmss*.log
  ```

### Usage Note:

- User can add additional extensions to extensions.csv to search type of files other than default list.
- User can enhance secondary_creds.csv/secondary_keys.csv by adding new patterns to do search other than default list.

## License

Licensed under the [Apache 2.0](LICENSE) license.

[python >= v3.6]: https://www.python.org/downloads/
[how to get github api token]: https://docs.github.com/en/github/authenticating-to-github/keeping-your-account-and-data-secure/creating-a-personal-access-token
