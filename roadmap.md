# xGitGuard Roadmap

## How to Use This Roadmap
This document serves as a comprehensive guide to the prioritized objectives of the xGitGuard project. It offers insight into the direction of the project, aiding contributors in understanding its trajectory. It also helps contributors determine whether their contributions align with the project's long-term goals. While a feature may not be listed here, it doesn't imply automatic refusal of a patch (except for "frozen features" mentioned below). We welcome patches for new features and encourage innovation. However, please be aware that such patches may take longer to review.

## How Can I Contribute?
Short-term objectives are documented in the wiki (link to be added later) and outlined in issues. Our aim is to distribute the workload in a manner that enables anyone to contribute. Please comment on issues to express your interest and avoid duplicating efforts.

## How Can I Propose a Feature for the Roadmap?
The roadmap process is a new initiative for xGitGuard, as we begin to structure and document our project objectives. Our immediate goal is to enhance transparency and collaborate with our community to focus on prioritized topics. While we aim to introduce a process for proposing topics to the roadmap in the near future, we're not there yet.

# Feature Classification 

## Adhoc Scan ---> https://github.com/Comcast/xGitGuard/issues/24

| Feature                   | Description                                             | Status | Developer (GitHub ID) |
|---------------------------|---------------------------------------------------------|--------|-----------------------|
| Targeted repository scanning | Enable xGitGuard to scan user specified repositories for secrets        | ✅ Done | [preethid03](https://github.com/preethid03) |
| Targeted organization scanning | Enable xGitGuard to scan user specified organization for secrets        | ✅ Done | [preethid03](https://github.com/preethid03) |
| Filtering archived repositories | Exclude archived repositories from scanning          | ✅ Done | [preethid03](https://github.com/preethid03) |
| Filtering forked repositories | Exclude forked repositories from scanning            | ✅ Done | [preethid03](https://github.com/preethid03) |
| Custom keyword search     | Search for specific keywords within repositories       | ✅ Done | [preethid03](https://github.com/preethid03) |

## File Scanner ---> https://github.com/Comcast/xGitGuard/issues/32

| Feature                   | Description                                             | Status | Developer (GitHub ID) |
|---------------------------|---------------------------------------------------------|--------|-----------------------|
| Directory scanning        | Enable scanning user specified directories for secrets                     | ⏳ WIP  | [](https://github.com/developer6) |
| Individual file scanning  | Enable scanning user specified individual files for secrets                | ⏳ WIP  | [](https://github.com/developer7) |

## ML Integration ---> https://github.com/Comcast/xGitGuard/issues/32

| Feature                   | Description                                             | Status | Developer (GitHub ID) |
|---------------------------|---------------------------------------------------------|--------|-----------------------|
| Training and building models using BERT | Train ML models for secret detection using BERT            | 🚧 To Do | [](https://github.com/developer8) |
| Integrating BERT into scanners | Integrating trained BERT model into the xGitGuard scanner  | 🚧 To Do | [](https://github.com/developer9) |

## Pre-commit Hook

| Feature                   | Description                                             | Status | Developer (GitHub ID) |
|---------------------------|---------------------------------------------------------|--------|-----------------------|
| Multi-language package manager | Manage code checks and linters before commits       |  🚧 To Do | [](https://github.com/preethid030) |
| Automatic installation of code linters | Install necessary tools for code review             |  🚧 To Do  | [](https://github.com/preethid031) |
| Run code linters and checks | Ensure code quality before committing changes       |  🚧 To Do  | [](https://github.com/preethid032) |
