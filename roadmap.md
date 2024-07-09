
# xGitGuard Roadmap

## How to Use This Roadmap
This document serves as a comprehensive guide to the prioritized objectives of the xGitGuard project. It offers insight into the direction of the project, aiding contributors in understanding its trajectory. It also helps contributors determine whether their contributions align with the project's long-term goals.

While a feature may not be listed here, it doesn't imply automatic refusal of a patch (except for "frozen features" mentioned below). We welcome patches for new features and encourage innovation. However, please be aware that such patches may take longer to review.

---

## Feature Classification

### Adhoc Scan
| Feature                          | Description                                      | Status    | Developer (GitHub ID)        |
|----------------------------------|--------------------------------------------------|-----------|------------------------------|
| [🎯 Targeted repository scanning](https://github.com/Comcast/xGitGuard/issues/24) | Scan user specified repositories for secrets     | ✅ Done   | [preethid03](https://github.com/preethid03) |
| [🎯 Targeted organization scanning](https://github.com/Comcast/xGitGuard/issues/24) | Scan user specified organization for secrets     | ✅ Done   | [preethid03](https://github.com/preethid03) |

---

### File Scanner

| Feature                   | Description                                             | Status | Developer (GitHub ID) |
|---------------------------|---------------------------------------------------------|--------|-----------------------|
| 📁 Directory scanning        | Enable scanning user specified directories for secrets                     | ⏳ WIP  | [](https://github.com/developer6) |
| 📁 Individual file scanning  | Enable scanning user specified individual files for secrets                | ⏳ WIP  | [](https://github.com/developer7) |



---

### ML Integration ---> [GitHub Issues](https://github.com/Comcast/xGitGuard/issues/32)
| Feature                          | Description                                      | Status    | Developer (GitHub ID)        |
|----------------------------------|--------------------------------------------------|-----------|------------------------------|
| 🤖 Training ML models using BERT  | Train models for secret detection using BERT    | 🚧 To Do  | [](https://github.com/developer8) |
| 🤖 Integrating BERT into scanners | Integrate BERT model into xGitGuard scanner     | 🚧 To Do  | [](https://github.com/developer9) |

---

### Pre-commit Hook
| Feature                          | Description                                      | Status    | Developer (GitHub ID)        |
|----------------------------------|--------------------------------------------------|-----------|------------------------------|
| 🔒 Detecting secrets pre-commit| Detect secrets before committing changes   | 🚧 To Do  | [](https://github.com/) |


---

### Others
| Feature                          | Description                                      | Status    | Developer (GitHub ID)        |
|----------------------------------|--------------------------------------------------|-----------|------------------------------|
| Custom keyword search          | Search for specific keywords within repositories| 🚧 To Do  | [](https://github.com/developer8) |
| Filtering archived repositories | Exclude archived repositories from scanning    | 🚧 To Do  | [](https://github.com/developer8) |
| Filtering forked repositories   | Exclude forked repositories from scanning      | 🚧 To Do  | [](https://github.com/developer8) |

---


**Legend:**
- ✅ Done: Completed feature.
- 🚧 To Do: Feature in progress.

---

## Additional Issues and Contributions

Contributors are welcome to explore and contribute to other issues on the xGitGuard repository: [xGitGuard GitHub Issues](https://github.com/Comcast/xGitGuard/issues)
