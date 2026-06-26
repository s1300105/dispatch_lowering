# TaintP2X

## Project Overview

![Project Overview Diagram](img/overview.png)

This repository implements a static analysis framework that integrates static taint analysis with large language model (LLM) semantic analysis. Our method statically detects P2Xi (Prompt-to-Anything Injection) issues by analyzing the call relationships between LLM APIs and sensitive functions, combined with the semantic understanding capabilities of LLMs.

## Key Features

Pysa-based Static Analysis Framework:
Built upon the open-source Pysa framework, enhancing its cross-function taint propagation capabilities and customizing it for LLM security scenarios.

Intelligent Taint Source Identification:
Combines AST parsing with semantic reasoning, utilizing LLMs to automatically generate structured taint source specifications, enabling automatic identification of standard and custom sources.

Multi-layer Taint Propagation Analysis:
Precisely constructs complete source-to-sink propagation paths through CFG-based intra-function analysis, inter-function propagation, and result intersection fusion.

LLM-assisted False Positive Pruning:
Employs a semantic-driven two-stage analysis, using source controllability analysis and multi-round LLM verification to effectively identify truly exploitable vulnerabilities and reduce false positives.


## Project Structure

- `LLM-assisted_Validation/`: Contains modules related to LLM-assisted validation, including `ds_llm_fully_determine_mul.py`, `ds_llm_source_determine_mul.py`, and `extract_code_mul.py`.
- `Source_Identification/`: Contains modules for source identification, such as `analyze_assignments.py`, `confirm_source.py`, and `make_pysa_source.py`.
- `Taint_Propagation/`: Core modules for taint propagation, including Pyre configuration, stub files (`stubs/`) for various libraries (e.g., `anthropic.pyi`, `autogen.pyi`, `django/`, `openai.pyi`), and Pysa taint definition files (`taint/`) like `django_sinks.pysa`, `llms_sources.pysa`, and `rce_sink.pysa`, including the predefined LLM API table `TaintP2X/Taint_Propagation/taint/llm_sources.xlsx`.
- `dataset/`: Contains all datasets for experiments.
- `project/`: Contains the directory of projects to be tested.
- `pysa_result/`: Directory for storing Pysa analysis results.
- `run_download_and_check.py`: Script for downloading and checking resources.
- `checked_repos.json` `test_source.json`: Other project files.

## Installation

This project requires Pyre to be installed. Link: https://pyre-check.org/docs/pysa-quickstart/


## Usage

Use `run_download_and_check.py` to detect projects. This script is used to download and perform initial checks on projects. Projects to be detected can be configured in `test_source.json`.

The format of the `test_source.json` file is as follows:
```json
{
  "project_name_1": {
    "git_url": "https://github.com/owner/repo1.git",
    "commit_hash": "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4"
  },
  "project_name_2": {
    "git_url": "https://github.com/owner/repo2.git",
    "commit_hash": "b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5"
  }
}
```
Where:
- `project_name_1`, `project_name_2`, etc., are unique names you define for your projects.
- `git_url` is the Git repository address of the project.
- `commit_hash` is the hash of the specific commit to be detected.

`run_download_and_check.py` will download projects to the `dataset/real_world` directory and perform initial checks based on the configuration in `test_source.json`.

Use `unified_analysis.py` to analyze the detected projects. This script iterates through the projects configured in `PROJECT_NAMES` and performs taint analysis and DeepSeek LLM-assisted verification for each project.

## Citation  

If you use this code in your research, please cite our paper:

```
@inproceedings{icse26taintp2x,
author = {He, Junjie and Wang, Shenao and Zhao, Yanjie and Hou, Xinyi and Liu, Zhao and Zou, Quanchen and Wang, Haoyu},
title = {TaintP2X: Detecting Taint-Style Prompt-to-Anything Injection Vulnerabilities in LLM-Integrated Applications},
year = {2026},
booktitle = {Proceedings of the IEEE/ACM 48th International Conference on Software Engineering},
doi = {10.1145/3744916.3773199},
url = {https://doi.org/10.1145/3744916.3773199}
}
```

## Contributing

We welcome contributions! Feel free to submit pull requests or open issues to report bugs and suggest features. For any questions or support, please contact hjj@hust.edu.cn.

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
