# PYCSPCHECKER

**PYCSPCHECKER** is a Python script designed to analyze and validate Content Security Policy (CSP) headers for websites. It helps developers and security analysts identify potential security issues in their CSP configurations.

## Features

- Asynchronously fetch CSP headers from provided URLs.
- Categorize CSP directives for easy analysis.
- Evaluate CSP for common security issues and provide warnings.
- Output results in plain text or JSON format.
- Option to save results to a file.

## Requirements

Make sure you have Python 3.x installed. The following packages are required:

- `aiohttp`
- `colorama`
- `pyfiglet`

You can install the necessary packages using `pip` with the following command:

```bash
pip3 install -r requirements.txt

Usage

    Clone the repository or download the script.
    Navigate to the directory containing the script.
    Run the script with the following command:

bash

python csp_checker.py
