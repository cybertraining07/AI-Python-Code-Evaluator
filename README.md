# AI Python Code Evaluator

A Python-based code evaluation tool that analyzes source code, runs automated tests, identifies potential security issues, measures code complexity, checks coding style, and generates an HTML evaluation report.

## Features

- **Static Code Analysis:** Uses Python's AST module to inspect source code without executing the analyzed file.
- **Automated Testing:** Runs pytest tests and reports pass rates and failures.
- **Security Analysis:** Uses Bandit to identify potential Python security vulnerabilities.
- **Custom Security Checks:** Detects issues such as `eval()`, mutable default arguments, bare `except` blocks, and potential hardcoded secrets.
- **Complexity Analysis:** Uses Radon to measure cyclomatic complexity.
- **Code Quality:** Uses Flake8 to identify style violations.
- **Scoring System:** Calculates a score out of 100 based on testing, security, complexity, and style.
- **HTML Reports:** Generates readable reports with findings and recommendations.

## Technologies Used

- Python 3
- Abstract Syntax Trees (AST)
- pytest
- Bandit
- Radon
- Flake8
- HTML and CSS

## Project Structure

```text
AI-Python-Code-Evaluator/
├── main.py
├── requirements.txt
├── README.md
├── evaluator/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── test_runner.py
│   ├── security.py
│   ├── scorer.py
│   └── report.py
├── tests/
│   ├── test_analyzer.py
│   ├── test_sample_code.py
│   └── test_scorer.py
├── samples/
│   ├── sample_code.py
│   └── vulnerable_sample.py
└── reports/
    ├── evaluation_report.html
    ├── vulnerable_evaluation_report.html
    └── incomplete_evaluation_report.html
```

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd AI-Python-Code-Evaluator
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Evaluate a Python source file with a corresponding pytest test file:

```bash
python main.py --file samples/sample_code.py --tests tests/test_sample_code.py
```

The evaluator performs the following steps:

1. Static code analysis.
2. Automated test execution.
3. Security and code quality analysis.
4. Score calculation.
5. HTML report generation.

The generated report is saved to:

```text
reports/evaluation_report.html
```

## View the HTML Report

Start a local web server from the reports directory:

```bash
cd reports
python -m http.server 8001 --bind 127.0.0.1
```

Open this address in your browser:

```text
http://127.0.0.1:8001/evaluation_report.html
```

Stop the server with `Ctrl+C`.

## Scoring System

| Category | Maximum Points |
|---|---:|
| Automated Testing | 40 |
| Security Analysis | 30 |
| Complexity Analysis | 20 |
| Code Style | 10 |
| **Total** | **100** |

A final grade is only assigned when all required evaluation stages complete successfully. Incomplete assessments are marked as incomplete rather than receiving a misleading final grade.

## Example Result

The clean sample project completed with:

- **Score:** 100/100
- **Grade:** Excellent
- **Tests:** 5 passed
- **Security findings:** 0
- **Complexity:** A
- **Style violations:** 0

## Running Tests

Run the project's test suite:

```bash
pytest -v
```

## Security Limitations

This project is an educational code analysis and evaluation tool, not a secure execution sandbox.

- Static AST analysis inspects source code without executing the analyzed source file.
- The pytest runner executes test code in a subprocess.
- A subprocess alone does not safely isolate malicious code.
- Do not use this tool to execute arbitrary untrusted or AI-generated code.
- The hardcoded secret detector is heuristic and may produce false positives or miss secrets.

A future improvement would be to add properly isolated execution using containers or another security boundary.

## Future Improvements

- Add isolated execution for untrusted code.
- Expand vulnerability detection rules.
- Improve report visualizations.
- Add support for more test and analysis configurations.
- Explore optional AI-assisted code feedback.

## Project Purpose

This project demonstrates practical Python development, static analysis, automated testing, security scanning, software quality measurement, scoring logic, and report generation.
