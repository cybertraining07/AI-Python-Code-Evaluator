
import json
import subprocess
import sys
from pathlib import Path


def run_analysis(command, timeout=30):
    """Run a static analysis tool without executing the target code."""

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        return {
            "exit_code": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "error": "Analysis timed out.",
        }

    except OSError as error:
        return {
            "exit_code": None,
            "stdout": "",
            "stderr": "",
            "error": str(error),
        }


def analyze_security(file_path):
    """Analyze Python code using Bandit."""

    path = Path(file_path).resolve()

    if not path.is_file() or path.suffix != ".py":
        raise ValueError("A valid Python source file is required.")

    command = [
        sys.executable,
        "-m",
        "bandit",
        "-f",
        "json",
        str(path),
    ]

    result = run_analysis(command)

    findings = []

    if result["error"]:
        return {
            "status": "ERROR",
            "findings": [],
            "error": result["error"],
        }

    try:
        data = json.loads(result["stdout"])

        for issue in data.get("results", []):
            findings.append({
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
                "test_id": issue.get("test_id"),
                "line": issue.get("line_number"),
                "message": issue.get("issue_text"),
            })

    except json.JSONDecodeError:
        return {
            "status": "ERROR",
            "findings": [],
            "error": result["stderr"] or "Invalid Bandit JSON output.",
        }

    return {
        "status": "COMPLETED",
        "findings": findings,
        "total_findings": len(findings),
        "error": None,
    }


def analyze_complexity(file_path):
    """Measure Python code complexity using Radon."""

    path = Path(file_path).resolve()

    if not path.is_file() or path.suffix != ".py":
        raise ValueError("A valid Python source file is required.")

    command = [
        sys.executable,
        "-m",
        "radon",
        "cc",
        "-j",
        str(path),
    ]

    result = run_analysis(command)

    if result["error"]:
        return {
            "status": "ERROR",
            "blocks": [],
            "error": result["error"],
        }

    try:
        data = json.loads(result["stdout"])
        blocks = data.get(str(path), [])

        return {
            "status": "COMPLETED",
            "blocks": blocks,
            "total_functions": len(blocks),
            "error": None,
        }

    except json.JSONDecodeError:
        return {
            "status": "ERROR",
            "blocks": [],
            "error": result["stderr"] or "Invalid Radon JSON output.",
        }


def analyze_style(file_path):
    """Check Python coding style using Flake8."""

    path = Path(file_path).resolve()

    if not path.is_file() or path.suffix != ".py":
        raise ValueError("A valid Python source file is required.")

    command = [
        sys.executable,
        "-m",
        "flake8",
        "--format=%(code)s|%(row)d|%(col)d|%(text)s",
        str(path),
    ]

    result = run_analysis(command)

    if result["error"]:
        return {
            "status": "ERROR",
            "findings": [],
            "error": result["error"],
        }

    findings = []

    for line in result["stdout"].splitlines():
        parts = line.split("|", 3)

        if len(parts) == 4:
            code, row, column, message = parts

            findings.append({
                "code": code,
                "line": int(row),
                "column": int(column),
                "message": message,
            })

    if result["exit_code"] not in (0, 1):
        return {
            "status": "ERROR",
            "findings": findings,
            "error": result["stderr"] or "Flake8 execution failed.",
        }

    return {
        "status": "COMPLETED",
        "findings": findings,
        "total_findings": len(findings),
        "error": None,
    }


def analyze_all(file_path):
    """Run all three static analysis tools."""

    return {
        "security": analyze_security(file_path),
        "complexity": analyze_complexity(file_path),
        "style": analyze_style(file_path),
    }
