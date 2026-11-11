
import re
import subprocess
import sys
from pathlib import Path


def run_tests(test_path, project_root=None, timeout=30):
    """
    Execute a Pytest test file and return structured results.

    Only use this runner with trusted code in your current
    development environment. It is not a security sandbox.
    """

    test_path = Path(test_path).resolve()

    if not test_path.is_file():
        raise FileNotFoundError(
            f"Test file not found: {test_path}"
        )

    if test_path.suffix != ".py":
        raise ValueError("Test file must be a Python file.")

    if project_root is None:
        project_root = Path.cwd()

    project_root = Path(project_root).resolve()

    results = {
        "status": "UNKNOWN",
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "pass_rate": 0.0,
        "exit_code": None,
        "output": "",
    }

    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--tb=short",
        str(test_path),
    ]

    try:
        process = subprocess.run(
            command,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        output = process.stdout + process.stderr

        results["output"] = output
        results["exit_code"] = process.returncode

        summary_match = re.search(
            r"(\d+) passed|(\d+) failed|"
            r"(\d+) error|(\d+) skipped",
            output,
        )

        # Collect every count from the Pytest summary.
        for key in ("passed", "failed", "errors", "skipped"):
            match = re.search(
                rf"(\d+) {key[:-1] if key == 'errors' else key}",
                output,
            )

            if match:
                results[key] = int(match.group(1))

        total = (
            results["passed"]
            + results["failed"]
            + results["errors"]
        )

        if total:
            results["pass_rate"] = round(
                results["passed"] / total * 100, 2
            )

        if process.returncode == 0:
            results["status"] = "PASSED"
        elif results["failed"] or results["errors"]:
            results["status"] = "FAILED"
        else:
            results["status"] = "ERROR"

    except subprocess.TimeoutExpired:
        results["status"] = "TIMEOUT"
        results["output"] = (
            f"Tests exceeded the {timeout}-second time limit."
        )

    except OSError as error:
        results["status"] = "ERROR"
        results["output"] = str(error)

    return results
