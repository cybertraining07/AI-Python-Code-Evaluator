
import ast
from pathlib import Path


DANGEROUS_FUNCTIONS = {
    "eval": "Dynamic code execution can introduce security risks.",
    "exec": "Executing dynamically generated code can be dangerous.",
}

SENSITIVE_NAMES = {
    "password",
    "secret",
    "api_key",
    "token",
}


def analyze_code(source_code):
    """
    Analyze Python source code without executing it.

    Returns syntax information, code structure,
    and potential implementation/security findings.
    """

    results = {
        "valid_syntax": False,
        "functions": [],
        "classes": [],
        "imports": [],
        "findings": [],
        "error": None,
    }

    # Step 1: Check Python syntax
    try:
        tree = ast.parse(source_code)
        results["valid_syntax"] = True

    except SyntaxError as error:
        results["error"] = {
            "message": error.msg,
            "line": error.lineno,
            "column": error.offset,
        }

        results["findings"].append({
            "severity": "HIGH",
            "type": "Syntax Error",
            "line": error.lineno,
            "message": error.msg,
            "recommendation": "Correct the syntax error before testing.",
        })

        return results

    # Step 2: Inspect code structure
    for node in ast.walk(tree):

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            results["functions"].append(node.name)

            # Detect functions without documentation
            if ast.get_docstring(node) is None:
                results["findings"].append({
                    "severity": "LOW",
                    "type": "Documentation",
                    "line": node.lineno,
                    "message": (
                        f"Function '{node.name}' has no docstring."
                    ),
                    "recommendation": (
                        "Add a docstring describing the function."
                    ),
                })

            # Detect mutable default arguments
            for default in node.args.defaults:
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    results["findings"].append({
                        "severity": "MEDIUM",
                        "type": "Potential Bug",
                        "line": node.lineno,
                        "message": (
                            f"Function '{node.name}' uses a mutable "
                            "default argument."
                        ),
                        "recommendation": (
                            "Use None as the default and initialize "
                            "the mutable object inside the function."
                        ),
                    })

        elif isinstance(node, ast.ClassDef):
            results["classes"].append(node.name)

        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                results["imports"].append(alias.name)

        # Step 3: Detect dangerous function calls
        elif isinstance(node, ast.Call):

            if isinstance(node.func, ast.Name):
                function_name = node.func.id

                if function_name in DANGEROUS_FUNCTIONS:
                    results["findings"].append({
                        "severity": "HIGH",
                        "type": "Security Risk",
                        "line": node.lineno,
                        "message": (
                            f"Dangerous function '{function_name}' detected."
                        ),
                        "recommendation": (
                            DANGEROUS_FUNCTIONS[function_name]
                        ),
                    })

            # Detect subprocess shell=True
            if (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                for keyword in node.keywords:
                    if (
                        keyword.arg == "shell"
                        and isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is True
                    ):
                        results["findings"].append({
                            "severity": "HIGH",
                            "type": "Security Risk",
                            "line": node.lineno,
                            "message": (
                                "Subprocess uses shell=True."
                            ),
                            "recommendation": (
                                "Avoid shell execution where possible. "
                                "Use argument lists and validate inputs."
                            ),
                        })

        # Step 4: Detect bare except blocks
        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                results["findings"].append({
                    "severity": "MEDIUM",
                    "type": "Error Handling",
                    "line": node.lineno,
                    "message": "Bare except block detected.",
                    "recommendation": (
                        "Catch specific exceptions instead."
                    ),
                })

        # Step 5: Detect potentially hardcoded secrets
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    variable_name = target.id.lower()

                    if (
                        variable_name in SENSITIVE_NAMES
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                        and node.value.value.strip()
                    ):
                        results["findings"].append({
                            "severity": "HIGH",
                            "type": "Potential Hardcoded Secret",
                            "line": node.lineno,
                            "message": (
                                f"Variable '{target.id}' contains "
                                "a hardcoded string value."
                            ),
                            "recommendation": (
                                "Use environment variables or "
                                "a secure secrets manager."
                            ),
                        })

    return results


def analyze_file(file_path):
    """Read and analyze a Python file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    if path.suffix != ".py":
        raise ValueError("Only Python files are supported.")

    source_code = path.read_text(encoding="utf-8")

    return analyze_code(source_code)
