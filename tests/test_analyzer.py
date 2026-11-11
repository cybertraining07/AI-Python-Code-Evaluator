
from evaluator.analyzer import analyze_code


def test_detects_eval():
    code = """
def calculate(expression):
    return eval(expression)
"""
    result = analyze_code(code)

    assert result["valid_syntax"] is True
    assert any(
        finding.get("severity") == "HIGH"
        and "eval" in finding.get("message", "").lower()
        for finding in result["findings"]
    )


def test_detects_hardcoded_secret():
    code = """
API_KEY = "DEMO-SECRET-123"
"""
    result = analyze_code(code)

    assert any(
        finding.get("severity") == "HIGH"
        and "secret" in finding.get("type", "").lower()
        for finding in result["findings"]
    )

def test_detects_mutable_default():
    code = """
def add_item(item, items=[]):
    items.append(item)
    return items
"""
    result = analyze_code(code)

    assert any(
        finding.get("severity") == "MEDIUM"
        and "mutable default" in finding.get("message", "").lower()
        for finding in result["findings"]
    )


def test_detects_missing_docstring():
    code = """
def calculate(a, b):
    return a + b
"""
    result = analyze_code(code)

    assert any(
        "docstring" in finding.get("message", "").lower()
        for finding in result["findings"]
    )


def test_detects_invalid_python_syntax():
    code = """
def broken_function(
    return 10
"""
    result = analyze_code(code)

    assert result["valid_syntax"] is False
