
from evaluator.scorer import calculate_score


def completed_analysis(security_findings=None):
    return {
        "security": {
            "status": "COMPLETED",
            "findings": security_findings or [],
            "total_findings": len(security_findings or []),
        },
        "complexity": {
            "status": "COMPLETED",
            "blocks": [
                {"name": "example", "rank": "A"}
            ],
            "total_functions": 1,
        },
        "style": {
            "status": "COMPLETED",
            "findings": [],
            "total_findings": 0,
        },
    }


def test_perfect_assessment():
    tests = {
        "status": "PASSED",
        "pass_rate": 100,
    }

    result = calculate_score(tests, completed_analysis())

    assert result["overall_score"] == 100
    assert result["grade"] == "Excellent"
    assert result["assessment_complete"] is True


def test_failed_tests_reduce_score():
    tests = {
        "status": "FAILED",
        "pass_rate": 75,
    }

    result = calculate_score(tests, completed_analysis())

    assert result["overall_score"] == 90
    assert result["assessment_complete"] is True


def test_incomplete_assessment_has_no_final_grade():
    tests = {
        "status": "NOT_RUN",
        "pass_rate": 0,
    }

    result = calculate_score(tests, completed_analysis())

    assert result["grade"] == "Incomplete"
    assert result["assessment_complete"] is False


def test_high_security_finding_reduces_score():
    tests = {
        "status": "PASSED",
        "pass_rate": 100,
    }

    findings = [
        {"severity": "HIGH"}
    ]

    result = calculate_score(
        tests,
        completed_analysis(findings),
    )

    assert result["breakdown"]["security"]["score"] == 20
    assert result["overall_score"] == 90
def test_ast_security_finding_reduces_score():
    tests = {
        "status": "PASSED",
        "pass_rate": 100,
    }

    static_results = {
        "findings": [
            {
                "severity": "HIGH",
                "type": "Potential Hardcoded Secret",
            }
        ]
    }

    result = calculate_score(
        tests,
        completed_analysis(),
        static_results,
    )

    assert result["breakdown"]["security"]["score"] == 20
    assert result["breakdown"]["security"]["ast_findings"] == 1
    assert result["overall_score"] == 90
def test_duplicate_security_findings_are_deduplicated():
    findings = [
        {
            "line": 6,
            "type": "Security Risk",
            "severity": "HIGH",
        },
        {
            "line": 6,
            "type": "Security Risk",
            "severity": "MEDIUM",
        },
    ]

    from evaluator.scorer import deduplicate_security_findings

    result = deduplicate_security_findings(findings)

    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"
def test_real_bandit_and_ast_eval_findings_are_deduplicated():
    findings = [
        {
            "line": 6,
            "test_id": "B307",
            "severity": "MEDIUM",
            "message": "Use of possibly insecure function - consider using safer ast.literal_eval.",
        },
        {
            "line": 6,
            "type": "Security Risk",
            "severity": "HIGH",
            "message": "Dangerous function 'eval' detected.",
        },
    ]

    from evaluator.scorer import deduplicate_security_findings

    result = deduplicate_security_findings(findings)

    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"
