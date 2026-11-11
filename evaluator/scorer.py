def deduplicate_security_findings(findings):
    """
    Remove duplicate findings based on line and issue type.
    Keep the finding with the highest severity.
    """

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
    }

    unique_findings = {}

    for finding in findings:
        line = finding.get("line")
        issue_type = finding.get("type", "").lower()
        message = finding.get("message", "").lower()
        test_id = finding.get("test_id", "").upper()

        # Recognize eval findings from both AST and Bandit.
        if test_id == "B307" or "eval" in issue_type or "eval" in message:
            issue_type = "eval"
        elif not issue_type:
            issue_type = test_id.lower() or message

        key = (line, issue_type)

        if key not in unique_findings:
            unique_findings[key] = finding
        else:
            current = unique_findings[key]

            new_rank = severity_rank.get(
                finding.get("severity", "").upper(), 0
            )
            current_rank = severity_rank.get(
                current.get("severity", "").upper(), 0
            )

            if new_rank > current_rank:
                unique_findings[key] = finding

    return list(unique_findings.values())
def calculate_score(test_results, analysis_results, static_results=None):
    """
    Calculate a code quality score out of 100.

    Testing:    40 points
    Security:   30 points
    Complexity: 20 points
    Style:      10 points

    An incomplete assessment receives no final grade.
    """

    breakdown = {}
    assessment_complete = True

    # 1. AUTOMATED TESTING
    test_status = test_results.get("status", "UNKNOWN")
    test_score = 0

    if test_status in ("PASSED", "FAILED"):
        pass_rate = test_results.get("pass_rate", 0)
        pass_rate = max(0, min(100, float(pass_rate)))
        test_score = 40 * (pass_rate / 100)
    else:
        assessment_complete = False

    test_score = round(test_score, 2)

    breakdown["testing"] = {
        "maximum": 40,
        "score": test_score,
        "status": test_status,
    }

    # 2. SECURITY
    security = analysis_results.get("security", {})
    security_status = security.get("status", "UNKNOWN")
    security_score = 0

    ast_findings = (
        static_results.get("findings", [])
        if static_results else []
    )

    bandit_findings = security.get("findings", [])
    all_security_findings = deduplicate_security_findings(
        bandit_findings + ast_findings
    )
    if security_status == "COMPLETED":
        security_score = 30

        penalties = {
            "HIGH": 10,
            "MEDIUM": 5,
            "LOW": 2,
        }

        for finding in all_security_findings:
            severity = finding.get("severity", "").upper()
            security_score -= penalties.get(severity, 0)

        security_score = max(0, security_score)
    else:
        assessment_complete = False

    breakdown["security"] = {
        "maximum": 30,
        "score": security_score,
        "findings": len(all_security_findings),
        "status": security_status,
        "bandit_findings": len(bandit_findings),
        "ast_findings": len(ast_findings),
    }
    # 3. CODE COMPLEXITY
    complexity = analysis_results.get("complexity", {})
    complexity_status = complexity.get("status", "UNKNOWN")
    complexity_score = 0

    if complexity_status == "COMPLETED":
        blocks = complexity.get("blocks", [])

        rank_scores = {
            "A": 20,
            "B": 18,
            "C": 15,
            "D": 10,
            "E": 5,
            "F": 0,
        }

        if blocks:
            scores = [
                rank_scores.get(block.get("rank", "F"), 0)
                for block in blocks
            ]
            complexity_score = sum(scores) / len(scores)
        else:
            complexity_score = 20
    else:
        assessment_complete = False

    complexity_score = round(complexity_score, 2)

    breakdown["complexity"] = {
        "maximum": 20,
        "score": complexity_score,
        "functions": complexity.get("total_functions"),
        "status": complexity_status,
    }

    # 4. CODE STYLE
    style = analysis_results.get("style", {})
    style_status = style.get("status", "UNKNOWN")
    style_score = 0

    if style_status == "COMPLETED":
        violations = style.get("total_findings", 0)
        style_score = max(0, 10 - violations)
    else:
        assessment_complete = False

    breakdown["style"] = {
        "maximum": 10,
        "score": style_score,
        "violations": style.get("total_findings"),
        "status": style_status,
    }

    # 5. FINAL SCORE AND GRADE
    total_score = round(
        test_score
        + security_score
        + complexity_score
        + style_score,
        2,
    )

    if assessment_complete:
        if total_score >= 90:
            grade = "Excellent"
        elif total_score >= 80:
            grade = "Very Good"
        elif total_score >= 70:
            grade = "Good"
        elif total_score >= 60:
            grade = "Fair"
        else:
            grade = "Needs Improvement"
    else:
        grade = "Incomplete"

    return {
        "overall_score": total_score,
        "maximum_score": 100,
        "grade": grade,
        "assessment_complete": assessment_complete,
        "breakdown": breakdown,
    }
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
