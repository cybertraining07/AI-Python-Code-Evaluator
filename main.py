
import argparse
import json
from pathlib import Path

from evaluator.analyzer import analyze_file
from evaluator.test_runner import run_tests
from evaluator.security import analyze_all
from evaluator.scorer import calculate_score
from evaluator.report import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="AI Python Code Evaluator"
    )

    parser.add_argument(
        "--file",
        required=True,
        help="Python source file to evaluate"
    )

    parser.add_argument(
        "--tests",
        required=True,
        help="Pytest test file to execute"
    )

    args = parser.parse_args()

    source_file = Path(args.file)
    test_file = Path(args.tests)

    if not source_file.is_file():
        parser.error(f"Source file not found: {source_file}")

    if not test_file.is_file():
        parser.error(f"Test file not found: {test_file}")

    print("\n===================================")
    print("       AI PYTHON CODE EVALUATOR")
    print("===================================")

    print("\n[1/5] Running static code analysis...")
    static_results = analyze_file(str(source_file))

    print("[2/5] Running automated tests...")
    test_results = run_tests(str(test_file))

    print("[3/5] Running security and quality analysis...")
    analysis_results = analyze_all(str(source_file))

    print("[4/5] Calculating evaluation score...")
    score_results = calculate_score(
        test_results,
        analysis_results,
        static_results
    )
    print("[5/5] Generating HTML report...")
    report_path = generate_report(
        test_results,
        analysis_results,
        score_results,
        static_results=static_results
    )

    print("\n===================================")
    print("          EVALUATION RESULTS")
    print("===================================")

    print(json.dumps(score_results, indent=4))

    print("\nHTML report:", report_path)
    print("\nEvaluation completed.")


if __name__ == "__main__":
    main()
