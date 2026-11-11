
import sys
from pathlib import Path

import pytest

# Make the samples directory available for imports.
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "samples")
)

from sample_code import divide


def test_normal_division():
    assert divide(10, 2) == 5


def test_decimal_division():
    assert divide(7, 2) == 3.5


def test_division_by_zero():
    with pytest.raises(ValueError):
        divide(10, 0)


def test_negative_numbers():
    assert divide(-10, 2) == -5


def test_invalid_input():
    with pytest.raises(TypeError):
        divide("ten", 2)
