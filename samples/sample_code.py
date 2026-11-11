
def divide(a, b):
    """Divide two numbers safely."""

    if b == 0:
        raise ValueError("Cannot divide by zero.")

    return a / b
