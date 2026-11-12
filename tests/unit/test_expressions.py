import math

import pytest

from qshield.core.parsers.expressions import ExpressionError, evaluate_expression


def test_basic_arithmetic():
    assert evaluate_expression("1 + 2 * 3") == 7.0
    assert evaluate_expression("(1 + 2) * 3") == 9.0
    assert evaluate_expression("10 / 4") == 2.5


def test_pi_and_constants():
    assert evaluate_expression("pi") == pytest.approx(math.pi)
    assert evaluate_expression("pi / 2") == pytest.approx(math.pi / 2)
    assert evaluate_expression("-pi/4") == pytest.approx(-math.pi / 4)
    assert evaluate_expression("2*pi") == pytest.approx(2 * math.pi)
    assert evaluate_expression("e") == pytest.approx(math.e)


def test_functions():
    assert evaluate_expression("sin(0)") == pytest.approx(0.0)
    assert evaluate_expression("cos(0)") == pytest.approx(1.0)
    assert evaluate_expression("sqrt(4)") == pytest.approx(2.0)
    assert evaluate_expression("sqrt(pi)") == pytest.approx(math.sqrt(math.pi))


def test_env_substitution():
    assert evaluate_expression("theta * 2", env={"theta": 1.5}) == pytest.approx(3.0)
    assert evaluate_expression("a + b", env={"a": 2.0, "b": 40.0}) == pytest.approx(42.0)


def test_rejects_dangerous_input():
    with pytest.raises(ExpressionError):
        evaluate_expression("__import__('os').system('echo hi')")
    with pytest.raises(ExpressionError):
        evaluate_expression("open('file')")
    with pytest.raises(ExpressionError):
        evaluate_expression("a.b")
    with pytest.raises(ExpressionError):
        evaluate_expression("theta")  # not in env, not a constant
    with pytest.raises(ExpressionError):
        evaluate_expression("")


def test_rejects_inf_and_nan():
    with pytest.raises(ExpressionError):
        evaluate_expression("1e999")


def test_rejects_bool_and_string_constants():
    # bools evaluate as floats (0.0/1.0) and are allowed by design
    assert evaluate_expression("True") == 1.0
    with pytest.raises(ExpressionError):
        evaluate_expression("'abc'")


def test_disallowed_binop_and_unary():
    with pytest.raises(ExpressionError):
        evaluate_expression("1 << 4")
    with pytest.raises(ExpressionError):
        evaluate_expression("2 ** 3 ** 2 ** 2 ** 2 ** 2")  # overflow -> inf rejected, or via OverflowError
    with pytest.raises(ExpressionError):
        evaluate_expression("not 1")


def test_division_by_zero():
    with pytest.raises(ExpressionError, match=r"[Dd]ivision"):
        evaluate_expression("1 / 0")


def test_unknown_function_and_kwargs():
    with pytest.raises(ExpressionError):
        evaluate_expression("nosuchfn(1)")
    with pytest.raises(ExpressionError):
        evaluate_expression("sin(x=0)")
    with pytest.raises(ExpressionError):
        evaluate_expression("sin.cos(0)")


def test_syntax_error():
    with pytest.raises(ExpressionError, match="Cannot parse"):
        evaluate_expression("1 +")


def test_expression_to_non_real():
    with pytest.raises(ExpressionError):
        evaluate_expression("1j")
