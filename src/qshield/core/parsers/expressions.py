"""Safe arithmetic evaluator for OpenQASM parameter expressions.

Allows numbers, + - * / % ** //, parentheses, unary +/-, the constants
``pi`` / ``e`` / ``tau`` and calls to the functions in ``MATH_FUNCS``.
Everything else raises :class:`ExpressionError`.
"""

from __future__ import annotations

import ast
import math
import re
from collections.abc import Callable
from typing import Any

# Resource limits — parameter expressions come from untrusted circuit files.
MAX_EXPRESSION_LENGTH = 2048      # characters; legit gate params are a handful
MAX_POW_EXPONENT = 128            # |exponent| cap; kills 2**10**10-class DoS
MAX_CONSTANT_DIGITS = 400         # int literals longer than this are rejected
_LONG_NUMBER_RE = re.compile(r"\d{401,}")

MATH_FUNCS: dict[str, Callable[..., float]] = {
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "asin": math.asin,
    "acos": math.acos,
    "atan": math.atan,
    "sqrt": math.sqrt,
    "exp": math.exp,
    "log": math.log,
    "ln": math.log,
    "abs": abs,
    "floor": math.floor,
    "ceil": math.ceil,
}

CONSTANTS = {"pi": math.pi, "e": math.e, "tau": math.tau}

_ALLOWED_BINOPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
    ast.FloorDiv: lambda a, b: a // b,
    ast.Mod: lambda a, b: a % b,
    ast.Pow: lambda a, b: a ** b,
}

_ALLOWED_UNARYOPS: dict[type, Callable[[float], float]] = {
    ast.UAdd: lambda a: +a,
    ast.USub: lambda a: -a,
}


class ExpressionError(ValueError):
    """Raised when an expression cannot be safely evaluated."""


def _eval_node(node: ast.AST, env: dict[str, float]) -> Any:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, env)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool):
            return float(node.value)
        if isinstance(node.value, (int, float)):
            try:
                return float(node.value)
            except OverflowError:
                raise ExpressionError("Numeric constant too large") from None
        raise ExpressionError(f"Disallowed constant: {node.value!r}")
    if isinstance(node, ast.Name):
        if node.id in env:
            return float(env[node.id])
        if node.id in CONSTANTS:
            return CONSTANTS[node.id]
        raise ExpressionError(f"Unknown name: {node.id!r}")
    if isinstance(node, ast.BinOp):
        op = _ALLOWED_BINOPS.get(type(node.op))
        if op is None:
            raise ExpressionError(f"Disallowed operator: {type(node.op).__name__}")
        left = _eval_node(node.left, env)
        right = _eval_node(node.right, env)
        if isinstance(node.op, ast.Pow):
            # Cap |exponent| — left**right with a huge exponent is a memory/CPU bomb.
            if abs(right) > MAX_POW_EXPONENT:
                raise ExpressionError(f"Exponent too large (|exp| > {MAX_POW_EXPONENT})")
            if abs(right) > 0 and abs(left) > 1.0 and right > 0:
                # left**right must stay representable
                try:
                    import math as _math
                    if right * _math.log10(abs(left)) > 308:
                        raise ExpressionError("Power result too large")
                except ValueError:
                    pass
        try:
            return op(left, right)
        except ZeroDivisionError as exc:
            raise ExpressionError("Division by zero in expression") from exc
        except OverflowError as exc:
            raise ExpressionError("Numeric overflow in expression") from exc
    if isinstance(node, ast.UnaryOp):
        uop = _ALLOWED_UNARYOPS.get(type(node.op))
        if uop is None:
            raise ExpressionError(f"Disallowed unary operator: {type(node.op).__name__}")
        return uop(_eval_node(node.operand, env))
    if isinstance(node, ast.Call):
        if node.keywords:
            raise ExpressionError("Keyword arguments are not allowed in expressions")
        if not isinstance(node.func, ast.Name):
            raise ExpressionError("Only direct function calls are allowed")
        func = MATH_FUNCS.get(node.func.id)
        if func is None:
            raise ExpressionError(f"Unknown function: {node.func.id!r}")
        args = [_eval_node(a, env) for a in node.args]
        try:
            return func(*args)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ExpressionError(f"Invalid arguments to {node.func.id!r}: {exc}") from exc
    raise ExpressionError(f"Disallowed expression element: {type(node).__name__}")


def evaluate_expression(expr: str, env: dict[str, float] | None = None) -> float:
    """Evaluate a parameter expression to a float.

    ``env`` maps formal parameter names (used inside ``gate`` bodies) to
    their numeric values.
    """
    env = env or {}
    text = expr.strip()
    if not text:
        raise ExpressionError("Empty expression")
    if len(text) > MAX_EXPRESSION_LENGTH:
        raise ExpressionError(f"Expression too long (>{MAX_EXPRESSION_LENGTH} chars)")
    if _LONG_NUMBER_RE.search(text):
        raise ExpressionError("Numeric literal too long")
    try:
        tree = ast.parse(text, mode="eval")
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise ExpressionError(f"Cannot parse expression: {expr!r}") from exc
    try:
        value = _eval_node(tree, env)
    except RecursionError as exc:
        raise ExpressionError("Expression too deeply nested") from exc
    if not isinstance(value, (int, float)) or math.isnan(float(value)):
        raise ExpressionError(f"Expression did not evaluate to a real number: {expr!r}")
    if math.isinf(float(value)):
        raise ExpressionError(f"Expression evaluated to infinity: {expr!r}")
    return float(value)
