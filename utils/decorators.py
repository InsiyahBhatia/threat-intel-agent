"""
Lightweight replacements for langchain decorators.
"""

from functools import wraps


class Tool:
    """Minimal replacement for langchain's tool-decorated function."""

    def __init__(self, func):
        self.func = func
        self.name = func.__name__
        self.description = func.__doc__ or ""
        wraps(func)(self)

    def invoke(self, input_value: str) -> str:
        return self.func(input_value)

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


def tool(func):
    return Tool(func)
