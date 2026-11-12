"""Phishing detection engine: raw email bytes in, a scored verdict out."""

from .engine import analyze

__all__ = ["analyze"]
