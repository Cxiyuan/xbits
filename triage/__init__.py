"""xbits static triage package.

用法（命令行）：
    python3 triage/triage.py --file /path/to/sample

作为库：
    from triage.triage import analyze
    result = analyze("/path/to/sample")
"""
from .triage import analyze  # noqa: F401

__all__ = ["analyze"]
