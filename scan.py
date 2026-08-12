#!/usr/bin/env python3
"""Convenience wrapper so the scanner runs as ./scan.py"""

import sys

from umscan.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
