#
# (c) FFRI Security, Inc., 2020-2024 / Author: FFRI Security, Inc.
#
__version__ = "0.1.3"

from .scanner import (
    PEiDScanner as PEiDScanner,
    format_as_katc_peid as format_as_katc_peid,
)

__all__ = ["PEiDScanner, format_as_katc_peid"]
