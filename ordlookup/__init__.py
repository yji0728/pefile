#!/usr/bin/env python3
"""A small module for keeping a database of ordinal to symbol mappings.

This is used for DLLs which frequently get linked without symbolic info.
"""

from __future__ import annotations

from typing import Dict, Optional, Union

from . import oleaut32
from . import ws2_32

ords: Dict[bytes, Dict[int, bytes]] = {
    b'ws2_32.dll': ws2_32.ord_names,
    b'wsock32.dll': ws2_32.ord_names,
    b'oleaut32.dll': oleaut32.ord_names,
}


def format_ord_string(ord_val: int) -> bytes:
    """Format ordinal value as a string."""
    return f'ord{ord_val}'.encode()


def ordLookup(libname: Union[str, bytes], ord_val: int, make_name: bool = False) -> Optional[bytes]:
    """Lookup a name for the given ordinal if it's in our database."""
    if isinstance(libname, str):
        libname = libname.encode().lower()
    else:
        libname = libname.lower()
        
    names = ords.get(libname)
    if names is None:
        if make_name:
            return format_ord_string(ord_val)
        return None
    name = names.get(ord_val)
    if name is None:
        return format_ord_string(ord_val)
    return name
