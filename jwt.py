u"""JSON Web Token"""

import base64
import re

def b64e(b):
    u"""Base64 encode some bytes.

    Uses the url-safe - and _ characters, and doesn't pad with = characters."""
    return base64.urlsafe_b64encode(b).rstrip(b"=")

_b64_re = re.compile(b"^[A-Za-z0-9_-]*$")
def b64d(b):
    u"""Decode some base64-encoded bytes.

    Raises ValueError if the string contains invalid characters or padding."""

    # Python's base64 functions ignore invalid characters, so we need to
    # check for them explicitly.
    if not _b64_re.match(b):
        raise ValueError(b)

    # add padding chars
    m = len(b) % 4
    if m == 1:
        raise ValueError(b)
    elif m == 2:
        b += b"=="
    elif m == 3:
        b += b"="
    return base64.urlsafe_b64decode(b)

def split_token(token):
    l = token.split(b".")
    if len(l) != 3:
        raise ValueError
    return tuple(l)

def check(token):
    if isinstance(token, unicode):
        raise TypeError

    header, claim, crypto = split_token(token)

    header = b64d(header)
    claim = b64d(claim)
    crypto = b64d(crypto)
