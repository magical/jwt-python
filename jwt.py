u"""JSON Web Token"""

import base64
import json
import re

import M2Crypto
import hashlib
import hmac

from itertools import izip

KNOWN_TYPS = (u"JWT", u"http://openid.net/specs/jwt/1.0")

class UnknownAlgorithm(Exception):
    pass

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

# Stolen from Werkzeug
def safe_str_cmp(a, b):
    """Compare two strings in constant time."""
    if len(a) != len(b):
        return False
    r = 0
    for c, d in izip(a, b):
        r |= ord(c) ^ ord(d)
    return r == 0

def sha256_digest(msg):
    return hashlib.sha256(msg).digest()

def verify_rsa_sha256(msg, sig, key):
    return key.verify(sha256_digest(msg), sig, 'sha256')

def verify_hmac_sha256(msg, sig, key):
    h = hmac.new(key, msg, digestmod=hashlib.sha256)
    return safe_str_cmp(h.digest(), sig)


ALGS = {
    'HS256': verify_hmac_sha256,
    'RS256': verify_rsa_sha256,
}

def check(token, key):
    if isinstance(token, unicode):
        raise TypeError

    header_b64, claim_b64, crypto_b64 = split_token(token)

    header = b64d(header_b64)
    claim = b64d(claim_b64)
    crypto = b64d(crypto_b64)

    header = json.loads(header)
    if u'typ' in header:
        if header[u'typ'] not in KNOWN_TYPS:
            raise ValueError(header)

    alg = header[u'alg']
    if alg not in ALGS:
        raise UnknownAlgorithm(alg)

    sigdata = header_b64 + b'.' + claim_b64

    verifier = ALGS[alg]

    return verifier(sigdata, crypto, key)


def _sign(header, payload, alg, key):
    if u"alg" in header:
        raise ValueError("alg present", header)

    assert alg == u"RS256"

    header[u"alg"] = alg

    header_b64 = b64e(json.dumps(header))
    payload_b64 = b64e(payload)

    token = header_b64 + b"." + payload_b64
    sig = key.sign(sha256_digest(token), 'sha256')
    sig_b64 = b64e(sig)

    return token + b"." + sig_b64


def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)

def rsa_loads(key):
    """Read a PEM-encoded RSA key pair from a string."""
    return M2Crypto.RSA.load_key_str(key, M2Crypto.util.no_passphrase_callback)
