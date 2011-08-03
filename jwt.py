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

class Signer(object):
    """Abstract base class for signing algorithms."""
    def sign(msg, key):
        raise NotImplementedError

    def verify(msg, sig, key):
        raise NotImplementedError

class HMACSigner(Signer):
    def __init__(self, digest):
        self.digest = digest

    def verify(self, msg, sig, key):
        h = hmac.new(key, msg, digestmod=self.digest)
        return safe_str_cmp(h.digest(), sig)

class RSASigner(Signer):
    def __init__(self, algo, digest):
        self.algo = algo
        self.digest = digest

    def sign(self, msg, key):
        return key.sign(self.digest(msg), self.algo)

    def verify(self, msg, sig, key):
        return key.verify(self.digest(msg), sig, self.algo)

ALGS = {
    'HS256': HMACSigner(hashlib.sha256),
    'RS256': RSASigner('sha256', sha256_digest),
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

    return verifier.verify(sigdata, crypto, key)


def _sign(header, payload, alg, key):
    if u"alg" in header:
        raise ValueError("alg present", header)

    if not alg in ALGS:
        raise UnknownAlgorithm(alg)

    header[u"alg"] = alg

    header_b64 = b64e(json.dumps(header))
    payload_b64 = b64e(payload)

    token = header_b64 + b"." + payload_b64

    signer = ALGS[alg]
    sig = signer.sign(token, key)
    sig_b64 = b64e(sig)

    return sig_b64


def rsa_load(filename):
    """Read a PEM-encoded RSA key pair from a file."""
    return M2Crypto.RSA.load_key(filename, M2Crypto.util.no_passphrase_callback)

def rsa_loads(key):
    """Read a PEM-encoded RSA key pair from a string."""
    return M2Crypto.RSA.load_key_str(key, M2Crypto.util.no_passphrase_callback)
