"""Tests for the jwt module."""

from nose.tools import assert_raises

import jwt

def test():
    assert_raises(TypeError, lambda: jwt.check(u"unicode string"))

    # too few/many dots
    assert_raises(ValueError, lambda: jwt.check(b""))
    assert_raises(ValueError, lambda: jwt.check(b"a.b"))
    assert_raises(ValueError, lambda: jwt.check(b"a.b.c.d"))

    jwt.check(b"..")

    # invalid base64 encoding
    assert_raises(ValueError, lambda: jwt.check(b"!!.$$.&&"))

    jwt.check(b"AAAA.AAA.AA")

def test_b64d():
    # invalid chars
    assert_raises(ValueError, lambda: jwt.b64d(b"!!!!"))
    assert_raises(ValueError, lambda: jwt.b64d(b" AA A A"))

    # padding present
    assert_raises(ValueError, lambda: jwt.b64d(b"AA=="))

    # invalid length
    assert_raises(ValueError, lambda: jwt.b64d(b"A"))
