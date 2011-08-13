"""Tests for the jwt module."""

from nose.tools import assert_raises
import array

import jwt

def bytes(b):
    if isinstance(b, str):
        return b
    return array.array("B", b).tostring()


def test():
    # miscellaneous tests

    assert_raises(TypeError, lambda: jwt.check(u"unicode string", b""))
    # {"typ":"foo"}
    assert_raises(jwt.BadType, lambda: jwt.verify(b"eyJ0eXAiOiJmb28ifQ..", None))

def test_split():
    # too few/many dots
    assert_raises(jwt.BadSyntax, lambda: jwt.split_token(b""))
    assert_raises(jwt.BadSyntax, lambda: jwt.split_token(b"a.b"))
    assert_raises(jwt.BadSyntax, lambda: jwt.split_token(b"a.b.c.d"))

    assert jwt.split_token(b"a.b.c") == (b"a", b"b", b"c")

    # XXX should empty segments be allowed?
    jwt.split_token(b"..")

def test_b64():
    # invalid chars
    assert_raises(jwt.BadSyntax, lambda: jwt.b64d(b"!&#$%"))
    assert_raises(jwt.BadSyntax, lambda: jwt.b64d(b"AAA A"))
    assert_raises(jwt.BadSyntax, lambda: jwt.b64d(b"   AAAA   "))

    # implicit padding
    assert jwt.b64d(b"AAAA") == b"\x00\x00\x00"
    assert jwt.b64d(b"AAA") == b"\x00\x00"
    assert jwt.b64d(b"AA") == b"\x00"

    assert jwt.b64e(b"\x00\x00\x00") == b"AAAA"
    assert jwt.b64e(b"\x00\x00") == b"AAA"
    assert jwt.b64e(b"\x00") == b"AA"

    # explicit padding
    assert_raises(jwt.BadSyntax, lambda: jwt.b64d(b"AA=="))
    assert_raises(jwt.BadSyntax, lambda: jwt.b64d(b"AAA="))

    # invalid length
    assert_raises(jwt.BadSyntax, lambda: jwt.b64d(b"A"))

def test_hmac():
    key = bytes([3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163])

    # Example from the JWS spec
    assert jwt.check(b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", key)
    assert not jwt.check(b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", key)

    assert jwt.check(jwt.sign(u'HS256', u"test", key), key)
    assert jwt.check(jwt.sign(u'HS384', u"test", key), key)
    assert jwt.check(jwt.sign(u'HS512', u"test", key), key)

def test_check_rsa():
    key = jwt.rsa_load("rsakey.pem")

    # Example from the JWS spec
    assert jwt.check(b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw", key)
    assert not jwt.check(b"eyJhbGciOiJSUzI1NiJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw", key)

    # XXX Should test the Signer classes directly. The check(sign()) dance
    # doesn't really verify that the correct algorithm was used, or that the
    # algorithm was implemented properly.
    assert jwt.check(jwt.sign(u'RS256', u"test", key), key)
    assert jwt.check(jwt.sign(u'RS384', u"test", key), key)
    assert jwt.check(jwt.sign(u'RS512', u"test", key), key)

def test_ecdsa_sha256():
    key = jwt.ec_load("eckey.pem")

    # Example from the JWS spec
    assert jwt.check(b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q", key)
    assert not jwt.check(b"eyJhbGciOiJFUzI1NiJ9.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q", key)

    assert jwt.check(jwt.sign(u'ES256', u"test", key), key)

def test_sign():
    assert_raises(jwt.UnknownAlgorithm,
        lambda: jwt.sign(u'foobar', u"test", key=None))
