"""Tests for the jwt module."""

from nose.tools import assert_raises
import array

import jwt

def bytes(b):
    if isinstance(b, str):
        return b
    return array.array("B", b).tostring()


def test():
    assert_raises(TypeError, lambda: jwt.check(u"unicode string", b""))

def test_split():
    # too few/many dots
    assert_raises(ValueError, lambda: jwt.split_token(b""))
    assert_raises(ValueError, lambda: jwt.split_token(b"a.b"))
    assert_raises(ValueError, lambda: jwt.split_token(b"a.b.c.d"))

    jwt.split_token(b"..")

def test_b64():
    # invalid chars
    assert_raises(ValueError, lambda: jwt.b64d(b"!&#$%"))
    assert_raises(ValueError, lambda: jwt.b64d(b"AAA A"))
    assert_raises(ValueError, lambda: jwt.b64d(b"   AAAA   "))

    # implicit padding
    jwt.b64d(b"AAAA")
    jwt.b64d(b"AAA")
    jwt.b64d(b"AA")

    # explicit padding
    assert_raises(ValueError, lambda: jwt.b64d(b"AA=="))
    assert_raises(ValueError, lambda: jwt.b64d(b"AAA="))

    # invalid length
    assert_raises(ValueError, lambda: jwt.b64d(b"A"))

def test_hmac_sha256():
    key = bytes([3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163])

    # Example from the JWS spec
    assert jwt.check(b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", key)

def test_check_rsa():
    key = jwt.rsa_load("rsakey.pem")

    # Example from the JWS spec
    assert jwt.check(b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw", key)

    assert jwt.check(b"eyJhbGciOiJSUzM4NCJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.UqgNjrJOGhk4wfoSG6Uvrt9GcKu-TgPwInExALrMBadg1pol1uTw7mZADTddAWsC6ZzdFiTFUmIi7DuD38ftLAZoW4qezdAO7RYf1yZDsbT20bt8DJJN1I4VovL2PLg80B6x6ug-kaW8k5LaM5ce0dk1zgWhjafKC3Mb4UNLL8f9fqVMkHpdWYRjF6QjTz12Ap-gq-tPyUoWSdvzCIYOcZ9-08SQQdUTTgsNF1Qwu3TqeWPqzNJwmWHiHMmaV8I4ktMFEX-AiEBa55KsfYTx0jSbTHP-odqmnLQJ4n-oQJ2RSXy0HQP6BkdiwDHdoMUk4z_wAeOsfDTs_mLxTgOInQ", key)

def test_ecdsa_sha256():
    key = jwt.ec_load("eckey.pem")

    # Example from the JWS spec
    assert jwt.check(b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q", key)

def test_sign():
    key = jwt.rsa_load("rsakey.pem")
    hmac_key = bytes([3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166, 143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80, 46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119, 98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103, 208, 128, 163])

    assert jwt._sign(u'HS256', '{"typ":"JWT",\r\n "alg":"HS256"}', '{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}', hmac_key) == b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    assert jwt._sign(u'RS256', b'{"alg": "RS256"}', b"test", key=key) == b'A_D3oXlHQLD9NQGL7DSE5IzMRlEhhr1FCZoMKSkpvTokmax9tdQTR7oSyyrlEsHzJvhBMMCU9nCXEv6Xj8TiNRn69X76UsfMnhz0-a6mVVURXe_GB60WH-T9j-WBdP9fvnJkvDcJycVzvBUWct0lX9A0yZJiFTAjyHvhbsmu9wTM8GmSkmOGCqaT6DSFUtUjsqNyEqlFSqhTsMrL3oTchr4nk5p8N-EqfR3b1kKzuPhmcfdsC9PcskDEfg7WJrYFVpW78L5TyJ6iLIa8GEdZIDz9bVO47xI8TKU5WKTzJ4zdI1DFobqds7BNeLIPxvAnDcyC1WDcBc5Lt5ZC3zIrMQ'

    assert_raises(jwt.UnknownAlgorithm,
        lambda: jwt._sign(u'foobar', b'', b"test", key=None))
