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

    assert jwt.check(b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", key)

def test_rsa_sha256():
    import M2Crypto.RSA
    from struct import pack

    def mpint(b):
        b = "\x00" + bytes(b)
        return pack(">L", len(b)) + b

    def rsa_key(n, e):
        return M2Crypto.RSA.new_pub_key((mpint(e), mpint(n)))

    n = [161, 248, 22, 10, 226, 227, 201, 180, 101, 206, 141, 45, 101, 98, 99, 54, 43, 146, 125, 190, 41, 225, 240, 36, 119, 252, 22, 37, 204, 144, 161, 54, 227, 139, 217, 52, 151, 197, 182, 234, 99, 221, 119, 17, 230, 124, 116, 41, 249, 86, 176, 251, 138, 143, 8, 154, 220, 75, 105, 137, 60, 193, 51, 63, 83, 237, 208, 25, 184, 119, 132, 37, 47, 236, 145, 79, 228, 133, 119, 105, 89, 75, 234, 66, 128, 211, 44, 15, 85, 191, 98, 148, 79, 19, 3, 150, 188, 110, 155, 223, 110, 189, 210, 189, 163, 103, 142, 236, 160, 198, 104, 247, 1, 179, 141, 191, 251, 56, 200, 52, 44, 226, 254, 109, 39, 250, 222, 74, 90, 72, 116, 151, 157, 212, 185, 207, 154, 222, 196, 199, 91, 5, 133, 44, 44, 15, 94, 248, 165, 193, 117, 3, 146, 249, 68, 232, 237, 100, 193, 16, 198, 182, 71, 96, 154, 164, 120, 58, 235, 156, 108, 154, 215, 85, 49, 48, 80, 99, 139, 131, 102, 92, 111, 111, 122, 130, 163, 150, 112, 42, 31, 100, 27, 130, 211, 235, 242, 57, 34, 25, 73, 31, 182, 134, 135, 44, 87, 22, 245, 10, 248, 53, 141, 154, 139, 157, 23, 195, 64, 114, 143, 127, 135, 216, 154, 24, 216, 252, 171, 103, 173, 132, 89, 12, 46, 207, 117, 147, 57, 54, 60, 7, 3, 77, 111, 96, 111, 158, 33, 224, 84, 86, 202, 229, 233, 161]
    e = [1, 0, 1]
    key = rsa_key(n, e)

    assert jwt.check(b"eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw", key)


def test_sign():
    jwt._sign({}, b"test", alg=u'RS256', key=jwt.rsa_load("rsakey.pem"))

    assert_raises(jwt.UnknownAlgorithm,
        lambda: jwt._sign({}, b"test", alg=u'foobar', key=None))
