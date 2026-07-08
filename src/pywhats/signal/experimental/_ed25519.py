# SPDX-License-Identifier: Apache-2.0
"""Minimal Ed25519 / Curve25519 point arithmetic for XEdDSA.

This is a small, self-contained reference implementation of the field and
group operations needed by XEdDSA. It is based on the public algorithms
described in RFC 8032 ("Edwards-Curve Digital Signature Algorithm (EdDSA)")
and RFC 7748 ("Elliptic Curves for Security"). No third-party Signal source
code was consulted.

WARNING: This is **not constant time**. It is intended for a reference /
experimental implementation only. See ``SECURITY.md``.
"""

from __future__ import annotations

# Curve25519 / Ed25519 constants (RFC 8032 / RFC 7748)
p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493  # group order
# d for twisted Edwards curve: -121665/121666 mod p
d = (-121665 * pow(121666, p - 2, p)) % p
# base point for Ed25519
_By = 4 * pow(5, p - 2, p) % p


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


def _recover_x(y: int, sign: int) -> int:
    """Recover x-coordinate from y and sign bit on Ed25519.

    Returns x with least-significant bit equal to ``sign``.
    """
    if y >= p:
        raise ValueError("y out of range")
    xx = (y * y - 1) * _inv(d * y * y + 1) % p
    # compute sqrt(xx) mod p where p = 5 (mod 8)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = x * pow(2, (p - 1) // 4, p) % p
    if (x * x - xx) % p != 0:
        raise ValueError("not on curve")
    if (x & 1) != sign:
        x = p - x
    return x


_Bx = _recover_x(_By, 0)
# Base point in extended coordinates (X, Y, Z, T) with T=XY/Z
B = (_Bx % p, _By % p, 1, (_Bx * _By) % p)


Point = tuple[int, int, int, int]


def _point_add(P: Point, Q: Point) -> Point:
    # RFC 8032 section 5.1.4 (extended homogeneous addition)
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = ((y1 - x1) * (y2 - x2)) % p
    Bv = ((y1 + x1) * (y2 + x2)) % p
    C = (t1 * 2 * d * t2) % p
    D = (z1 * 2 * z2) % p
    E = (Bv - A) % p
    F = (D - C) % p
    G = (D + C) % p
    H = (Bv + A) % p
    return ((E * F) % p, (G * H) % p, (F * G) % p, (E * H) % p)


def _scalar_mult(s: int, P: Point) -> Point:
    Q: Point = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P: Point, Q: Point) -> bool:
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    if (x1 * z2 - x2 * z1) % p != 0:
        return False
    if (y1 * z2 - y2 * z1) % p != 0:
        return False
    return True


def _point_compress(P: Point) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x = (x * zi) % p
    y = (y * zi) % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(data: bytes) -> Point | None:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    try:
        x = _recover_x(y, sign)
    except ValueError:
        return None
    return (x, y, 1, (x * y) % p)


def scalar_mult_base(s: int) -> Point:
    return _scalar_mult(s % q, B)


def encode_point(P: Point) -> bytes:
    return _point_compress(P)


def decode_point(b: bytes) -> Point | None:
    return _point_decompress(b)


def point_equal(P: Point, Q: Point) -> bool:
    return _point_equal(P, Q)


def point_add(P: Point, Q: Point) -> Point:
    return _point_add(P, Q)


def point_negate(P: Point) -> Point:
    x, y, z, t = P
    return ((-x) % p, y, z, (-t) % p)


def mont_u_to_ed_y(u: int) -> int:
    """Convert Montgomery u-coordinate to Edwards y-coordinate.

    y = (u - 1) / (u + 1) mod p  (birational map, RFC 7748 section 4.1).
    """
    return ((u - 1) * _inv(u + 1)) % p


def clamp_scalar(k: bytes) -> int:
    """RFC 7748 X25519 scalar clamping."""
    a = bytearray(k)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(bytes(a), "little")
