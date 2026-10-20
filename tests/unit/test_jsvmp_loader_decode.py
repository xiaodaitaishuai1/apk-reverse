"""Round-trip and known-vector tests for the jsvmp loader decoder.

The decoder implements the loader chain documented in
`skills/apk-reverse/references/jsvmp-recovery.md` (base64/hex -> varint -> ZigZag).
Its evidence is the round trip plus pinned byte layouts -- no real jsvmp target was
ever decoded in this repository, which is why these tests pin encodings that do not
depend on the encoder under test having written them.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills',
                                'apk-reverse', 'scripts'))

from jsvmp_loader_decode import (  # noqa: E402
    b64_to_bytes, decode_program, hex_to_bytes, main, varint_decode, varint_encode,
    zigzag_decode, zigzag_encode,
)


def test_zigzag_known_vectors():
    # The write-up's formula (n >> 1) ^ -(n & 1): neighbours interleave 0,1,2,3...
    assert [zigzag_decode(u) for u in (0, 1, 2, 3)] == [0, -1, 1, -2]
    assert [zigzag_encode(n) for n in (0, -1, 1, -2)] == [0, 1, 2, 3]
    assert zigzag_encode(-1) == 1 and zigzag_decode(1) == -1


def test_varint_known_layout():
    # Raw varint(300) = AC 02 is the canonical protobuf example; the decode-side layout
    # must not depend on this repository's encoder having produced it.
    assert varint_decode(b'\xac\x02') == [(0, 300)]
    assert varint_decode(b'\x7f\x80\x01') == [(0, 127), (1, 128)]
    # varint_encode is the full-chain encode side: it zigzags FIRST, so signed 300
    # encodes as zigzag(300)=600 -> D8 04 (and raw 600 would be AC 04, not AC 02).
    assert varint_encode([1, -1]) == b'\x02\x01'
    assert varint_encode([300]) == b'\xd8\x04'


def test_varint_truncation_raises():
    # A stream that ends mid-value is truncation (or not varint) -- it must raise
    # rather than silently decode short.
    for truncated in (b'\xac', b'\x80'):
        try:
            varint_decode(truncated)
        except ValueError:
            pass
        else:
            raise AssertionError('truncated varint %r decoded silently' % truncated)


def test_round_trip_random_and_extremes():
    import random
    rng = random.Random(7)
    values = [0, 1, -1, 127, -127, 128, -128, 2 ** 31 - 1, -(2 ** 31)]
    values += [rng.randrange(-(2 ** 31), 2 ** 31) for _ in range(500)]
    decoded = [v for _, v in decode_program(varint_encode(values))]
    assert decoded == values


def test_b64_and_hex_frontends():
    blob = varint_encode([1, -1, 300])
    import base64
    assert b64_to_bytes(base64.b64encode(blob).decode()) == blob
    # Stripped padding (the write-up's loader strips '=') must still decode.
    text = base64.b64encode(blob).decode().rstrip('=')
    assert b64_to_bytes(text) == blob
    assert hex_to_bytes(blob.hex().upper()) == blob


def test_cli_selftest_and_decode(capsys):
    assert main(['--selftest']) == 0
    assert 'OK' in capsys.readouterr().out
    encoded = varint_encode([5, -7])
    import base64
    rc = main(['--b64-string', base64.b64encode(encoded).decode(), '--json'])
    out = capsys.readouterr()
    assert rc == 0
    assert '"values": [5, -7]' in out.out
