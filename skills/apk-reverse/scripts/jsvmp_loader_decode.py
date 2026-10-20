#!/usr/bin/env python3
"""Decode a jsvmp program literal: base64/hex -> varint -> ZigZag -> signed integers.

The register-machine jsvmp family documented in `references/jsvmp-recovery.md` ships its
guest program as an encoded integer stream. The write-up's loader chain is three standard
stages, each recognisable by fingerprint and each invertible without the target:

  1. base64 (or hex) text -> unsigned byte array
  2. varint groups: each byte contributes its low 7 bits; a set high bit continues
  3. ZigZag decode per accumulated integer: (n >> 1) ^ -(n & 1)  (unsigned -> signed)

This script implements the decode side **and** the encode side, so the chain can be proven
against its own round trip (`--selftest`), which is the only evidence this repository has
for it: no real jsvmp target was ever decoded here. When a target's loader differs, expect
the difference in stage order or byte-signedness conventions (the write-up read the byte
array as *signed* int8, where "high bit set" surfaces as a negative value -- the same bits),
not in the stage identities.

Output: one decoded integer per line with its input offset, plus a summary. Feed the result
to your disassembler stage (`program.bin` in `references/jsvmp-recovery.md` §9).

Examples:
    python scripts/jsvmp_loader_decode.py --b64-string 'JgQCFhoEBBZEHgASPkQEZp/4A4PzAg=='
    python scripts/jsvmp_loader_decode.py --hex-string 484e4f4a403f5243 --json
    python scripts/jsvmp_loader_decode.py --selftest
"""
import argparse
import base64
import json
import sys


def zigzag_decode(n):
    """Unsigned -> signed ((n >> 1) ^ -(n & 1)), the standard ZigZag mapping."""
    return (n >> 1) ^ -(n & 1)


def zigzag_encode(n):
    """Signed -> unsigned ZigZag. Python ints are unbounded, so any width works."""
    return (n << 1) ^ (n >> 63) if n < 0 else (n << 1)


def b64_to_bytes(text):
    """base64 text -> bytes, tolerant of stripped padding and whitespace."""
    cleaned = ''.join(text.split())
    pad = (-len(cleaned)) % 4
    return base64.b64decode(cleaned + '=' * pad)


def hex_to_bytes(text):
    cleaned = ''.join(text.split())
    if len(cleaned) % 2:
        raise ValueError('hex string has an odd length: %d' % len(cleaned))
    return bytes.fromhex(cleaned)


def varint_decode(data, shift_step=7):
    """Byte stream -> list of (offset, unsigned_value).

    Each byte contributes its low `shift_step` bits; a set high bit means "continue".
    Raises on a stream that ends mid-value -- truncation is a finding, not a zero.
    """
    out = []
    value = 0
    shift = 0
    start = 0
    for i, byte in enumerate(data):
        value |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += shift_step
            continue
        out.append((start, value))
        value = 0
        shift = 0
        start = i + 1
    if value or shift:
        raise ValueError('varint stream ends mid-value at offset %d '
                         '(truncated input, or this is not varint)' % start)
    return out


def varint_encode(values):
    """Signed integers -> varint byte stream (ZigZag first), the encode side of the chain."""
    out = bytearray()
    for n in values:
        u = zigzag_encode(n)
        while True:
            byte = u & 0x7F
            u >>= 7
            if u:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
    return bytes(out)


def decode_program(data):
    """Raw bytes -> decoded signed integers (the full chain stages 2+3)."""
    return [(off, zigzag_decode(u)) for off, u in varint_decode(data)]


def selftest():
    """Round-trip proof: encode -> decode must be exact on fixed and random vectors."""
    import random
    cases = [
        [0],
        [1, -1, 2, -2],                 # zigzag neighbours: 0,1,2,3 unsigned
        [127, 128, -128, 129, -129],    # varint width boundaries
        [300, -300, 16383, 16384],      # 2- and 3-byte varints
        [2 ** 31 - 1, -(2 ** 31)],      # int32 extremes
    ]
    rng = random.Random(20240901)
    cases.append([rng.randrange(-(2 ** 31), 2 ** 31) for _ in range(2000)])
    for values in cases:
        encoded = varint_encode(values)
        decoded = [v for _, v in decode_program(encoded)]
        if decoded != values:
            print('FAIL round trip: %r -> %d bytes -> %d values (first divergence at index %d)'
                  % (values[:8], len(encoded), len(decoded),
                     next(i for i, (a, b) in enumerate(zip(values, decoded)) if a != b)))
            return 1
    # Known byte layouts pin the layout, not just self-consistency. Raw varint(300) = AC 02
    # (pinned through varint_decode below is the decode side); the full chain zigzags FIRST,
    # so encoding signed 300 means encoding zigzag(300)=600 -> D8 04.
    assert varint_encode([1, -1]) == b'\x02\x01', varint_encode([1, -1])
    assert varint_encode([300]) == b'\xd8\x04', varint_encode([300])
    assert varint_decode(b'\xac\x02') == [(0, 300)]
    # Truncated input must raise rather than silently decode short.
    try:
        varint_decode(b'\xac')
    except ValueError:
        pass
    else:
        print('FAIL: truncated varint did not raise')
        return 1
    total = sum(len(c) for c in cases)
    print('OK: %d values round-tripped exactly (encode->varint->zigzag->decode), '
          'known byte layouts pinned, truncation raises' % total)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Decode a jsvmp program literal (base64/hex -> varint -> ZigZag). '
                    'See references/jsvmp-recovery.md for the loader chain and its limits.')
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--b64-string', help='base64 program literal on the command line')
    src.add_argument('--b64-file', help='file containing the base64 program literal')
    src.add_argument('--hex-string', help='hex program literal (two chars per byte) on the command line')
    src.add_argument('--hex-file', help='file containing the hex program literal')
    src.add_argument('--bytes-file', help='file containing the raw already-decoded byte stream')
    src.add_argument('--selftest', action='store_true',
                     help='prove the encode/decode round trip on fixed and random vectors, then exit')
    ap.add_argument('--json', action='store_true', help='emit a JSON object instead of lines')
    ap.add_argument('--limit', type=int, default=0,
                    help='stop after N decoded values (0 = all)')
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.b64_string is not None:
        data = b64_to_bytes(args.b64_string)
    elif args.b64_file is not None:
        data = b64_to_bytes(open(args.b64_file, encoding='utf-8').read())
    elif args.hex_string is not None:
        data = hex_to_bytes(args.hex_string)
    elif args.hex_file is not None:
        data = hex_to_bytes(open(args.hex_file, encoding='utf-8').read())
    else:
        data = open(args.bytes_file, 'rb').read()

    try:
        decoded = decode_program(data)
    except ValueError as exc:
        print('error: %s' % exc, file=sys.stderr)
        return 2

    if args.limit:
        decoded = decoded[:args.limit]
    if args.json:
        print(json.dumps({
            'input_bytes': len(data),
            'values': [v for _, v in decoded],
            'min': min((v for _, v in decoded), default=None),
            'max': max((v for _, v in decoded), default=None),
        }))
    else:
        for off, value in decoded:
            print('%6d  %d' % (off, value))
        print('# %d values from %d bytes (opcode stream starts here; '
              'stage identities and caveats: references/jsvmp-recovery.md §6)'
              % (len(decoded), len(data)), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
