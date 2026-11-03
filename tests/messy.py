"""Seeded damage to real log and manifest bytes, the way evidence arrives in practice.

Logs out of time order, error lines mixed into an access log, cut lines, broken UTF-8,
NUL bytes, CRLF, a rotated .gz cut short, manifests with broken rows. The analysis must
never stop on such input: it reads what it can and reports the rest as unreadable (D96).
"""

import gzip
import random

JUNK = [
    b"\x00\x00\x00", b"\xff\xfe\xfd garbage", b"sh: 1: /usr/sbin/sendmail: not found",
    b"[Thu Jan 14 07:42:17.055410 2021] [php7:error] [pid 22] [client 1.2.3.4:5] x",
    b"A" * 200_000,
    b'\xef\xbb\xbf1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',
    b'1.2.3.4 - - [99/Foo/2026:25:61:61 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',
    b'1.2.3.4 - - [01/Jan/1970:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',
    b'1.2.3.4 - - [31/Dec/2099:23:59:59 +1400] "POST /x.php HTTP/1.1" 200 - "-" "-"',
    b'::1 - - [01/Jan/2026:00:00:00 -1200] "GET /%%%zz HTTP/1.1" 999 -5 "-" "-"',
    b'not-an-ip - - [01/Jan/2026:00:00:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"',
    b'1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "-" 408 0 "-" "-"',
]
LOG_OPS = ("shuffle", "reverse", "junk", "truncate", "dup", "crlf", "badutf", "drop",
           "swapts", "empty", "onlyjunk", "nul")
MANIFEST_OPS = ("junkrow", "dropcol", "badhex", "badtime", "badint", "duprow", "crlf",
                "shuffle")


def damage_log(data: bytes, rng: random.Random) -> bytes:
    lines = data.split(b"\n")
    for _ in range(rng.randint(1, 4)):
        op = rng.choice(LOG_OPS)
        if not lines:
            break
        i = rng.randrange(len(lines))
        if op == "shuffle":
            j = min(len(lines), i + rng.randint(2, 50))
            chunk = lines[i:j]
            rng.shuffle(chunk)
            lines[i:j] = chunk
        elif op == "reverse":
            lines.reverse()
        elif op == "junk":
            for _ in range(rng.randint(1, 5)):
                lines.insert(rng.randrange(len(lines) + 1), rng.choice(JUNK))
        elif op == "truncate":
            lines[i] = lines[i][: rng.randrange(len(lines[i]) + 1)]
        elif op == "dup":
            lines[i:i] = [lines[i]] * rng.randint(1, 3)
        elif op == "crlf":
            lines = [x + b"\r" if rng.random() < 0.5 else x for x in lines]
        elif op == "badutf":
            lines[i] = lines[i].replace(b"/", b"/\xc3\x28", 1)
        elif op == "drop":
            del lines[i: i + rng.randint(1, 20)]
        elif op == "swapts":
            j = rng.randrange(len(lines))
            a, b = lines[i], lines[j]
            if b"[" in a and b"[" in b:
                ta, tb = a.split(b"[", 1)[1][:26], b.split(b"[", 1)[1][:26]
                lines[i], lines[j] = a.replace(ta, tb, 1), b.replace(tb, ta, 1)
        elif op == "empty":
            lines = []
        elif op == "onlyjunk":
            lines = [rng.choice(JUNK) for _ in range(rng.randint(1, 10))]
        elif op == "nul":
            lines[i] = lines[i][:5] + b"\x00" + lines[i][5:]
    return b"\n".join(lines)


def damage_manifest(data: bytes, rng: random.Random) -> bytes:
    lines = data.split(b"\n")
    for _ in range(rng.randint(1, 3)):
        op = rng.choice(MANIFEST_OPS)
        rows = [k for k, x in enumerate(lines) if x and not x.startswith(b"#")]
        if not rows:
            break
        k = rng.choice(rows)
        cols = lines[k].split(b"\t")
        if op == "junkrow":
            lines.insert(k, rng.choice([b"garbage", b"\t\t\t", b"zz\tf\t1"]))
        elif op == "dropcol" and len(cols) > 2:
            del cols[rng.randrange(len(cols))]
            lines[k] = b"\t".join(cols)
        elif op == "badhex":
            cols[0] = b"zz" + cols[0]
            lines[k] = b"\t".join(cols)
        elif op == "badtime" and len(cols) > 8:
            cols[rng.choice([6, 7, 8])] = rng.choice([b"-5", b"0", b"99999999999", b"1.5",
                                                      b"1e308", b"nan"])
            lines[k] = b"\t".join(cols)
        elif op == "badint" and len(cols) > 3:
            cols[2] = b"abc"
            lines[k] = b"\t".join(cols)
        elif op == "duprow":
            lines.insert(k, lines[k])
        elif op == "crlf":
            lines = [x + b"\r" for x in lines]
        elif op == "shuffle":
            body = [lines[r] for r in rows]
            rng.shuffle(body)
            for r, x in zip(rows, body, strict=True):
                lines[r] = x
    return b"\n".join(lines)


def cut_gzip(data: bytes) -> bytes:
    """A compressed log copied only halfway."""
    packed = gzip.compress(data)
    return packed[: max(10, len(packed) // 2)]
