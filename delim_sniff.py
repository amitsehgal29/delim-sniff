#!/usr/bin/env python3
"""Sniff the raw format of a delimited text file before loading it.

Reports encoding guess, BOM, line endings, delimiter, quote char,
header presence and whether every row has the same field count.
"""
import argparse, csv, io, json, sys

CANDIDATES = [",", ";", "\t", "|"]

def detect_bom(raw):
    for bom, name in [(b"\xef\xbb\xbf", "utf-8-sig"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")]:
        if raw.startswith(bom):
            return name
    return None

def detect_encoding(raw):
    bom = detect_bom(raw)
    if bom:
        return bom
    try:
        raw.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError:
        return "latin-1"

def line_endings(raw):
    crlf = raw.count(b"\r\n")
    lf = raw.count(b"\n") - crlf
    cr = raw.count(b"\r") - crlf
    kinds = {k: v for k, v in {"CRLF": crlf, "LF": lf, "CR": cr}.items() if v}
    if not kinds:
        return "none"
    return next(iter(kinds)) if len(kinds) == 1 else "mixed"

def best_delimiter(text):
    lines = [l for l in text.splitlines() if l.strip()][:50]
    best, score = ",", -1
    for d in CANDIDATES:
        counts = [len(r) for r in csv.reader(io.StringIO("\n".join(lines)), delimiter=d)]
        if not counts or max(counts) < 2:
            continue
        s = counts.count(max(set(counts), key=counts.count)) * max(counts)
        if s > score:
            best, score = d, s
    return best

def sniff(raw):
    enc = detect_encoding(raw)
    text = raw.decode(enc)
    delim = best_delimiter(text)
    rows = list(csv.reader(io.StringIO(text), delimiter=delim))
    rows = [r for r in rows if r]
    widths = sorted({len(r) for r in rows})
    quote = '"' if '"' in text else ("'" if "'" in text else None)
    try:
        header = csv.Sniffer().has_header(text[:4096])
    except csv.Error:
        header = None
    return {
        "encoding": enc, "bom": detect_bom(raw) is not None,
        "line_endings": line_endings(raw), "delimiter": delim,
        "quote_char": quote, "has_header": header, "rows": len(rows),
        "field_counts": widths, "ragged": len(widths) > 1,
    }

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path")
    a = p.parse_args(argv)
    with open(a.path, "rb") as f:
        res = sniff(f.read())
    print(json.dumps(res, indent=2))
    return 1 if res["ragged"] else 0

if __name__ == "__main__":
    sys.exit(main())
