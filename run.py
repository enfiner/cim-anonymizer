# -*- coding: utf-8 -*-
"""Запуск:
  python run.py input.xml output.xml [--db mappings.db] [--shift-coords] [--no-ports]
  python run.py input.xml --analyze
  python run.py input.xml --make-test test.xml --lines 50000
  python run.py --validate input.xml output.xml
"""
import argparse
import re
import sys
from collections import Counter
from pathlib import Path


def analyze(path):
    from lxml import etree
    from anonymizer import local
    classes, props = Counter(), Counter()
    depth, n = 0, 0
    nsmap = {}
    for ev, el in etree.iterparse(path, events=("start", "end"),
                                  huge_tree=True, recover=True):
        if ev == "start":
            depth += 1
            if depth == 1:
                nsmap = dict(el.nsmap)
            continue
        if depth == 2:
            classes[local(el.tag)] += 1
            for ch in el:
                if isinstance(ch.tag, str):
                    props[local(ch.tag)] += 1
            n += 1
            el.clear()
            while el.getprevious() is not None:
                del el.getparent()[0]
            if n >= 300_000:
                break
        depth -= 1
    print("=== namespaces ===")
    for p, u in nsmap.items():
        print(f"  {p}: {u}")
    print("=== top classes ===")
    for k, v in classes.most_common(40):
        print(f"  {k}: {v}")
    print("=== top properties ===")
    for k, v in props.most_common(40):
        print(f"  {k}: {v}")


def make_test(path, out, lines):
    root = "rdf:RDF"
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fi, \
         open(out, "w", encoding="utf-8") as fo:
        for i, line in enumerate(fi):
            if i >= lines:
                break
            m = re.search(r"<(\w+:RDF)\b", line)
            if m:
                root = m.group(1)
            fo.write(line)
        fo.write(f"\n</{root}>\n")
    print(f"[OK] test fragment: {out} ({lines} lines)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output", nargs="?")
    ap.add_argument("--db", default="mappings.db")
    ap.add_argument("--salt", default=None)
    ap.add_argument("--shift-coords", action="store_true")
    ap.add_argument("--no-ports", action="store_true")
    ap.add_argument("--analyze", action="store_true")
    ap.add_argument("--make-test", metavar="OUT")
    ap.add_argument("--lines", type=int, default=50000)
    ap.add_argument("--validate", action="store_true")
    a = ap.parse_args()

    if not Path(a.input).exists():
        print("input not found:", a.input); sys.exit(1)

    if a.analyze:
        analyze(a.input); return
    if a.make_test:
        make_test(a.input, a.make_test, a.lines); return
    if a.validate:
        from validate import validate
        sys.exit(0 if validate(a.input, a.output) else 2)

    if not a.output:
        print("output required"); sys.exit(1)

    import config
    from anonymizer import CIMAnonymizer
    size = Path(a.input).stat().st_size / 1024 / 1024
    print(f"input : {a.input} ({size:.1f} MB)")
    print(f"output: {a.output}")
    print(f"db    : {a.db}")
    CIMAnonymizer(
        a.input, a.output, db=a.db,
        salt=a.salt or config.SALT,
        anon_ports=not a.no_ports,
        shift_coords=a.shift_coords,
    ).run()


if __name__ == "__main__":
    main()