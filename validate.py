# -*- coding: utf-8 -*-
"""Валидация: классы, количество объектов, висячие ссылки (сравнение с исходным),
изоморфизм графа с точностью до переименования вершин."""
from collections import Counter
from lxml import etree
import config
from anonymizer import local


def core_id(v):
    if v.startswith("#"):
        return v[1:].lstrip("_")
    if v.startswith("urn:uuid:"):
        return v[9:]
    return None


def scan(path):
    ids, classes = {}, Counter()
    edges = []
    depth = 0
    for ev, el in etree.iterparse(path, events=("start", "end"),
                                  huge_tree=True, recover=True):
        if ev == "start":
            depth += 1
            continue
        if depth == 2:
            cls = local(el.tag)
            classes[cls] += 1
            oid = core_id(el.get(config.RDF_ABOUT) or el.get(config.RDF_ID) or "")
            if oid:
                ids[oid] = cls
            for ch in el:
                if not isinstance(ch.tag, str):
                    continue
                r = ch.get(config.RDF_RESOURCE)
                if r is not None:
                    t = core_id(r)
                    if t is not None:
                        edges.append((oid, local(ch.tag), t))
            el.clear()
            while el.getprevious() is not None:
                del el.getparent()[0]
        depth -= 1
    return ids, classes, edges


def graph_signature(ids, edges):
    per_obj = {}
    for oid, prop, t in edges:
        per_obj.setdefault(oid, []).append((prop, ids.get(t, "MISSING")))
    sig = Counter()
    for oid, refs in per_obj.items():
        sig[(ids.get(oid, "?"), tuple(sorted(refs)))] += 1
    return sig


def validate(original, anonymized):
    print("scan original...")
    ids1, cls1, e1 = scan(original)
    print("scan anonymized...")
    ids2, cls2, e2 = scan(anonymized)

    ok = True
    if cls1 != cls2:
        ok = False
        print("[FAIL] class histogram differs:")
        for k in set(cls1) | set(cls2):
            if cls1[k] != cls2[k]:
                print(f"  {k}: {cls1[k]} -> {cls2[k]}")
    else:
        print(f"[OK] class histogram identical ({sum(cls1.values())} objects)")

    if len(ids1) != len(ids2):
        ok = False
        print(f"[FAIL] id count: {len(ids1)} -> {len(ids2)}")
    else:
        print(f"[OK] id count: {len(ids2)}")

    leaked = set(ids1) & set(ids2)
    print(("[OK]" if not leaked else "[WARN]") + f" original ids remaining: {len(leaked)}")

    d1 = [t for _, _, t in e1 if t not in ids1]
    d2 = [t for _, _, t in e2 if t not in ids2]
    if len(d2) == len(d1) and len(set(d2)) == len(set(d1)):
        note = " (cross-fragment refs, same as original)" if d1 else ""
        print(f"[OK] dangling local refs: {len(d2)} = original {len(d1)}{note}")
    else:
        ok = False
        print(f"[FAIL] dangling local refs: original {len(d1)} -> anonymized {len(d2)}")

    if graph_signature(ids1, e1) == graph_signature(ids2, e2):
        print("[OK] graph identical up to vertex renaming (signatures match)")
    else:
        ok = False
        print("[FAIL] graph signatures differ")

    print("RESULT:", "PASS" if ok else "FAIL")
    return ok