# -*- coding: utf-8 -*-
"""Однопроходное потоковое обезличивание CIM RDF XML.
Память O(размера одного объекта). Вывод в UTF-8 (читаемая кириллица)."""
import base64
import hashlib
import random
import re
from lxml import etree

import config
from generators import Pseudonymizer

_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_MAGIC = {b"\x89PNG": "PNG", b"\xff\xd8\xff": "JPEG", b"%PDF": "PDF", b"PK\x03\x04": "ZIP/DOCX"}
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def local(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def ns_of(tag: str) -> str:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") else ""


class CIMAnonymizer:
    def __init__(self, inp, out, db="mappings.db", salt=config.SALT,
                 anon_ports=None, shift_coords=None):
        self.inp, self.out = str(inp), str(out)
        self.ps = Pseudonymizer(db, salt)
        self.anon_ports = config.ANON_PORTS if anon_ports is None else anon_ports
        self.shift_coords = config.SHIFT_COORDS if shift_coords is None else shift_coords
        r = random.Random(int(hashlib.sha256((salt + "|coords").encode()).hexdigest()[:16], 16))
        self.dx, self.dy = round(r.uniform(-0.5, 0.5), 6), round(r.uniform(-0.5, 0.5), 6)
        self.count = 0

    def map_ref(self, val: str) -> str:
        """Локальные '#_id' и 'urn:uuid:' -> детерминированная замена.
        Абсолютные http-URI (перечисления CIM) НЕ трогаем."""
        if val.startswith("#"):
            core = val[1:]
            pre = "_" if core.startswith("_") else ""
            body = core[1:] if pre else core
            new = self.ps.get(body, "uuid")
            if not pre and new[0].isdigit():
                pre = "_"
            return "#" + pre + new
        if val.startswith("urn:uuid:"):
            return "urn:uuid:" + self.ps.get(val[9:], "uuid")
        return val

    def free_text(self, text: str) -> str:
        for cat, pat in config.PATTERNS_PDN:
            text = pat.sub(lambda m: self.ps.get(m.group(0), cat), text)
        return text

    def process_object(self, el):
        cls = local(el.tag)
        category = config.CLASS_CATEGORY.get(cls, "object")
        pid = el.get(config.RDF_ABOUT) or el.get(config.RDF_ID) or ""
        ctx = {"person_id": pid} if category in ("person", "employee") else {}

        for attr in (config.RDF_ID, config.RDF_ABOUT):
            v = el.get(attr)
            if v is not None:
                el.set(attr, self.map_ref(v))

        for child in el:
            if not isinstance(child.tag, str):
                continue
            prop = local(child.tag)

            res = child.get(config.RDF_RESOURCE)
            if res is not None:
                child.set(config.RDF_RESOURCE, self.map_ref(res))
                continue

            txt = child.text
            if not txt or not txt.strip():
                continue

            # бинарные вложения (base64): тип по сигнатуре, замена заглушкой
            s = txt.strip()
            clean = s.replace("\n", "").replace("\r", "")
            if (len(clean) > 200 and " " not in clean and "\t" not in clean
                    and len(clean) % 4 == 0 and _B64.fullmatch(clean)):
                try:
                    raw = base64.b64decode(clean, validate=True)
                except Exception:
                    raw = b""
                if raw:
                    kind = next((v for k, v in _MAGIC.items() if raw.startswith(k)), "BIN")
                    child.text = base64.b64encode(
                        f"[ANONYMIZED {kind} ATTACHMENT]".encode()).decode()
                    continue

            rule = config.PROP_RULES.get(prop)
            # любое поле, содержащее name
            if rule is None and "name" in prop.lower():
                rule = "name_by_category"
            # строковые идентификаторы (mRIDStr и подобные)
            if rule is None and "mrid" in prop.lower():
                rule = "id_string"

            if prop in config.COORD_PROPS and self.shift_coords:
                try:
                    v = float(txt)
                    child.text = str(round(v + (self.dx if prop.endswith("xPosition") else self.dy), 6))
                except ValueError:
                    pass
                continue

            if rule is None:
                if category in ("person", "employee", "organization"):
                    child.text = self.free_text(txt)
                continue

            if rule == "name_by_category":
                if category in ("person", "employee"):
                    child.text = self.ps.get(txt, "fio", **ctx)
                elif category == "organization":
                    child.text = self.ps.get(txt, "org_name")
                else:
                    child.text = self.ps.get(txt, "object_name")
            elif rule == "mrid":
                pre = "_" if txt.strip().startswith("_") else ""
                child.text = pre + self.ps.get(txt.strip().lstrip("_"), "uuid")
            elif rule == "id_string":
                v = txt.strip()
                if _UUID_RE.fullmatch(v):
                    child.text = self.ps.get(v, "uuid")
                else:
                    child.text = self.ps.get(txt, "object_name")
            elif rule == "port":
                if self.anon_ports:
                    try:
                        p = int(txt.strip())
                        if 1 <= p <= 65535:
                            child.text = self.ps.get(txt, "port")
                    except ValueError:
                        pass
            elif rule == "free_text":
                child.text = self.free_text(txt)
            elif rule == "ext_link":
                child.text = self.ps.get(txt, "authority")
            elif rule == "file_name":
                stem, dot, ext = txt.rpartition(".")
                if dot and 1 <= len(ext) <= 5:
                    child.text = self.ps.get(stem, "object_name") + "." + ext
                else:
                    child.text = self.ps.get(txt, "object_name")
            else:
                child.text = self.ps.get(txt, rule, **ctx)

    @staticmethod
    def _root_qname(root):
        uri, name = ns_of(root.tag), local(root.tag)
        for p, u in root.nsmap.items():
            if u == uri and p:
                return f"{p}:{name}"
        return name

    def _open_tag(self, root):
        parts = [self._root_qname(root)]
        for p, u in root.nsmap.items():
            parts.append(f'xmlns:{p}="{u}"' if p else f'xmlns="{u}"')
        return ("<" + " ".join(parts) + ">\n").encode("utf-8")

    def run(self):
        depth = 0
        root_qname = None
        with open(self.out, "wb") as f:
            f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
            context = etree.iterparse(self.inp, events=("start", "end"),
                                      huge_tree=True, recover=True)
            for event, el in context:
                if event == "start":
                    depth += 1
                    if depth == 1:
                        root_qname = self._root_qname(el)
                        f.write(self._open_tag(el))
                    continue

                if depth == 2:
                    self.process_object(el)
                    f.write(etree.tostring(el, encoding="utf-8"))
                    self.count += 1
                    if self.count % 100_000 == 0:
                        print(f"  objects: {self.count}")
                    el.clear()
                    while el.getprevious() is not None:
                        del el.getparent()[0]
                elif depth == 1:
                    f.write(f"\n</{root_qname}>\n".encode("utf-8"))
                depth -= 1
        self.ps.close()
        print(f"[OK] objects processed: {self.count}")