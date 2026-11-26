# -*- coding: utf-8 -*-
"""Детерминированный движок псевдонимизации.
seed = SHA-256(salt | category | original | attempt) -> random.Random
Маппинги в SQLite: стабильность между запусками + UNIQUE для ключевых категорий."""
import hashlib
import random
import re
import sqlite3
from collections import OrderedDict

import config
import dictionaries as D

_TOKEN = re.compile(r"[A-Za-zА-Яа-яЁё]+|\d+")
_UNITS = {"kv", "кв", "гц", "hz", "мва", "kva", "мв", "мвар", "в", "а", "вт", "вар", "км", "м"}


class Pseudonymizer:
    def __init__(self, db_path: str, salt: str = config.SALT):
        self.salt = salt
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.execute("PRAGMA cache_size=-64000")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS map("
            "key TEXT PRIMARY KEY, val TEXT NOT NULL, cat TEXT NOT NULL)")
        cats = ",".join(f"'{c}'" for c in config.UNIQUE_CATEGORIES)
        self.conn.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS uq_val ON map(cat, val) "
            f"WHERE cat IN ({cats})")
        self.conn.commit()
        self._lru = OrderedDict()
        self._lru_max = 100_000
        self._pending = 0

    def _rng(self, cat: str, original: str, attempt: int) -> random.Random:
        h = hashlib.sha256(
            f"{self.salt}|{cat}|{original}|{attempt}".encode("utf-8")).hexdigest()
        return random.Random(int(h[:16], 16))

    def _lookup(self, key: str):
        if key in self._lru:
            self._lru.move_to_end(key)
            return self._lru[key]
        row = self.conn.execute("SELECT val FROM map WHERE key=?", (key,)).fetchone()
        if row:
            self._cache(key, row[0])
            return row[0]
        return None

    def _cache(self, key, val):
        self._lru[key] = val
        if len(self._lru) > self._lru_max:
            self._lru.popitem(last=False)

    def _store(self, key, val, cat):
        self.conn.execute("INSERT INTO map(key,val,cat) VALUES(?,?,?)", (key, val, cat))
        self._pending += 1
        if self._pending >= 5000:
            self.conn.commit()
            self._pending = 0
        self._cache(key, val)

    def get(self, original: str, cat: str, **ctx) -> str:
        original = original.strip()
        if not original:
            return original
        key = f"{cat}|{original}"
        hit = self._lookup(key)
        if hit is not None:
            return hit
        for attempt in range(60):
            rng = self._rng(cat, original, attempt)
            val = self._generate(cat, original, rng, ctx)
            try:
                self._store(key, val, cat)
                return val
            except sqlite3.IntegrityError:
                continue
        suffix = hashlib.sha256(key.encode()).hexdigest()[:6].upper()
        val = f"{val}-{suffix}"
        self._store(key, val, cat)
        return val

    def close(self):
        self.conn.commit()
        self.conn.close()

    def _person(self, rng):
        if rng.random() < 0.5:
            return (rng.choice(D.SURNAMES_M), rng.choice(D.NAMES_M), rng.choice(D.PATR_M))
        return (rng.choice(D.SURNAMES_F), rng.choice(D.NAMES_F), rng.choice(D.PATR_F))

    def _person_rng(self, original, ctx):
        pid = ctx.get("person_id", original)
        return self._rng("person", pid, 0)

    def _generate(self, cat, original, rng, ctx):
        if cat == "uuid":
            h = hashlib.sha256(f"{self.salt}|uuid|{original}".encode()).hexdigest()
            return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"

        if cat == "fio":
            s, n, p = self._person(self._person_rng(original, ctx))
            return f"{s} {n} {p}"
        if cat == "last_name":
            return self._person(self._person_rng(original, ctx))[0]
        if cat == "first_name":
            return self._person(self._person_rng(original, ctx))[1]
        if cat == "middle_name":
            return self._person(self._person_rng(original, ctx))[2]

        if cat == "email":
            s, n, _ = self._person(self._person_rng(original, ctx))
            login = f"{D.translit(n[0])}.{D.translit(s)}"
            return f"{login}@{rng.choice(D.EMAIL_DOMAINS)}"

        if cat == "address":
            self._person(self._person_rng(original, ctx))
            adj = D.adj_feminine(rng.choice(D.ADJ_LIST))
            return f"г. Синтетическ, ул. {adj}, д. {rng.randint(1, 120)}"

        if cat == "phone":
            return (f"+7 ({rng.randint(900, 999)}) {rng.randint(100, 999)}-"
                    f"{rng.randint(10, 99)}-{rng.randint(10, 99)}")

        if cat == "org_name":
            adj = rng.choice(D.ADJ_LIST).capitalize()
            return f'ООО "{adj}-{rng.randint(1, 99999)}"'

        if cat == "object_name":
            return self._replace_name_tokens(original, rng)

        if cat == "inn":
            return self._inn(original, rng)

        if cat == "digits":
            n = sum(c.isdigit() for c in original) or len(original)
            n = max(1, min(n, 30))
            return str(rng.randint(1, 9)) + "".join(str(rng.randint(0, 9)) for _ in range(n - 1))

        if cat == "ip":
            return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

        if cat == "port":
            return str(rng.randint(1024, 65535))

        if cat == "authority":
            h = hashlib.sha256(f"{self.salt}|auth|{original}".encode()).hexdigest()[:10]
            return f"http://example.invalid/authority/{h}"

        return original

    def _replace_name_tokens(self, name: str, rng) -> str:
        """Именные токены -> прилагательные; числа -> случайные цифры той же длины;
        числа при единицах (230 kV) сохраняются; техслова и одиночные буквы сохраняются;
        регистр сохраняется."""
        toks = list(_TOKEN.finditer(name))
        out, last = [], 0
        for i, m in enumerate(toks):
            out.append(name[last:m.start()])
            w = m.group(0)
            if w.isdigit():
                nxt = toks[i + 1].group(0).lower() if i + 1 < len(toks) else ""
                gap = name[m.end():toks[i + 1].start()] if i + 1 < len(toks) else ""
                if nxt in _UNITS and gap.strip() == "":
                    out.append(w)
                else:
                    out.append("".join(str(rng.randint(0, 9)) for _ in w))
            elif len(w) == 1 or w.lower() in D.TECH_TOKENS:
                out.append(w)
            else:
                adj = rng.choice(D.ADJ_LIST)
                out.append(adj.upper() if w.isupper()
                           else adj.capitalize() if w[0].isupper() else adj)
            last = m.end()
        out.append(name[last:])
        return "".join(out)

    def _inn(self, original: str, rng) -> str:
        digits = [rng.randint(0, 9) for _ in range(9)]
        if len(re.sub(r"\D", "", original)) == 12:
            digits = [rng.randint(0, 9) for _ in range(10)]
            c1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            digits.append(sum(d * c for d, c in zip(digits, c1)) % 11 % 10)
            c2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
            digits.append(sum(d * c for d, c in zip(digits, c2)) % 11 % 10)
        else:
            c = [2, 4, 10, 3, 5, 9, 4, 6, 8]
            digits.append(sum(d * k for d, k in zip(digits, c)) % 11 % 10)
        return "".join(map(str, digits))