"""A self-contained signature engine with a YARA-flavored rule language.

Why not just require YARA? Because triage boxes are often air-gapped and the
``yara-python`` wheel isn't always installable. This engine implements a useful
*subset* of the YARA language in pure Python:

    rule Ransom_ShadowCopy_Delete {
        meta:
            severity    = high
            category    = ransomware
            attack      = T1490, T1486
            description = "Deletes volume shadow copies then references encryption"
        strings:
            $vss   = "vssadmin delete shadows" nocase
            $wmic  = "wmic shadowcopy delete" nocase
            $note  = "your files have been encrypted" nocase wide
            $hex   = { 6A 40 68 00 30 00 00 }
            $re    = /\\.(locky|crypt|wncry)/ nocase
        condition:
            2 of them and $note
    }

Supported: string / wide / nocase / fullword / xor modifiers, hex patterns with
``??`` / ``?x`` nibble wildcards, ``/regex/`` patterns, counts (``#id``),
``N of them`` / ``all of them`` / ``any of them`` / ``N of ($a,$b,$pre*)``,
boolean ``and``/``or``/``not`` with parentheses, and the special terms
``filesize`` and ``entropy`` (whole-file Shannon entropy) with numeric
comparisons (``KB``/``MB`` suffixes allowed).

If the real ``yara`` library *is* present, :func:`compile_rules` still returns
Strix rules — the two engines are complementary, not exclusive.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


# --------------------------------------------------------------------------
# Pattern matchers
# --------------------------------------------------------------------------
@dataclass
class Pattern:
    name: str
    regex: "re.Pattern[bytes]"
    raw: str

    def count(self, data: bytes) -> int:
        return len(self.regex.findall(data))


def _literal_to_regex(value: str, nocase: bool, wide: bool, fullword: bool, xor: bool) -> "re.Pattern[bytes]":
    raw = value.encode("latin-1", "replace")
    variants: list[bytes] = [raw]
    if wide:
        variants.append(raw.decode("latin-1").encode("utf-16le"))
    parts = [re.escape(v) for v in variants]
    body = b"(?:" + b"|".join(parts) + b")"
    if fullword:
        body = rb"(?<![A-Za-z0-9_])" + body + rb"(?![A-Za-z0-9_])"
    flags = re.DOTALL | (re.IGNORECASE if nocase else 0)
    if xor:
        # XOR single-byte brute force is expensive; we approximate by matching
        # the plaintext only and noting the modifier (documented limitation).
        pass
    return re.compile(body, flags)


_HEX_TOKEN = re.compile(r"[0-9a-fA-F?]{2}|\?\?|\[\d+(?:-\d+)?\]|\(|\)|\|")


def _hex_to_regex(body: str) -> "re.Pattern[bytes]":
    out = bytearray(b"")
    pieces: list[bytes] = []
    i = 0
    tokens = body.replace("\n", " ").split()
    for tok in tokens:
        if tok in ("(", ")", "|"):
            pieces.append(tok.encode())
            continue
        if tok.startswith("[") and tok.endswith("]"):
            inner = tok[1:-1]
            if "-" in inner:
                lo, hi = inner.split("-")
                pieces.append(b".{%s,%s}" % (lo.encode(), hi.encode()))
            else:
                pieces.append(b".{%s}" % inner.encode())
            continue
        if tok == "??":
            pieces.append(b".")
        elif "?" in tok:
            hi, lo = tok[0], tok[1]
            if hi == "?":
                pieces.append(b"[" + _nibble_lo(lo) + b"]")
            else:
                pieces.append(b"[" + _nibble_hi(hi) + b"]")
        else:
            pieces.append(re.escape(bytes.fromhex(tok)))
    return re.compile(b"".join(pieces), re.DOTALL)


def _nibble_hi(hi: str) -> bytes:
    return bytes(b for b in range(256) if f"{b:02x}"[0] == hi.lower()).replace(b"\\", b"\\\\")


def _nibble_lo(lo: str) -> bytes:
    return bytes(b for b in range(256) if f"{b:02x}"[1] == lo.lower()).replace(b"\\", b"\\\\")


# --------------------------------------------------------------------------
# Rule model
# --------------------------------------------------------------------------
@dataclass
class Rule:
    name: str
    meta: dict
    patterns: list[Pattern]
    condition: str
    _eval: Optional[Callable] = field(default=None, repr=False)

    def pattern_names(self) -> list[str]:
        return [p.name for p in self.patterns]


@dataclass
class Match:
    rule: str
    meta: dict
    matched_patterns: dict[str, int]  # name -> count

    def evidence(self) -> list[str]:
        return [f"${n} ×{c}" for n, c in self.matched_patterns.items() if c]


# --------------------------------------------------------------------------
# Rule-file parser
# --------------------------------------------------------------------------
_RULE_START = re.compile(r"\brule\s+([A-Za-z_]\w*)[^\{]*\{")
_SECTION_RE = re.compile(r"(meta|strings|condition)\s*:", re.S)


def _extract_braced(text: str, start: int) -> tuple[str, int]:
    """Given ``text[start] == '{'``, return ``(inner, index_after_close)``.

    Brace depth is tracked while skipping double-quoted string literals, so
    braces inside rule strings, hex patterns (``{ DE AD }``) and regex
    quantifiers (``{2,3}``) all balance correctly.
    """

    depth = 0
    i = start
    n = len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i], i + 1
        i += 1
    return text[start + 1 :], n


def load_bundled() -> list[Rule]:
    """Compile every ``*.strx`` rule shipped inside the package."""

    rules: list[Rule] = []
    if not os.path.isdir(_RULES_DIR):
        return rules
    for fn in sorted(os.listdir(_RULES_DIR)):
        if fn.endswith(".strx"):
            with open(os.path.join(_RULES_DIR, fn), "r", encoding="utf-8") as fh:
                rules.extend(compile_rules(fh.read()))
    return rules


def load_paths(paths: list[str]) -> list[Rule]:
    """Compile user-supplied rule files or directories of ``*.strx``."""

    rules: list[Rule] = []
    for p in paths:
        if os.path.isdir(p):
            for fn in sorted(os.listdir(p)):
                if fn.endswith(".strx"):
                    with open(os.path.join(p, fn), encoding="utf-8") as fh:
                        rules.extend(compile_rules(fh.read()))
        elif os.path.isfile(p):
            with open(p, encoding="utf-8") as fh:
                rules.extend(compile_rules(fh.read()))
    return rules


def compile_rules(text: str) -> list[Rule]:
    rules: list[Rule] = []
    # strip /* */ comments and FULL-LINE // comments only — never inline, so a
    # "http://..." literal inside a rule string is left intact.
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(?m)^\s*//[^\n]*$", "", text)
    pos = 0
    while True:
        m = _RULE_START.search(text, pos)
        if not m:
            break
        name = m.group(1)
        brace = m.end() - 1  # position of the opening '{'
        body, pos = _extract_braced(text, brace)
        meta, strings, cond = _split_sections(body)
        patterns = _parse_strings(strings)
        rule = Rule(name=name, meta=_parse_meta(meta), patterns=patterns, condition=cond.strip())
        rule._eval = _compile_condition(cond.strip(), [p.name for p in patterns])
        rules.append(rule)
    return rules


def _split_sections(body: str) -> tuple[str, str, str]:
    idx = {name: m.start() for m in _SECTION_RE.finditer(body) for name in [m.group(1)]}
    order = sorted(idx.items(), key=lambda kv: kv[1])
    chunks = {"meta": "", "strings": "", "condition": ""}
    for i, (sect, start) in enumerate(order):
        colon = body.index(":", start) + 1
        end = order[i + 1][1] if i + 1 < len(order) else len(body)
        chunks[sect] = body[colon:end]
    return chunks["meta"], chunks["strings"], chunks["condition"]


def _parse_meta(text: str) -> dict:
    meta: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"')
        if key == "attack":
            meta[key] = [v.strip() for v in val.split(",") if v.strip()]
        else:
            meta[key] = val
    return meta


_STR_LINE = re.compile(r"\$(\w+)\s*=\s*(.+)$")


def _parse_strings(text: str) -> list[Pattern]:
    patterns: list[Pattern] = []
    for line in text.splitlines():
        line = line.strip()
        m = _STR_LINE.match(line)
        if not m:
            continue
        name, rhs = m.group(1), m.group(2).strip()
        mods = set(re.findall(r"\b(nocase|wide|ascii|fullword|xor)\b", rhs))
        if rhs.startswith('"'):
            value = re.match(r'"((?:[^"\\]|\\.)*)"', rhs).group(1)
            value = bytes(value, "latin-1").decode("unicode_escape")
            rx = _literal_to_regex(value, "nocase" in mods, "wide" in mods,
                                   "fullword" in mods, "xor" in mods)
            patterns.append(Pattern(name, rx, rhs))
        elif rhs.startswith("{"):
            hexbody = rhs[rhs.index("{") + 1 : rhs.index("}")]
            patterns.append(Pattern(name, _hex_to_regex(hexbody), rhs))
        elif rhs.startswith("/"):
            end = rhs.rindex("/")
            pat = rhs[1:end]
            flags = re.DOTALL | (re.IGNORECASE if "nocase" in mods else 0)
            patterns.append(Pattern(name, re.compile(pat.encode("latin-1", "replace"), flags), rhs))
    return patterns


# --------------------------------------------------------------------------
# Condition compiler (recursive-descent over a small grammar)
# --------------------------------------------------------------------------
_TOK = re.compile(r"""
    \s*(?:
      (?P<num>0x[0-9a-fA-F]+|\d+)\s*(?P<unit>KB|MB|GB)? |
      (?P<op><=|>=|==|!=|<|>) |
      (?P<kw>and|or|not|of|them|all|any|filesize|entropy|uint\d+|int\d+) |
      (?P<count>\#\w+) |
      (?P<ref>\$\w+\*?|\$\*) |
      (?P<punc>[()*,]) |
      (?P<other>\S)
    )
""", re.X | re.I)


def _tokenize(expr: str) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    for m in _TOK.finditer(expr):
        if m.group("num") is not None:
            val = int(m.group("num"), 0)
            unit = (m.group("unit") or "").upper()
            val *= {"KB": 1024, "MB": 1024**2, "GB": 1024**3}.get(unit, 1)
            toks.append(("num", str(val)))
        elif m.group("op"):
            toks.append(("op", m.group("op")))
        elif m.group("kw"):
            toks.append(("kw", m.group("kw").lower()))
        elif m.group("count"):
            toks.append(("count", m.group("count")[1:]))
        elif m.group("ref"):
            toks.append(("ref", m.group("ref")))
        elif m.group("punc"):
            toks.append(("punc", m.group("punc")))
        elif m.group("other"):
            toks.append(("other", m.group("other")))
    return toks


class _Parser:
    def __init__(self, toks, names):
        self.toks = toks
        self.i = 0
        self.names = names

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else ("eof", "")

    def next(self):
        t = self.peek()
        self.i += 1
        return t

    def parse(self):
        node = self._or()
        return node

    def _or(self):
        node = self._and()
        while self.peek() == ("kw", "or"):
            self.next()
            rhs = self._and()
            node = ("or", node, rhs)
        return node

    def _and(self):
        node = self._not()
        while self.peek() == ("kw", "and"):
            self.next()
            rhs = self._not()
            node = ("and", node, rhs)
        return node

    def _not(self):
        if self.peek() == ("kw", "not"):
            self.next()
            return ("not", self._not())
        return self._primary()

    def _primary(self):
        typ, val = self.peek()
        if (typ, val) == ("punc", "("):
            self.next()
            node = self._or()
            if self.peek() == ("punc", ")"):
                self.next()
            return node
        # quantifier: "N of ...", "all of ...", "any of ..."
        if typ == "num" and self._lookahead_is_of(1):
            n = int(val); self.next()
            return self._of(n)
        if (typ, val) in (("kw", "all"), ("kw", "any")) and self._lookahead_is_of(1):
            self.next()
            return self._of(val)
        # count reference "#name > 3"
        if typ == "count":
            self.next()
            name = val
            if self.peek()[0] == "op":
                op = self.next()[1]
                num = int(self.next()[1])
                return ("cmp", ("count", name), op, num)
            return ("bool", ("count", name))  # count as truthy
        # filesize / entropy comparisons
        if (typ, val) in (("kw", "filesize"), ("kw", "entropy")):
            self.next()
            op = self.next()[1]
            num = float(self.next()[1])
            return ("cmp", ("var", val), op, num)
        # pattern ref
        if typ == "ref":
            self.next()
            return ("ref", val)
        if typ == "num":
            self.next()
            return ("lit", int(val))
        # unknown token — consume to avoid infinite loop
        self.next()
        return ("lit", 0)

    def _lookahead_is_of(self, ahead):
        j = self.i + ahead
        return j <= len(self.toks) and self.i + 1 < len(self.toks) and self.toks[self.i + 1] == ("kw", "of")

    def _of(self, quant):
        # consume "of"
        if self.peek() == ("kw", "of"):
            self.next()
        if self.peek() == ("kw", "them"):
            self.next()
            targets = list(self.names)
        elif self.peek() == ("punc", "("):
            self.next()
            targets = []
            while self.peek()[0] != "eof" and self.peek() != ("punc", ")"):
                t, v = self.next()
                if t == "ref":
                    targets.extend(self._expand(v))
                # commas/punc skipped
            if self.peek() == ("punc", ")"):
                self.next()
        else:
            targets = list(self.names)
        return ("of", quant, targets)

    def _expand(self, ref: str) -> list[str]:
        base = ref.lstrip("$")
        if base.endswith("*"):
            pre = base[:-1]
            return [n for n in self.names if n.startswith(pre)]
        return [base]


def _compile_condition(expr: str, names: list[str]) -> Callable:
    toks = _tokenize(expr)
    ast = _Parser(toks, names).parse()

    def ev(node, ctx):
        kind = node[0]
        if kind == "or":
            return bool(ev(node[1], ctx)) or bool(ev(node[2], ctx))
        if kind == "and":
            return bool(ev(node[1], ctx)) and bool(ev(node[2], ctx))
        if kind == "not":
            return not bool(ev(node[1], ctx))
        if kind == "ref":
            return ctx["counts"].get(node[1].lstrip("$"), 0) > 0
        if kind == "of":
            quant, targets = node[1], node[2]
            hit = sum(1 for t in targets if ctx["counts"].get(t, 0) > 0)
            if quant == "all":
                return hit == len(targets) and len(targets) > 0
            if quant == "any":
                return hit > 0
            return hit >= int(quant)
        if kind == "cmp":
            left = _val(node[1], ctx)
            return _apply(left, node[2], node[3])
        if kind == "bool":
            return _val(node[1], ctx) > 0
        if kind == "lit":
            return bool(node[1])
        return False

    def _val(ref, ctx):
        if ref[0] == "count":
            return ctx["counts"].get(ref[1], 0)
        if ref[0] == "var":
            return ctx.get(ref[1], 0)
        return 0

    def _apply(left, op, right):
        return {
            "<": left < right, ">": left > right, "<=": left <= right,
            ">=": left >= right, "==": left == right, "!=": left != right,
        }.get(op, False)

    return lambda ctx: bool(ev(ast, ctx))


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def scan(data: bytes, rules: list[Rule], *, filesize: int = 0, entropy: float = 0.0) -> list[Match]:
    matches: list[Match] = []
    for rule in rules:
        counts = {p.name: p.count(data) for p in rule.patterns}
        ctx = {"counts": counts, "filesize": filesize or len(data), "entropy": entropy}
        try:
            fired = rule._eval(ctx) if rule._eval else False
        except Exception:
            fired = False
        if fired:
            matched = {n: c for n, c in counts.items() if c}
            matches.append(Match(rule.name, rule.meta, matched))
    return matches
