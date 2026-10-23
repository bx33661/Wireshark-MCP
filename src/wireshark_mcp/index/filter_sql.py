"""Translate a safe subset of Wireshark display filters into SQL over the index.

The translator is deliberately conservative. Anything it cannot reproduce with
the same meaning tshark gives it raises :class:`UnsupportedFilter`, and the
caller falls back to a live tshark scan. Getting a different answer from the
index than from tshark would be worse than being slow.

Supported:

* bare protocol names (``dns``, ``tcp``) and bare indexed fields (presence)
* ``==``/``eq``, ``!=``/``ne``, ``>``, ``<``, ``>=``, ``<=`` and their word forms
* ``contains`` on string fields, ``in {a b c}`` sets of literals
* ``and``/``&&``, ``or``/``||``, ``not``/``!`` and parentheses
* the ``ip.addr``, ``tcp.port`` style aliases for either direction

Semantics follow Wireshark 4.x: a comparison matches when *any* occurrence
matches, ``!=`` means *all* occurrences differ (and the field is present), and a
comparison against an absent field is false. Mixing ``and`` with ``or`` at one
level without parentheses is refused rather than guessing precedence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..tools.stats import LITERAL_STRING_FIELDS
from .schema import FIELD_ALIASES, INDEX_FIELDS, PROTOCOL_ALIASES, FieldKind


class UnsupportedFilter(ValueError):
    """The filter uses syntax or fields the index cannot answer exactly."""


_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<string>"(?:[^"\\]|\\.)*")
      | (?P<op>==|!=|>=|<=|&&|\|\||[<>!(){},])
      | (?P<word>[A-Za-z0-9_.:\-/]+)
    )
    """,
    re.VERBOSE,
)

_WORD_OPERATORS = {
    "eq": "==",
    "ne": "!=",
    "gt": ">",
    "lt": "<",
    "ge": ">=",
    "le": "<=",
    "and": "&&",
    "or": "||",
    "not": "!",
}
_COMPARISONS = {"==", "!=", ">", "<", ">=", "<="}
_NUMBER_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[0-9]+(?:\.[0-9]+)?)$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_PROTOCOL_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


@dataclass
class _Token:
    kind: str  # "string", "op", "word"
    text: str


@dataclass
class TranslatedFilter:
    """A SQL boolean expression plus its positional parameters."""

    sql: str
    params: list[Any] = field(default_factory=list)
    fields: set[str] = field(default_factory=set)


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    stripped = text.rstrip()
    while position < len(stripped):
        match = _TOKEN_RE.match(stripped, position)
        if not match or match.end() == position:
            raise UnsupportedFilter(f"unsupported syntax near {stripped[position : position + 12]!r}")
        position = match.end()
        if match.group("string") is not None:
            tokens.append(_Token("string", match.group("string")))
        elif match.group("op") is not None:
            tokens.append(_Token("op", match.group("op")))
        else:
            word = match.group("word")
            lowered = word.lower()
            if lowered in _WORD_OPERATORS:
                tokens.append(_Token("op", _WORD_OPERATORS[lowered]))
            elif lowered in {"contains", "in"}:
                tokens.append(_Token("op", lowered))
            elif lowered in {"matches", "xor", "bitand", "all", "any"}:
                raise UnsupportedFilter(f"operator {word!r} is not supported by the index")
            else:
                tokens.append(_Token("word", word))
    return tokens


def _decode_string(token: _Token) -> str:
    body = token.text[1:-1]
    if "\\" in body:
        # Only plain escapes are reproducible; byte escapes would need tshark's rules.
        if re.search(r"\\[^\"\\]", body):
            raise UnsupportedFilter('string escapes other than \\" and \\\\ are not supported')
        body = body.replace('\\"', '"').replace("\\\\", "\\")
    return body


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class _Translator:
    def __init__(self, tokens: list[_Token], columns: set[str], protocols: set[str]) -> None:
        self.tokens = tokens
        self.position = 0
        self.columns = columns
        self.protocols = protocols
        self.params: list[Any] = []
        self.fields: set[str] = set()

    # ── token helpers ────────────────────────────────────────────────────
    def peek(self) -> _Token | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> _Token:
        token = self.peek()
        if token is None:
            raise UnsupportedFilter("unexpected end of filter")
        self.position += 1
        return token

    def take_op(self, text: str) -> None:
        token = self.take()
        if token.kind != "op" or token.text != text:
            raise UnsupportedFilter(f"expected {text!r}")

    # ── grammar ──────────────────────────────────────────────────────────
    def parse(self) -> str:
        expression = self.parse_logical()
        if self.peek() is not None:
            raise UnsupportedFilter(f"unexpected token {self.peek().text!r}")  # type: ignore[union-attr]
        return expression

    def parse_logical(self) -> str:
        parts = [self.parse_unary()]
        joiner: str | None = None
        while (token := self.peek()) is not None and token.kind == "op" and token.text in {"&&", "||"}:
            if joiner is not None and token.text != joiner:
                raise UnsupportedFilter("mixing 'and' and 'or' needs explicit parentheses")
            joiner = token.text
            self.position += 1
            parts.append(self.parse_unary())
        if joiner is None:
            return parts[0]
        sql_joiner = " AND " if joiner == "&&" else " OR "
        return "(" + sql_joiner.join(parts) + ")"

    def parse_unary(self) -> str:
        token = self.peek()
        if token is not None and token.kind == "op" and token.text == "!":
            self.position += 1
            return f"(NOT {self.parse_unary()})"
        if token is not None and token.kind == "op" and token.text == "(":
            self.position += 1
            inner = self.parse_logical()
            self.take_op(")")
            return inner
        return self.parse_test()

    def parse_test(self) -> str:
        token = self.take()
        if token.kind != "word":
            raise UnsupportedFilter(f"expected a field or protocol, got {token.text!r}")
        name = token.text
        following = self.peek()
        if following is not None and following.kind == "op" and following.text in _COMPARISONS | {"contains", "in"}:
            self.position += 1
            columns = self.resolve_columns(name)
            if following.text == "in":
                return self.translate_in(columns)
            literal = self.take()
            if literal.kind not in {"word", "string"}:
                raise UnsupportedFilter(f"expected a value after {following.text!r}")
            return self.translate_comparison(columns, following.text, literal)
        return self.translate_presence(name)

    # ── semantics ────────────────────────────────────────────────────────
    def resolve_columns(self, name: str) -> list[str]:
        candidates = list(FIELD_ALIASES.get(name, (name,)))
        missing = [column for column in candidates if column not in self.columns]
        if missing:
            raise UnsupportedFilter(f"field {name!r} is not in the index")
        self.fields.update(candidates)
        return candidates

    def translate_presence(self, name: str) -> str:
        if "." in name or name in self.columns or name in FIELD_ALIASES:
            columns = self.resolve_columns(name)
            return "(" + " OR ".join(f"COALESCE({_quote_ident(c)}, '') <> ''" for c in columns) + ")"
        lowered = name.lower()
        if not _PROTOCOL_RE.match(lowered):
            raise UnsupportedFilter(f"{name!r} is not a recognised protocol name")
        if "frame.protocols" not in self.columns:
            raise UnsupportedFilter("frame.protocols is not in the index")
        protocol = PROTOCOL_ALIASES.get(lowered, lowered)
        if protocol not in self.protocols:
            # Unseen names may be typos (tshark rejects them) or protocols that
            # never appear in frame.protocols; only tshark can tell which.
            raise UnsupportedFilter(f"protocol {name!r} does not occur in this capture's index")
        self.fields.add("frame.protocols")
        self.params.append(protocol)
        return "list_contains(string_split(COALESCE(\"frame.protocols\", ''), ':'), ?)"

    def elements(self, column: str) -> str:
        quoted = _quote_ident(column)
        if column in LITERAL_STRING_FIELDS:
            return f"list_filter([COALESCE({quoted}, '')], lambda v: v <> '')"
        return f"list_filter(string_split(COALESCE({quoted}, ''), ','), lambda v: v <> '')"

    def element_predicate(self, column: str, operator: str, literal: _Token) -> str:
        """SQL predicate over one occurrence ``v`` of ``column``."""
        kind: FieldKind = INDEX_FIELDS.get(column, "string")
        value = _decode_string(literal) if literal.kind == "string" else literal.text

        if operator == "contains":
            if kind != "string":
                raise UnsupportedFilter(f"'contains' on {column} is not supported by the index")
            self.params.append(value)
            return "contains(v, ?)"

        if kind == "bool":
            if operator not in {"==", "!="}:
                raise UnsupportedFilter(f"ordering on boolean field {column}")
            truthy = value.lower() in {"1", "true"}
            if not truthy and value.lower() not in {"0", "false"}:
                raise UnsupportedFilter(f"{value!r} is not a boolean")
            self.params.extend(["1", "True"] if truthy else ["0", "False"])
            return "v IN (?, ?)"

        if kind == "number":
            if not _NUMBER_RE.match(value):
                raise UnsupportedFilter(f"{value!r} is not a plain number for {column}")
            number = int(value, 16) if value.lower().startswith("0x") else float(value)
            self.params.append(number)
            parsed = "(CASE WHEN v ILIKE '0x%' THEN TRY_CAST(v AS UBIGINT)::DOUBLE ELSE TRY_CAST(v AS DOUBLE) END)"
            return f"{parsed} {operator} ?"

        if operator not in {"==", "!="}:
            raise UnsupportedFilter(f"ordering on {kind} field {column}")
        if kind == "ipv4":
            if not _IPV4_RE.match(value):
                raise UnsupportedFilter(f"{value!r} is not a single IPv4 address")
        elif kind == "mac":
            value = value.lower()
            if not _MAC_RE.match(value):
                raise UnsupportedFilter(f"{value!r} is not a colon-separated MAC address")
        elif kind == "ipv6":
            raise UnsupportedFilter("IPv6 address comparison is not supported by the index")
        self.params.append(value)
        return "v = ?"

    def any_match(self, columns: list[str], operator: str, literal: _Token) -> str:
        positive = "==" if operator == "!=" else operator
        clauses = []
        for column in columns:
            predicate = self.element_predicate(column, positive, literal)
            clauses.append(f"len(list_filter({self.elements(column)}, lambda v: {predicate})) > 0")
        return "(" + " OR ".join(clauses) + ")"

    def translate_comparison(self, columns: list[str], operator: str, literal: _Token) -> str:
        if operator != "!=":
            return self.any_match(columns, operator, literal)
        # Wireshark 4.x: `a != b` is "all not equal", false when the field is absent.
        present = "(" + " OR ".join(f"len({self.elements(c)}) > 0" for c in columns) + ")"
        return f"({present} AND NOT {self.any_match(columns, '==', literal)})"

    def translate_in(self, columns: list[str]) -> str:
        self.take_op("{")
        # Comma-separated only: tshark 4.2+ rejects the old whitespace-separated form,
        # and accepting it here would answer a filter tshark itself refuses.
        literals: list[_Token] = []
        while True:
            token = self.take()
            if token.kind not in {"word", "string"} or ".." in token.text:
                raise UnsupportedFilter("only comma-separated literal values are supported inside 'in { }'")
            literals.append(token)
            separator = self.take()
            if separator.kind == "op" and separator.text == "}":
                break
            if separator.kind != "op" or separator.text != ",":
                raise UnsupportedFilter("set elements must be separated by commas")
        return "(" + " OR ".join(self.any_match(columns, "==", literal) for literal in literals) + ")"


def translate_filter(display_filter: str, columns: set[str], protocols: set[str]) -> TranslatedFilter:
    """Translate ``display_filter`` or raise :class:`UnsupportedFilter`.

    ``protocols`` is the set of frame.protocols tokens seen in the capture.
    """
    if not display_filter.strip():
        return TranslatedFilter("TRUE")
    translator = _Translator(_tokenize(display_filter), columns, protocols)
    sql = translator.parse()
    return TranslatedFilter(sql, translator.params, translator.fields)
