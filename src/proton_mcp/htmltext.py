"""HTML to readable text, in linear time on hostile input.

Built on html.parser (a single pass) with a bounded element stack: script,
style and other non-content elements are dropped, and so is anything the
reader cannot see (hidden attribute, display:none and the other usual
hiding styles: hidden text is the classic channel for instructions aimed
at a model). Links stay readable as `text <url>`, images become
`[image: alt]`, data: URIs are redacted.

Why not html2text (2025.4.15, the obvious library): measured on it, it
renders text hidden with display:none, the hidden attribute or font-size:0
verbatim, keeps data: URIs, and spends 107 s on 20,000 nested <ul><li>
(quadratic), so one hostile 160 KB message would stall the server. This
converter drops hidden content and stays linear; tests/test_htmltext.py
holds both properties, the nested-list case included."""

from __future__ import annotations

import re
from html.parser import HTMLParser

from .textmatch import INVISIBLE

MAX_INPUT = 4_000_000  # characters of HTML considered at all
_MAX_STACK = 512
_MATCH_WINDOW = 48  # how far up the stack an end tag may close
_MAX_URL = 300

_SKIP = frozenset(
    "script style head title template noscript svg math iframe object embed applet frameset "
    "frame canvas audio video select option datalist xml".split()
)
_VOID = frozenset("area base br col embed hr img input link meta param source track wbr keygen".split())
# Blocks that start a paragraph (a blank line) and blocks that start a line.
_PARAGRAPH = frozenset("p h1 h2 h3 h4 h5 h6 blockquote pre table ul ol dl form figure address center".split())
_LINE = frozenset(
    "div section article header footer main nav aside tbody thead tfoot dd dt fieldset figcaption details "
    "summary caption li tr".split()
)
_ZERO = re.compile(r"0(?:\.0+)?(?:px|pt|em|rem|%|vh|vw)?")
_FAR_OFF = re.compile(r"-\d{3,}")
_DATA_URI = re.compile(r"\bdata:[a-z0-9.+/-]*(?:;[a-z0-9=.+-]*)*,[^\s\"'<>)\]]{16,}", re.I)
_WS = re.compile(r"\s+")
_TRAILING = re.compile(r"[ \t]+\n")
_BLANKS = re.compile(r"\n{3,}")


def redact_data_uris(text: str) -> str:
    return _DATA_URI.sub("[data URI removed]", text)


def _declarations(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for decl in style[:2000].split(";")[:60]:
        name, sep, value = decl.partition(":")
        if sep:
            out[name.strip().lower()] = value.replace("!important", "").strip().lower()
    return out


def _visibility(attrs: dict[str, str | None], parent: tuple[bool, bool]) -> tuple[bool, bool, bool]:
    """(hard-hidden, font-size zero, visibility hidden) for an element.

    Hard: what no descendant can undo (the hidden attribute, display:none,
    opacity:0, a zero box with overflow:hidden, positioned far off screen).
    The other two are inherited and a descendant resets them, as responsive
    templates do: their column containers set font-size:0 and the cells
    inside set it again. mso-hide is Outlook-only and does not hide."""
    d = _declarations(attrs.get("style") or "")
    hard = "hidden" in attrs or d.get("display") == "none" or bool(_ZERO.fullmatch(d.get("opacity", "1")))
    if d.get("overflow") == "hidden" and any(
        _ZERO.fullmatch(d.get(p, "x")) for p in ("height", "width", "max-height", "max-width")
    ):
        hard = True
    if any(_FAR_OFF.match(d.get(p, "")) for p in ("left", "top", "text-indent", "margin-left", "margin-top")):
        hard = True
    font_zero, vis_hidden = parent
    if "font-size" in d:
        font_zero = bool(_ZERO.fullmatch(d["font-size"]))
    if d.get("visibility") in ("hidden", "collapse"):
        vis_hidden = True
    elif d.get("visibility") == "visible":
        vis_hidden = False
    return hard, font_zero, vis_hidden


def _short_url(url: str) -> str:
    url = url.strip()
    return url if len(url) <= _MAX_URL else url[:_MAX_URL] + "…"


class _Converter(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        # (tag, suppresses content, font-size zero, visibility hidden)
        self.stack: list[tuple[str, bool, bool, bool]] = []
        self.suppressed = 0
        self.pre = 0
        self.links: list[tuple[int, str, bool]] = []  # (output position, href, visible) of open <a>
        self.newlines = 0  # newlines at the end of the output so far
        self.started = False  # any visible text yet

    @property
    def inherited(self) -> tuple[bool, bool]:
        return (self.stack[-1][2], self.stack[-1][3]) if self.stack else (False, False)

    @property
    def visible(self) -> bool:
        return not self.suppressed and not any(self.inherited)

    # ── the visible-text sink ────────────────────────────────────────────

    def _text(self, text: str) -> None:
        if not text or not self.visible:
            return
        self.out.append(text)
        stripped = text.rstrip("\n")
        if stripped:
            self.started = True
            self.newlines = len(text) - len(stripped)
        else:
            self.newlines += len(text)

    def _break(self, n: int) -> None:
        """At least n line breaks here (none before the first text)."""
        if self.started and self.newlines < n:
            self._text("\n" * (n - self.newlines))

    def _push(self, tag: str, suppress: bool, font_zero: bool, vis_hidden: bool) -> None:
        if len(self.stack) >= _MAX_STACK:
            return
        self.stack.append((tag, suppress, font_zero, vis_hidden))
        if suppress:
            self.suppressed += 1
        if tag == "pre":
            self.pre += 1

    def _pop_to(self, tag: str) -> bool:
        limit = max(0, len(self.stack) - _MATCH_WINDOW)
        for i in range(len(self.stack) - 1, limit - 1, -1):
            if self.stack[i][0] == tag:
                while len(self.stack) > i:
                    t, suppress, _, _ = self.stack.pop()
                    if suppress:
                        self.suppressed -= 1
                    if t == "pre":
                        self.pre -= 1
                    if t == "a":
                        self._close_link()
                return True
        return False

    def _close_link(self) -> None:
        if not self.links:
            return
        start, href, was_visible = self.links.pop()
        if not href or not was_visible:
            return
        shown = "".join(self.out[start:]).strip()
        low = href.lower()
        if low.startswith("mailto:"):
            target = href[7:].split("?", 1)[0]
            if target and target.lower() not in shown.lower():
                self._text(f" <{target}>")
        elif low.startswith(("http://", "https://")) and href not in shown:
            self._text(f" <{_short_url(href)}>")

    # ── parser callbacks ─────────────────────────────────────────────────

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        a = {k.lower(): v for k, v in attrs[:64]}
        hard, font_zero, vis_hidden = _visibility(a, self.inherited)
        if tag in _VOID:
            if hard or font_zero or vis_hidden or not self.visible:
                return
            if tag == "br":
                self._text("\n")
            elif tag == "hr":
                self._break(2)
            elif tag == "img":
                width, height = (a.get("width") or "").strip(), (a.get("height") or "").strip()
                if width in ("0", "1") or height in ("0", "1"):
                    return
                alt = _WS.sub(" ", a.get("alt") or "").strip()
                if alt:
                    self._text(f"[image: {redact_data_uris(alt)[:200]}]")
            return
        self._push(tag, hard or tag in _SKIP, font_zero, vis_hidden)
        if tag in _PARAGRAPH:
            self._break(2)
        elif tag in _LINE:
            self._break(1)
            if tag == "li":
                self._text("- ")
        elif tag in ("td", "th"):
            if self.out and self.newlines == 0:
                self._text(" ")
        elif tag == "a":
            self.links.append((len(self.out), (a.get("href") or "").strip(), self.visible))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in _VOID:
            self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "br":  # </br> is a line break in every browser
            self._text("\n")
            return
        if not self._pop_to(tag):
            return
        if tag in _PARAGRAPH:
            self._break(2)
        elif tag in _LINE:
            self._break(1)

    def handle_data(self, data: str) -> None:
        if not self.visible:
            return
        if self.pre:
            self._text(data)
            return
        text = _WS.sub(" ", data)
        if not self.started or self.newlines:
            text = text.lstrip(" ")
        self._text(text)


def html_to_text(html: str) -> str:
    conv = _Converter()
    conv.feed(html[:MAX_INPUT])
    conv.close()
    while conv.links:
        conv._close_link()
    text = "".join(conv.out)
    text = INVISIBLE.sub("", text).replace("\xa0", " ").replace("\r", "")
    text = redact_data_uris(text)
    text = _TRAILING.sub("\n", text)
    text = _BLANKS.sub("\n\n", text)
    return text.strip("\n").rstrip()


def plain_text(text: str) -> str:
    """The same normalization for a text/plain body."""
    text = INVISIBLE.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    text = redact_data_uris(text)
    text = _TRAILING.sub("\n", text)
    text = _BLANKS.sub("\n\n", text)
    return text.strip()
