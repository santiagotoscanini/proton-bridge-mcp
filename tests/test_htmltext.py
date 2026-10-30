"""HTML to text: content, hiding, links, and linear time on hostile input."""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from proton_mcp.htmltext import html_to_text, plain_text


def test_structure() -> None:
    html = "<h1>Title</h1><p>One <b>two</b></p><ul><li>a</li><li>b</li></ul><table><tr><td>x</td><td>y</td></tr></table>"
    text = html_to_text(html)
    assert text.splitlines()[0] == "Title"
    assert "One two" in text and "- a\n- b" in text and "x y" in text


@pytest.mark.parametrize(
    "html",
    [
        '<div style="display:none">SECRET</div>',
        '<div style="DISPLAY : NONE !important">SECRET</div>',
        '<span style="visibility:hidden">SECRET</span>',
        '<span style="font-size:0px">SECRET</span>',
        '<span style="font-size:0">SECRET</span>',
        '<span style="opacity:0">SECRET</span>',
        '<div style="max-height:0;overflow:hidden">SECRET</div>',
        '<p style="position:absolute;left:-9999px">SECRET</p>',
        "<div hidden>SECRET</div>",
        "<script>SECRET</script>",
        "<style>SECRET{}</style>",
        "<head><title>SECRET</title></head>",
        "<template>SECRET</template>",
        "<noscript>SECRET</noscript>",
        "<svg><text>SECRET</text></svg>",
        '<div style="display:none"><p><b>SECRET</b></p></div>',
    ],
)
def test_hidden_content_is_dropped(html: str) -> None:
    text = html_to_text(f"<p>visible</p>{html}<p>after</p>")
    assert "SECRET" not in text and "visible" in text and "after" in text


def test_visible_lookalikes_are_kept() -> None:
    text = html_to_text('<p style="font-size:10px">small</p><p style="opacity:0.5">faded</p><p style="width:0.5em">x</p>')
    assert "small" in text and "faded" in text


def test_links_images_data_uris() -> None:
    text = html_to_text(
        '<a href="https://example.org/a">Read</a> <a href="https://example.org/b">https://example.org/b</a> '
        '<a href="mailto:x@example.org">write</a> <a href="javascript:evil()">js</a> <a href="#top">top</a> '
        '<img alt="chart"> <img src="x.gif" width="1" height="1" alt="pixel"> '
        '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">d</a> '
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
    )
    assert "Read <https://example.org/a>" in text
    assert text.count("https://example.org/b") == 1
    assert "write <x@example.org>" in text
    assert "javascript" not in text and "#top" not in text and "pixel" not in text
    assert "[image: chart]" in text
    assert "PHNjcmlwd" not in text and "iVBOR" not in text and "[data URI removed]" in text
    long = "https://example.org/" + "a" * 1000
    assert len(html_to_text(f'<a href="{long}">x</a>')) < 400


def test_entities_whitespace_pre_and_invisibles() -> None:
    text = html_to_text("<p>a&nbsp;&amp;&lt;b&gt;&#233;​</p><pre>  keep\n   spacing</pre><p>  many    spaces </p>")
    assert "a &<b>é" in text and "  keep\n   spacing" in text and "many spaces" in text


def test_malformed_markup() -> None:
    text = html_to_text("<div><p>one<b>two<i>three</b>four</i></div></div></div><p>five")
    assert all(w in text for w in ("one", "two", "three", "four", "five"))
    assert html_to_text("") == "" and html_to_text("plain") == "plain"
    assert "<!--" not in html_to_text("<p>x</p><!-- never closed <script>alert(1)</script>")
    assert "alert" not in html_to_text("<p>x</p><!-- never closed <script>alert(1)</script>")


def test_plain_text_normalization() -> None:
    assert plain_text("a\r\nb\rc\n\n\n\nd \t\n") == "a\nb\nc\n\nd"
    assert plain_text("zero​width﻿") == "zerowidth"


HOSTILE = [
    "<" * 200_000,
    "<a " * 100_000,
    "<!--" * 50_000,
    "<div>" * 100_000,
    "</div>" * 100_000,
    "<p style='" + "display:none;" * 50_000 + "'>x",
    "&#" * 100_000,
    "<![CDATA[" * 50_000,
    "<a href='" + "x" * 500_000 + "'>",
    "<scr" + "ipt>" * 50_000,
    "<div hidden>" * 2000 + "x" + "</div>" * 2000,
    "<b><i>" * 50_000,
    "data:," + "A" * 500_000,
    "<ul><li>" * 20_000,  # quadratic in html2text
    "<table><tr><td>" * 20_000,
    "<blockquote>" * 20_000,
]


@pytest.mark.parametrize("html", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_input_is_fast(html: str) -> None:
    start = time.monotonic()
    html_to_text(html)
    assert time.monotonic() - start < 3.0


def test_cost_grows_linearly() -> None:
    def cost(n: int) -> float:
        doc = "<div style='color:red'><a href='https://example.org/x'>link</a> text &amp; <b>more</b></div>" * n
        start = time.perf_counter()
        html_to_text(doc)
        return time.perf_counter() - start

    small, large = cost(2_000), cost(16_000)
    assert large < small * 8 * 3  # 8x the input: well under quadratic


@given(st.text(alphabet=st.sampled_from(list("<>/=\"' abcdiv&#;!-[]")), max_size=3000))
@settings(max_examples=200)
def test_arbitrary_markup_terminates_quickly(html: str) -> None:
    out = html_to_text(html)
    assert isinstance(out, str)
    assert "​" not in out


def test_inherited_invisibility_is_overridable() -> None:
    """Responsive templates zero the font size on column containers and set
    it again inside; visibility:hidden can be undone by visibility:visible."""
    text = html_to_text(
        '<td style="font-size:0px"><div style="font-size:0px;display:inline-block">'
        '<div style="font-size:14px">column one</div>gap</div></td>'
        '<div style="visibility:hidden">secret <span style="visibility:visible">shown</span></div>'
        '<div style="mso-hide:all">outlook hides this, readers do not</div>'
        '<div style="height:0">overflowing, so visible</div>'
        '<div style="height:0;overflow:hidden">clipped</div>'
    )
    assert "column one" in text and "shown" in text and "readers do not" in text and "overflowing" in text
    assert "gap" not in text and "secret" not in text and "clipped" not in text


def test_hidden_link_does_not_steal_a_visible_ones_url() -> None:
    text = html_to_text('<a href="https://example.org/a">first <span hidden><a href="https://example.org/h">h</a></span></a>')
    assert "<https://example.org/a>" in text and "example.org/h" not in text
