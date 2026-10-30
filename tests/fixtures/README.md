# Test fixtures

`eml/` holds one message per file, each exercising one decoding case
(charsets, transfer encodings, RFC 2047/2231, nested messages, inline
images, calendar invitations) or one shape Proton Mail Bridge produces
(the `X-Pm-*` headers it adds, the synthesized
`<id@protonmail.internalid>` Message-ID and self reference, the
armored-PGP body and `.pgp` attachment it writes when it cannot decrypt,
the PGP/MIME fallback). `tests/test_mime_corpus.py` lists what each one
must decode to. Every address and host is a reserved example domain.

## Third-party material

`eml/nested-rfc822.eml`, `eml/multipart-mixed-gluon.eml` and
`eml/afternoon-meeting.eml` are adapted from the test data of
[gluon](https://github.com/ProtonMail/gluon) (`tests/testdata/`,
revision 7e800978ab4a), with addresses and hosts rewritten to example
domains and transport headers removed. gluon is distributed under the MIT
License:

> The MIT License (MIT)
>
> Copyright (c) 2020 James Houlahan
> Copyright (c) 2021 Proton AG
>
> Permission is hereby granted, free of charge, to any person obtaining a
> copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to
> the following conditions:
>
> The above copyright notice and this permission notice shall be included
> in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
> OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
> IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
> CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
> TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
> SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

`afternoon-meeting.eml` is in turn the example message of RFC 3501.
