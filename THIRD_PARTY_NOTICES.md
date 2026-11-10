# Third-party notices

## Scope of prior grants and contributions

Copyright (c) 2026 Tokeii. StarMem's original material that Tokeii has
authority to license is available under [LGPL-3.0-only](LICENSE), which
incorporates the [GPL 3.0 terms](licenses/LICENSE-GPL). Existing grants under
[MIT](licenses/LICENSE-MIT) or [Apache-2.0](licenses/LICENSE-APACHE) are
preserved. These license texts are provided for previously granted rights
and applicable third-party material.

The existing licenses of b3nguang's original contributions are preserved.
The contributions were made while the repository declared MIT OR Apache-2.0.
The relevant commits are `acebd51` (driver inspection) and `f57c00d` (PPID
lineage audit).

## MemNixFS — Linux incident-response reports and product name rules

The native Rust Linux incident-response modules reference the report scope of
[MemNixFS](https://github.com/MemNixFS/MemNixFS), including resolver configuration,
crash log indicators, timeline summaries and BTF metadata. The AV/EDR name rule
table in `src/linux_ir/av_signatures.rs` is adapted from its `av_edr.cpp`.
All name matches remain investigation leads, not verified product identities.

Copyright MemNixFS contributors. Licensed under the Apache License, Version 2.0.
The license is included in [the Apache-2.0 text](licenses/LICENSE-APACHE).
The Rust parsers and evidence range validation are StarMem implementations;
MemNixFS is not invoked by them.

## xpress-huffman — Microsoft XPRESS-Huffman decompression

StarMem uses the Apache-2.0 licensed `xpress-huffman` Rust crate to decompress
Windows MAM-wrapped Prefetch files on Windows, Linux, and macOS. The crate is a
clean-room implementation of the Microsoft [MS-XCA] XPRESS-Huffman algorithm.

Copyright (c) SecurityRonin contributors

Licensed under the Apache License, Version 2.0. A copy of the license is
available at <https://www.apache.org/licenses/LICENSE-2.0>.

## Immersive Labs memory forensics plugins — Cobalt Strike configuration format

StarMem's `cobaltstrikescan` is a native Rust reimplementation informed by the
configuration signatures, field identifiers and parsing approach published in
[the original Immersive Labs plugin repository](https://github.com/Immersive-Labs-Sec/volatility_plugins),
commit `032bc053556f529ca4f698c77a12542b0ea58557`.

Copyright (C) 2021 Kevin Breen, Immersive Labs

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Fox-IT dissect.cobaltstrike — modern Beacon configuration semantics

StarMem's interpretation of modern Beacon settings, Malleable C2 transform
programs, process-injection execution methods, DNS retry settings and
BeaconGate fields is informed by
[`fox-it/dissect.cobaltstrike`](https://github.com/fox-it/dissect.cobaltstrike).
StarMem uses its own streaming memory scanner and Rust data model; it does not
embed or execute the Python package.

Copyright (c) 2021 NCC Group, Fox-IT

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
