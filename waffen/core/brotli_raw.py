"""Pure-stdlib Brotli *stored* (uncompressed) stream encoder.

WAFFEN is stdlib-only, and Python has no `brotli` in the standard library. For the
`brotli_body` request transform we don't need compression *ratio* — we need a
byte stream that is valid Brotli (so a real backend's `Content-Encoding: br`
decoder accepts it) while exercising a WAF's br-decompression path. A Brotli
"uncompressed meta-block" (RFC 7932 §9.2) gives exactly that: the payload bytes
appear verbatim, framed by a few header/trailer bits.

Stream layout emitted here (bits are LSB-first within each byte, per RFC 7932):

    WBITS = 16                      1 bit  : 0
    for each data chunk (<=2^24 B), as a NON-last uncompressed meta-block:
        ISLAST            = 0       1 bit
        MNIBBLES          = 4|5|6   2 bits : (nibbles-4)
        MLEN-1                       nibbles*4 bits
        ISUNCOMPRESSED    = 1       1 bit
        <pad to byte boundary>
        <raw chunk bytes>
    final empty meta-block:
        ISLAST            = 1       1 bit
        ISLASTEMPTY       = 1       1 bit   -> trailing 0x03 byte

Verified round-trip against both `node` (zlib.brotliDecompressSync) and the
`brotli` CLI for empty, 1-byte, NUL/0x03-containing, 256-byte and 5000-byte
inputs; see tests/test_brotli_raw.py (decoder round-trip skipped when neither
decoder is installed).
"""
from __future__ import annotations

_MAX_MLEN = 1 << 24  # largest MLEN one uncompressed meta-block can carry (24-bit field)


class _BitWriter:
    """Accumulate bits LSB-first and emit bytes."""

    __slots__ = ("buf", "_cur", "_n")

    def __init__(self) -> None:
        self.buf = bytearray()
        self._cur = 0
        self._n = 0

    def write(self, value: int, nbits: int) -> None:
        for i in range(nbits):
            self._cur |= ((value >> i) & 1) << self._n
            self._n += 1
            if self._n == 8:
                self.buf.append(self._cur)
                self._cur = 0
                self._n = 0

    def align(self) -> None:
        """Flush the current partial byte, zero-padding to a byte boundary."""
        if self._n:
            self.buf.append(self._cur)
            self._cur = 0
            self._n = 0

    def value(self) -> bytes:
        self.align()
        return bytes(self.buf)


def compress_stored(data: bytes) -> bytes:
    """Return `data` wrapped as a valid, uncompressed Brotli stream.

    Accepts arbitrary bytes (NULs included); output decodes back to `data`
    byte-for-byte under any compliant Brotli decoder.
    """
    bw = _BitWriter()
    bw.write(0, 1)  # WBITS = 16
    n = len(data)
    if n == 0:
        bw.write(1, 1)  # ISLAST
        bw.write(1, 1)  # ISLASTEMPTY
        return bw.value()
    mv = memoryview(data)
    i = 0
    while i < n:
        chunk = mv[i:i + _MAX_MLEN]
        m = len(chunk) - 1  # MLEN - 1
        nibbles = 4 if m < (1 << 16) else 5 if m < (1 << 20) else 6
        bw.write(0, 1)              # ISLAST = 0
        bw.write(nibbles - 4, 2)    # MNIBBLES
        bw.write(m, nibbles * 4)    # MLEN - 1
        bw.write(1, 1)             # ISUNCOMPRESSED = 1
        bw.align()                 # raw bytes are byte-aligned
        bw.buf.extend(chunk)
        i += len(chunk)
    bw.write(1, 1)  # final meta-block: ISLAST = 1
    bw.write(1, 1)  # ISLASTEMPTY = 1  -> 0x03
    return bw.value()
