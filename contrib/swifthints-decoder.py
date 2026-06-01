"""Standalone reference decoder for the SwiftHints (.dat) file format.

Written for clarity, not speed. It has no external dependencies and needs
Python 3.10+. The format is documented in doc/swifthints.md.

The three classes mirror the C++ decoder in src/rpc/blockchain.cpp:

    ANSDecoder        <->  struct ANSDecoder       (the rANS entropy decoder)
    SwiftHintsDecoder <->  class  SwiftHintDecoder  (decodes one group)
    SwiftHintsFileDecoder                           (Python-only wrapper over a
                                                      whole file; transparently
                                                      moves from group to group)

Decoding does not look at the UTXO set. It only needs, in order, the number of
outputs of every transaction from genesis up to the target block -- the same
information the C++ decoder reads from the block data. Group boundaries fall on
block boundaries, so a caller drives the file decoder block by block:

    dec = SwiftHintsFileDecoder(open("swifthints.dat", "rb").read())
    for block in blocks:                  # genesis first, up to the target block
        dec.begin_block()
        for tx in block.transactions:
            unspent = dec.decode_tx(len(tx.outputs))
            ...                            # unspent[i] is True iff output i is
                                           # unspent at the target height
    dec.finalize()
"""

from __future__ import annotations

# Number of probability contexts; see "Context model" in doc/swifthints.md.
NUM_CONTEXTS: int = 105


def swifthints_context(n: int, i: int, spent: int) -> int:
    """Return the context index (0..104) for output ``i`` of a transaction with
    ``n`` outputs, given that ``spent`` of the earlier outputs (indices < i) are
    spent. Identical to SwiftHintsContext() in the C++ source.
    """
    s = min(n, 7) - 1   # size class, 0..6
    p = min(i, 6)       # position class, 0..6
    if p < 6:
        return s * (s + 1) * (s + 2) // 6 + p * (p + 1) // 2 + spent
    return 77 + min(spent * 28 // i, 27)


class ANSDecoder:
    """Byte-wise range-ANS decoder with 8-bit renormalisation.

    Matches ``struct ANSDecoder``. It is constructed from the 3-byte
    little-endian initial state followed by the bitstream; bytes are pulled from
    the bitstream only when the state needs renormalising. The state stays in
    ``[0x10000, 0x1000000)``.
    """

    def __init__(self, data: bytes) -> None:
        self.data: bytes = data
        self.pos: int = 3  # bytes 0..2 are the initial state; the bitstream follows
        self.state: int = data[0] | (data[1] << 8) | (data[2] << 16)

    def get(self, qprob: int) -> bool:
        """Decode one boolean symbol whose probability of being True ("unspent")
        is ``qprob / 256``. ``qprob == 0`` means the symbol is never coded and is
        always False (the state is left untouched).
        """
        if qprob == 0:
            return False
        slot = self.state & 0xFF
        is_unspent = slot >= (256 - qprob)
        freq = qprob if is_unspent else (256 - qprob)
        start = (256 - qprob) if is_unspent else 0
        self.state = freq * (self.state >> 8) + slot - start
        while self.state < 0x10000:
            self.state = (self.state << 8) | self.data[self.pos]
            self.pos += 1
        return is_unspent


class SwiftHintsDecoder:
    """Decodes the outputs of a single group, including parsing the group's own
    header. Matches ``class SwiftHintDecoder``.

    Constructed from the whole file buffer ``data`` and the ``offset`` of the
    group's first byte. The first two bytes are the size field (total group size
    minus those two bytes), which directly gives ``group_size``; the next two bytes
    are the count field (low 15 bits = blocks-1, top bit = mode flag). It reads the
    probability table (replicating the single shared byte across all contexts for a
    compact group). After construction, ``nblocks`` is the number of blocks the group
    covers and ``group_size`` the number of bytes it occupies (so the caller can
    advance to the next group).
    """

    def __init__(self, data: bytes, offset: int) -> None:
        if offset + 4 > len(data):
            raise EOFError("unexpected end of file inside a group header")
        size_field = data[offset] | (data[offset + 1] << 8)
        count = data[offset + 2] | (data[offset + 3] << 8)
        self.group_size: int = 2 + size_field
        self.compact: bool = bool(count & 0x8000)
        self.nblocks: int = (count & 0x7FFF) + 1
        prob_bytes = 1 if self.compact else NUM_CONTEXTS
        end = offset + self.group_size
        if 4 + prob_bytes + 3 > self.group_size or end > len(data):
            raise EOFError("unexpected end of file inside a group")
        if self.compact:
            # Compact: a single shared probability, replicated across all contexts.
            self._qprob: bytes = bytes([data[offset + 4]]) * NUM_CONTEXTS
        else:
            # Full: NUM_CONTEXTS per-context probabilities.
            self._qprob = bytes(data[offset + 4:offset + 4 + NUM_CONTEXTS])
        body_off = offset + 4 + prob_bytes  # start of [3-byte state][bitstream]
        self._ans: ANSDecoder = ANSDecoder(data[body_off:end])

    def decode_tx(self, num_outputs: int) -> list[bool]:
        """Decode one transaction's outputs in order, returning one flag per
        output (True == unspent at the target height).
        """
        out: list[bool] = []
        spent_before = 0
        for i in range(num_outputs):
            ctx = swifthints_context(num_outputs, i, spent_before)
            unspent = self._ans.get(self._qprob[ctx])
            out.append(unspent)
            if not unspent:
                spent_before += 1
        return out

    @property
    def state(self) -> int:
        """The ANS state after the symbols decoded so far. Must equal ``0x10000``
        once the group's every output has been decoded (per-group checksum).
        """
        return self._ans.state


class SwiftHintsFileDecoder:
    """Decodes a whole swifthints file, transparently transitioning between
    groups as blocks are consumed.

    Locating each group, advancing from one to the next, and per-group checksum
    verification are handled here; the per-group header -- including the full/compact
    mode distinction -- is parsed by :class:`SwiftHintsDecoder`. Individual groups are
    never exposed. Because groups end on block boundaries and the file stores neither
    the transaction count per block nor the output count per transaction, the caller
    must mark block boundaries with :meth:`begin_block` (and call
    :meth:`finalize` once at the end); see the module docstring for the loop.
    """

    def __init__(self, data: bytes) -> None:
        self._data: bytes = bytes(data)
        self._pos: int = 0           # offset of the next unread group header
        self._blocks_left: int = 0   # blocks still to come in the current group
        self._decoder: SwiftHintsDecoder | None = None

    def begin_block(self) -> None:
        """Mark the start of a block. When the current group is exhausted this
        verifies its checksum and advances to the next group.
        """
        if self._blocks_left == 0:
            if self._decoder is not None:
                self._verify_checksum()  # the previous group is now complete
            self._load_group()
        self._blocks_left -= 1

    def decode_tx(self, num_outputs: int) -> list[bool]:
        """Decode one transaction's outputs from the current group, exactly like
        :meth:`SwiftHintsDecoder.decode_tx`.
        """
        if self._decoder is None:
            raise RuntimeError("begin_block() must be called before decode_tx()")
        return self._decoder.decode_tx(num_outputs)

    def finalize(self) -> None:
        """Call once after the last block: verifies the final group's checksum and
        that the whole file was consumed exactly.
        """
        if self._decoder is not None and self._blocks_left == 0:
            self._verify_checksum()
        if self._blocks_left != 0:
            raise ValueError("file ended in the middle of a group")
        if self._pos != len(self._data):
            raise ValueError("trailing data after the final group")

    # -- internals --------------------------------------------------------

    def _verify_checksum(self) -> None:
        assert self._decoder is not None
        if self._decoder.state != 0x10000:
            raise ValueError(f"ANS checksum mismatch (state=0x{self._decoder.state:x})")

    def _load_group(self) -> None:
        """Build the decoder for the group at ``self._pos`` and advance past it. The
        group decoder parses the header (mode, block count, probabilities) itself."""
        if self._pos >= len(self._data):
            raise EOFError("unexpected end of file: expected another group")
        self._decoder = SwiftHintsDecoder(self._data, self._pos)
        self._blocks_left = self._decoder.nblocks
        self._pos += self._decoder.group_size
