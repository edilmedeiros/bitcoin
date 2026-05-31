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
NUM_CONTEXTS: int = 144


def swifthints_context(n: int, i: int, spent: int) -> int:
    """Return the context index (0..143) for output ``i`` of a transaction with
    ``n`` outputs, given that ``spent`` of the earlier outputs (indices < i) are
    spent. Identical to SwiftHintsContext() in the C++ source.
    """
    s = min(n, 8) - 1   # size class, 0..7
    p = min(i, 7)       # position class, 0..7
    if p < 7:
        return s * (s + 1) * (s + 2) // 6 + p * (p + 1) // 2 + spent
    return 112 + min(spent * 32 // i, 31)


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
    """Decodes the outputs of a single group. Matches ``class SwiftHintDecoder``.

    ``data`` is the group body with the size/block-count header already stripped:
    ``NUM_CONTEXTS`` quantized-probability bytes, then the 3-byte ANS state, then
    the bitstream. A compact group is presented here as a full group whose
    ``NUM_CONTEXTS`` probability bytes are all identical, so this class does not
    need to know which mode produced it.
    """

    def __init__(self, data: bytes) -> None:
        self._qprob: bytes = data[:NUM_CONTEXTS]
        self._ans: ANSDecoder = ANSDecoder(data[NUM_CONTEXTS:])

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

    Group parsing, the full/compact mode distinction, and per-group checksum
    verification are all handled internally; individual groups are never exposed.
    Because groups end on block boundaries and the file stores neither the
    transaction count per block nor the output count per transaction, the caller
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
        """Parse the next group header at ``self._pos`` and build its decoder."""
        data, pos = self._data, self._pos
        if pos >= len(data):
            raise EOFError("unexpected end of file: expected another group")
        b0 = data[pos]
        pos += 1
        if b0 & 0x80:
            # Compact group: 7-bit block count, 2-byte size, one shared probability
            # replicated across all contexts so SwiftHintsDecoder stays uniform.
            bitstream_size = data[pos] | (data[pos + 1] << 8)
            pos += 2
            single_qprob = data[pos]
            pos += 1
            nblocks = (b0 & 0x7F) + 1
            body = bytes([single_qprob]) * NUM_CONTEXTS + data[pos:pos + 3 + bitstream_size]
            pos += 3 + bitstream_size
        else:
            # Full group: 15-bit big-endian block count, 2-byte size, 144 probs.
            b1 = data[pos]
            pos += 1
            bitstream_size = data[pos] | (data[pos + 1] << 8)
            pos += 2
            nblocks = (((b0 & 0x7F) << 8) | b1) + 1
            body = data[pos:pos + NUM_CONTEXTS + 3 + bitstream_size]
            pos += NUM_CONTEXTS + 3 + bitstream_size
        if pos > len(data):
            raise EOFError("unexpected end of file inside a group")
        self._decoder = SwiftHintsDecoder(body)
        self._blocks_left = nblocks
        self._pos = pos
