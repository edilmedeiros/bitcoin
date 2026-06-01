# SwiftHints file format

A *swifthints* file (`.dat`) records, for **every transaction output created from
the genesis block up to a chosen target block**, a single bit: whether that output
is still unspent at the target height. The bits are stored in transaction-output
order (genesis first), so the file is meaningful only together with the block data
it describes — it stores *just the spent/unspent bits*, not the transactions
themselves.

This document describes only the on-disk format and how to decode it. The encoder's
strategy for choosing where to split the chain into groups is summarised briefly at
the end, but it is not part of the format: any valid grouping decodes identically.

## Purpose and design goals

SwiftHints is intended to feed **SwiftSync**, a validation scheme that processes
blocks **in parallel**: knowing in advance which outputs are ever spent (within the
range up to the target) lets a node validate blocks without maintaining the
intermediate UTXO set between them, so blocks need not be processed in order. Two
properties of the format follow directly from that use:

* **Every group is decodable on its own.** Each group carries its own explicit
  probabilities and its own self-contained rANS stream; nothing in a group depends
  on data decoded from any earlier group. A consumer can therefore decode (or seek
  to, or distribute) groups independently and in parallel, matching SwiftSync's
  parallel block processing. This rules out the more usual approach of letting the
  coder's model carry over from one block to the next.

* **Decoder simplicity is prioritised over encoder simplicity.** A swifthints file
  is expected to be produced once and consumed many times, so cost is deliberately
  pushed to the encoder. rANS decoding is extremely cheap (a multiply, a few adds,
  and an occasional byte read per output, with no per-symbol model update). All the
  hard work — choosing group boundaries and per-context probabilities to minimise
  size — happens in the encoder, which can afford to spend time on it (see the
  appendix). The format itself is agnostic to how well the encoder does this.

## Informal overview

The spent/unspent bit of an output is highly predictable from cheap, locally
available features (how many outputs its transaction has, the output's position,
how many earlier outputs in the same transaction are already spent). SwiftHints
exploits this with **context modeling** and **entropy coding**
([entropy coding](https://en.wikipedia.org/wiki/Entropy_coding),
[context modeling](https://en.wikipedia.org/wiki/Context_model)):

* Each output is assigned to one of **105 contexts** computed from those features.
* For a contiguous range of blocks (a *group*), each context is given a single
  quantized probability of "unspent".
* The bits are then compressed with **range Asymmetric Numeral Systems (rANS)**
  ([Asymmetric numeral systems](https://en.wikipedia.org/wiki/Asymmetric_numeral_systems),
  J. Duda, [arXiv:1311.2540](https://arxiv.org/abs/1311.2540); see also the widely
  used [ryg_rans](https://github.com/rygorous/ryg_rans) implementation), which
  approaches the [Shannon entropy](https://en.wikipedia.org/wiki/Shannon_entropy)
  of the modelled bits.

The probabilities are **semi-static**, not adaptive: within a group they are fixed
and signalled explicitly in the header, rather than being learned on the fly and
updated as symbols are coded (as in adaptive arithmetic/range coding). The model
*does* vary across the chain — each group has its own probability table — so it
tracks changing chain statistics at group granularity, but it never depends on
previously coded data, which is what keeps groups independently decodable. Dividing
the chain into groups is thus a trade-off: more groups track local statistics more
tightly, fewer groups amortise the per-group probability table over more blocks.
Two group encodings exist: a *full* one that carries a probability per context, and
a *compact* one (a single shared probability) for short or anomalous block ranges
where the full table would not pay for itself.

The decoder walks blocks genesis → target, and for each output it reads one bit from
the rANS stream and emits it. The number of transactions per block and outputs per
transaction are taken from the actual block data, never stored in the file.

## File structure

A swifthints file is simply a **concatenation of groups**, with no file header,
magic bytes, or group count. Each group covers a contiguous, non-overlapping range
of blocks; group boundaries always fall between blocks. The groups in order cover
heights 0, 1, 2, … up to and including the target height. The decoder knows the
target height out of band and reads groups until those blocks are exhausted; a
clean end-of-file is expected immediately after the last group.

All multi-byte integers are **little-endian** (uint16 unless noted).

### Common header and group framing

Every group begins with the same **4-byte header**, regardless of mode:

| Offset | Size | Field | Description |
|-------:|-----:|-------|-------------|
| 0 | 2 | size | **Total group size minus these two bytes** — i.e. the number of bytes following the size field (the count field, the probability table, the state, and the bitstream). A reader can skip to the next group at `offset + 2 + size`. |
| 2 | 2 | count | Low **15 bits** hold `blocks − 1` (range **1 … 32768 blocks**); the **top bit** (bit 15) is the mode flag: `0` → full, `1` → compact. |

These two fields are all that's needed to walk the file group by group and learn how
many blocks each group covers, without decoding (or even understanding) the
probability/rANS payload — so that work can be delegated to lower-level code. The
size field is a uint16, so a group is at most `0xFFFF + 2` bytes; for a full group
that caps the state+bitstream at `0xFFFF − 2 − 105` bytes.

After the header comes the mode-specific payload:

### Mode 0 — full group (count top bit `0`)

| Offset | Size | Field | Description |
|-------:|-----:|-------|-------------|
| 4 | 105 | probabilities | One quantized probability byte per context, in context-index order 0 … 104. |
| 109 | 3 | initial state | Initial rANS decoder state, a 3-byte little-endian integer in `[0x10000, 0xFFFFFF]`. |
| 112 | … | bitstream | The rANS-coded bits (see below); its length is `size − 2 − 105 − 3`. |

Total group size: `4 + 105 + 3 + N` bytes (size field = `2 + 105 + 3 + N`).

### Mode 1 — compact group (count top bit `1`)

| Offset | Size | Field | Description |
|-------:|-----:|-------|-------------|
| 4 | 1 | probability | A single quantized probability byte, used for **every** context. |
| 5 | 3 | initial state | Initial rANS decoder state, a 3-byte little-endian integer in `[0x10000, 0xFFFFFF]`. |
| 8 | … | bitstream | The rANS-coded bits (see below); its length is `size − 2 − 1 − 3`. |

Total group size: `4 + 1 + 3 + N` bytes (size field = `2 + 1 + 3 + N`).

A compact group is exactly equivalent to a full group whose 105 probability bytes
are all identical; a decoder may simply replicate the single byte into a 105-entry
table and then use the mode-0 decode path unchanged.

## Context model

Every output is mapped to one of 105 contexts (indices `0 … 104`) from three
features:

* `n` — the number of outputs in the output's transaction,
* `i` — the output's index within that transaction (`0`-based),
* `spent` — how many outputs at indices `< i` in the same transaction are spent.

Let:

```
s = min(n, 7) − 1     // size class, 0..6
p = min(i, 6)         // position class, 0..6
```

The context is then:

```
if (p < 6)  context = s*(s+1)*(s+2)/6 + p*(p+1)/2 + spent
else        context = 77 + min(spent * 28 / i, 27)
```

The first branch lays out, for each size class `s`, a triangular block of
`(p, spent)` pairs (`spent` ranges `0 … p`), offset by the tetrahedral number
`s*(s+1)*(s+2)/6`. This accounts for contexts `0 … 76` (all positions `i < 6`,
across size classes). The second branch handles every output at position `i ≥ 6`
by bucketing the *fraction* of earlier outputs that are spent into 28 buckets,
giving contexts `77 … 104`. The total is exactly 105.

The decoder must compute the context for each output with the identical formula and
in the identical order the encoder used (see decoding order below), since the
context determines which probability is applied.

## Quantized probabilities

Each probability byte `t` encodes the probability that an output in its context is
**unspent**, as `t / 256`. Thus `t` ranges over `0 … 255`:

* `t = 0` means *every* output in that context (within this group) is spent. Such
  outputs are **not coded at all** — they contribute zero bits to the rANS stream
  and consume none when decoding.
* `t ∈ [1, 255]` gives `P(unspent) = t/256`. Probability exactly `1` is not
  representable (there is no `t = 256`); a context with at least one unspent output
  is therefore quantized to some `t ≥ 1`.

The probabilities are constant within a group and are not updated as outputs are
decoded.

## rANS coding

The bitstream uses **byte-wise range ANS** with 8-bit renormalisation. The
denominator is `256`; the state is a 32-bit value kept in the range
`[0x10000, 0x1000000)` (i.e. `[2^16, 2^24)`).

For a context with probability byte `t`, the unit interval `[0, 256)` is split into
two symbol slots:

* **spent** occupies `[0, 256 − t)` (frequency `256 − t`),
* **unspent** occupies `[256 − t, 256)` (frequency `t`).

### Decoding one output

Given the current `state` and the output's probability byte `t`:

```
if t == 0:                       // all-spent context: not coded, state unchanged
    is_unspent = false
else:
    slot       = state & 255
    is_unspent = (slot >= 256 − t)
    freq       = is_unspent ? t : (256 − t)
    start      = is_unspent ? (256 − t) : 0
    state      = freq * (state >> 8) + slot − start
    while state < 0x10000:       // renormalise: pull bytes from the bitstream
        state = (state << 8) | next_bitstream_byte
// the decoded output is unspent iff is_unspent
```

Bytes are consumed from the bitstream **in order**, left to right, only during the
renormalisation step.

### Decoding order

Outputs are decoded in natural forward order:

1. blocks by ascending height (within the group's range),
2. transactions by ascending index within a block,
3. outputs by ascending index within a transaction.

`spent` is tracked per transaction as outputs are decoded (reset to 0 at the start
of each transaction, incremented whenever a decoded output is spent). The number of
transactions in a block and outputs in a transaction come from the block data, not
the file.

### Initial and final state (checksum)

The encoder starts its state at `0x10000` and runs the inverse of the above
(encoding outputs in reverse order, since rANS is last-in-first-out, and writing
renormalisation bytes so that — after the byte sequence is reversed on disk — the
decoder reads them little-endian/front-to-back). The 3-byte stored state is the
encoder's final state, i.e. the decoder's starting state.

After all outputs of a group have been decoded, the state **must** have returned to
exactly `0x10000`. This serves as a per-group integrity check; any other value
indicates a corrupt file or a decode desynchronisation.

## Appendix: how the encoder chooses groups (non-normative)

The format permits *any* partition of the chain into groups (subject to the 32768
blocks-per-group limit and the 16-bit group-size field), and every valid partition
decodes to the same bits. The encoder merely tries to pick a partition that minimises
total file size.

The reference encoder (the standalone `bitcoin-swifthints` tool) works over a sliding
**lookahead window** of buffered blocks. It buffers blocks until the window is large
enough to choose the next boundary well — at least a configurable number of candidate
blocks *and* a minimum estimated size, or until a hard cap on blocks/outputs is hit —
then commits **one** group from the front of the window, drops those blocks, and
repeats. Choosing each boundary on a bounded window (rather than the whole chain at
once) is what keeps the encoder's time and memory roughly linear in the chain length.

For each window it picks boundaries in three stages:

1. **Candidate grid.** Rather than consider every block boundary (quadratic in the
   window size), it lays down a set of candidate boundary positions. The grid is
   **deliberately not evenly spaced**: it is *denser toward the front* of the window
   and coarser toward the back, because only the front-most group is actually
   committed, so near-term boundaries are placed at finer resolution than far ones.
   (When the window is no larger than the candidate count, every block boundary is a
   candidate.) Any grid cell large enough to exceed a group's block or bitstream limit
   is subdivided so a valid partition always exists.

2. **Cost-model dynamic program.** A DP over the candidate grid computes the
   minimum-total-size partition of the window using boundaries drawn from the grid.
   The cost of a candidate group is the smaller of its estimated full-mode and
   compact-mode sizes, under a deterministic integer entropy-cost model (so the
   encoder's decisions are reproducible across platforms).

3. **Exact-block refinement.** The grid-aligned partition is then improved at
   exact-block resolution by **several local-search passes** (the reference encoder
   runs three). Each pass walks the window's boundaries from back to front and, at
   each one, tries to lower the estimated total size by **splitting** a group at its
   best interior block, or **moving** an existing boundary to a better block, or
   **merging** two adjacent groups by removing a boundary; improving moves are applied
   and re-examined. This recovers the resolution the coarse grid gives up, so the
   committed front boundary is chosen at single-block precision.

Only the first group of the refined partition is committed each step; the rest of the
window is reconsidered after more blocks arrive. This grid-DP-plus-refinement scheme
approximates the size-optimal grouping closely while staying fast. None of it affects
decoding: any valid partition the encoder might choose decodes to the same bits, so a
different or improved encoder remains fully compatible.
