// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Standalone SwiftHints encoder.
//
// Reads a human-readable record file -- one line per block, "<height> <hash>: <tx> <tx> ...", where
// each <tx> is a string of 'U' (unspent at the target height) and 's' (spent), one character per
// output, exactly as written by `bitcoin-cli swifthints dump` -- and writes the compressed binary
// swifthints file. It needs no chain data, which is why it lives outside the node.
//
// The code is split in two layers. SwiftHintsEncoder encapsulates every encoding decision behind a
// StartBlock()/AddTx()/Finalize() interface: it knows nothing about the record text format, only
// about blocks and each transaction's per-output unspent flags, from which it derives contexts
// itself. ParseRecordFile is the higher-level driver that parses the record text and feeds that
// interface.
//
// The binary format is documented in doc/swifthints.md and is decoded by `bitcoin-cli swifthints
// decode`. This tool deliberately shares no code with the node: the context model below is
// duplicated from the decoder in src/rpc/blockchain.cpp and must stay byte-compatible with it.
//
// Usage: bitcoin-swifthints <record.txt> <output.dat> [num_candidates]

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

// ===========================================================================
// Context model -- duplicated from the decoder; must produce identical contexts.
// ===========================================================================

constexpr int SWIFTHINTS_NUM_CONTEXTS = 144;

// Context (0..143) for output i of a transaction with n outputs, given that `spent` of the earlier
// outputs in the same transaction are spent.
int SwiftHintsContext(int n, int i, int spent) noexcept {
    int s = std::min(n, 8) - 1;
    int p = std::min(i, 7);
    if (p < 7) return s * (s + 1) * (s + 2) / 6 + p * (p + 1) / 2 + spent;
    return 112 + std::min(spent * 32 / i, 31);
}

// ===========================================================================
// Encoder tunables and limits.
// ===========================================================================

// Lookahead window: the group-boundary DP runs once the queue holds at least num_candidates blocks and
// SWIFTHINTS_MIN_BYTES of estimated unsplit encoded size, or a hard cap is hit. The byte target is a
// flat absolute value (a parameter sweep on a full mainnet chain found the encoded size within ~0.02%
// of optimal for any window above ~150 KiB, so 240'000 leaves headroom as the chain grows).
constexpr size_t SWIFTHINTS_HARD_BLOCK_LIMIT = 150'000;
constexpr uint64_t SWIFTHINTS_HARD_OUTPUT_LIMIT = 100'000'000;
constexpr uint64_t SWIFTHINTS_MIN_BYTES = 240'000;
constexpr size_t SWIFTHINTS_DEFAULT_NUM_CANDIDATES = 256;

// A full-mode group stores (blocks - 1) in a 15-bit field; a compact-mode group in 7 bits.
constexpr int MAX_BLOCKS_PER_GROUP = 32768;
constexpr size_t MAX_BLOCKS_PER_GROUP_COMPACT = 128;
// Largest rANS bitstream per group; the header size field is a uint16_t and the small margin absorbs
// the gap between the entropy estimate and the actual encoded size.
constexpr uint64_t SWIFTHINTS_MAX_BITSTREAM_BYTES = 0xFFFF - 64;

// Coding costs are integers in units of 1/2^32 of a bit, so all decisions are deterministic and free
// of floating point. A total coded size up to 512 MiB (2^32 bits) fits in a uint64_t.
constexpr uint64_t SWIFTHINTS_COST_UNIT = (uint64_t{1} << 32);

// Cost of coding one symbol assigned quantized probability k/256, in 1/2^32-bit units:
// round(-2^32 * log2(k/256)). Entry 0 and 256 are 0. Hardcoded (computed once at 80-digit precision)
// so the values are identical on every platform.
constexpr std::array<uint64_t, 257> SWIFTHINTS_BITCOST = {
    0x0, 0x800000000, 0x700000000, 0x66a3fe5c6, 0x600000000, 0x5ad961ed1, 0x56a3fe5c6, 0x531513015,
    0x500000000, 0x4d47fcb8c, 0x4ad961ed1, 0x48a62b07f, 0x46a3fe5c6, 0x44caffb8e, 0x431513015, 0x417d60497,
    0x400000000, 0x3e99c0905, 0x3d47fcb8c, 0x3c087d28e, 0x3ad961ed1, 0x39b9115dc, 0x38a62b07f, 0x379f7d7f9,
    0x36a3fe5c6, 0x35b2c3da2, 0x34caffb8e, 0x33ebfb152, 0x331513015, 0x3245b5b85, 0x317d60497, 0x30bb9ca65,
    0x300000000, 0x2f4a29645, 0x2e99c0905, 0x2dee74ee6, 0x2d47fcb8c, 0x2ca6143a5, 0x2c087d28e, 0x2b6efe154,
    0x2ad961ed1, 0x2a47778ca, 0x29b9115dc, 0x292e05023, 0x28a62b07f, 0x28215ea5d, 0x279f7d7f9, 0x27206770b,
    0x26a3fe5c6, 0x262a2602b, 0x25b2c3da2, 0x253dbeecb, 0x24caffb8e, 0x245a7014e, 0x23ebfb152, 0x237f8cf50,
    0x231513015, 0x22ac7b854, 0x2245b5b85, 0x21e0b1ae9, 0x217d60497, 0x211bb32a6, 0x20bb9ca65, 0x205d0fba2,
    0x200000000, 0x1fa461a5f, 0x1f4a29645, 0x1ef14c760, 0x1e99c0905, 0x1e437bdbf, 0x1dee74ee6, 0x1d9aa2c3b,
    0x1d47fcb8c, 0x1cf67a860, 0x1ca6143a5, 0x1c56c2368, 0x1c087d28e, 0x1bbb3e095, 0x1b6efe154, 0x1b23b6cc5,
    0x1ad961ed1, 0x1a8ff9718, 0x1a47778ca, 0x19ffd6a74, 0x19b9115dc, 0x1973227d6, 0x192e05023, 0x18e9b414b,
    0x18a62b07f, 0x186365578, 0x18215ea5d, 0x17e012ba3, 0x179f7d7f9, 0x175f9b02b, 0x17206770b, 0x16e1df15f,
    0x16a3fe5c6, 0x1666c1caa, 0x162a2602b, 0x15ee27c0b, 0x15b2c3da2, 0x1577f73c8, 0x153dbeecb, 0x15041805f,
    0x14caffb8e, 0x1492734ac, 0x145a7014e, 0x1422f3836, 0x13ebfb152, 0x13b5845a8, 0x137f8cf50, 0x134a1296b,
    0x131513015, 0x12e08c064, 0x12ac7b854, 0x1278df6ca, 0x1245b5b85, 0x1212fc71a, 0x11e0b1ae9, 0x11aed391b,
    0x117d60497, 0x114c560fe, 0x111bb32a6, 0x10eb75e90, 0x10bb9ca65, 0x108c25c72, 0x105d0fba2, 0x102e58f74,
    0x100000000, 0xfd2035e9, 0xfa461a5f, 0xf7719715, 0xf4a29645, 0xf1d902a3, 0xef14c760, 0xec55d023,
    0xe99c0905, 0xe6e75e92, 0xe437bdbf, 0xe18d13ef, 0xdee74ee6, 0xdc465cd1, 0xd9aa2c3b, 0xd712ac0d,
    0xd47fcb8c, 0xd1f17a56, 0xcf67a860, 0xcce245f1, 0xca6143a5, 0xc7e49264, 0xc56c2368, 0xc2f7e831,
    0xc087d28e, 0xbe1bd491, 0xbbb3e095, 0xb94fe936, 0xb6efe154, 0xb493bc0f, 0xb23b6cc5, 0xafe6e714,
    0xad961ed1, 0xab49080f, 0xa8ff9718, 0xa6b9c06e, 0xa47778ca, 0xa238b516, 0x9ffd6a74, 0x9dc58e34,
    0x9b9115dc, 0x995ff71c, 0x973227d6, 0x95079e1a, 0x92e05023, 0x90bc3458, 0x8e9b414b, 0x8c7d6db7,
    0x8a62b07f, 0x884b00af, 0x86365578, 0x8424a633, 0x8215ea5d, 0x800a1996, 0x7e012ba3, 0x7bfb186c,
    0x79f7d7f9, 0x77f76275, 0x75f9b02b, 0x73feb984, 0x7206770b, 0x7010e168, 0x6e1df15f, 0x6c2d9fd4,
    0x6a3fe5c6, 0x6854bc51, 0x666c1caa, 0x64860025, 0x62a2602b, 0x60c13643, 0x5ee27c0b, 0x5d062b3b,
    0x5b2c3da2, 0x5954ad26, 0x577f73c8, 0x55ac8b9b, 0x53dbeecb, 0x520d979a, 0x5041805f, 0x4e77a385,
    0x4caffb8e, 0x4aea830d, 0x492734ac, 0x47660b27, 0x45a7014e, 0x43ea1201, 0x422f3836, 0x40766ef4,
    0x3ebfb152, 0x3d0afa7a, 0x3b5845a8, 0x39a78e26, 0x37f8cf50, 0x364c0493, 0x34a1296b, 0x32f83962,
    0x31513015, 0x2fac092e, 0x2e08c064, 0x2c67517f, 0x2ac7b854, 0x2929f0c7, 0x278df6ca, 0x25f3c65b,
    0x245b5b85, 0x22c4b263, 0x212fc71a, 0x1f9c95dc, 0x1e0b1ae9, 0x1c7b528b, 0x1aed391b, 0x1960cafa,
    0x17d60497, 0x164ce26c, 0x14c560fe, 0x133f7cde, 0x11bb32a6, 0x10387efc, 0xeb75e90, 0xd37ce1c,
    0xbb9ca65, 0xa3d503a, 0x8c25c72, 0x748ebf1, 0x5d0fba2, 0x45a8879, 0x2e58f74, 0x1720d9c,
    0x0,
};

// ===========================================================================
// Statistics and cost estimation.
// ===========================================================================

struct SwiftHintsStats {
    uint64_t m_unspent{0};
    uint64_t m_total{0};
    SwiftHintsStats& operator+=(const SwiftHintsStats& o) { m_unspent += o.m_unspent; m_total += o.m_total; return *this; }
    SwiftHintsStats& operator-=(const SwiftHintsStats& o) { m_unspent -= o.m_unspent; m_total -= o.m_total; return *this; }
    struct QuantizeResult {
        uint8_t m_qprob;   // quantized probability of "unspent" in 1/256 (0 = all spent)
        uint64_t m_cost;   // estimated coding cost in 1/2^32-bit units
    };
    // Optimal quantized probability and its coding cost. All-integer, hence deterministic.
    QuantizeResult Quantize() const {
        if (m_unspent == 0) return {0, 0};
        uint64_t spent = m_total - m_unspent;
        auto cost = [&](uint64_t q) -> uint64_t {
            return m_unspent * SWIFTHINTS_BITCOST[q] + spent * SWIFTHINTS_BITCOST[256 - q];
        };
        uint64_t q_lo = (m_unspent * 256) / m_total; // floor(unspent*256/total), clamped to [1,255]
        uint64_t q, c;
        if (q_lo < 1) { q = 1; c = cost(1); }
        else if (q_lo >= 255) { q = 255; c = cost(255); }
        else {
            uint64_t q_hi = q_lo + 1;
            uint64_t c_lo = cost(q_lo), c_hi = cost(q_hi);
            if (c_lo <= c_hi) { q = q_lo; c = c_lo; } else { q = q_hi; c = c_hi; }
        }
        return {static_cast<uint8_t>(q), c};
    }
};

struct SwiftHintsGroupStats {
    SwiftHintsStats m_ctx[SWIFTHINTS_NUM_CONTEXTS]{};
    SwiftHintsGroupStats& operator+=(const SwiftHintsGroupStats& o) {
        for (int i = 0; i < SWIFTHINTS_NUM_CONTEXTS; i++) m_ctx[i] += o.m_ctx[i];
        return *this;
    }
    SwiftHintsGroupStats& operator-=(const SwiftHintsGroupStats& o) {
        for (int i = 0; i < SWIFTHINTS_NUM_CONTEXTS; i++) m_ctx[i] -= o.m_ctx[i];
        return *this;
    }
    uint64_t TotalOutputs() const {
        uint64_t n = 0;
        for (const auto& s : m_ctx) n += s.m_total;
        return n;
    }
    uint64_t TotalUnspent() const {
        uint64_t n = 0;
        for (const auto& s : m_ctx) n += s.m_unspent;
        return n;
    }
    std::array<uint8_t, SWIFTHINTS_NUM_CONTEXTS> ComputeQuantizedProbabilities() const {
        std::array<uint8_t, SWIFTHINTS_NUM_CONTEXTS> qprob;
        for (int i = 0; i < SWIFTHINTS_NUM_CONTEXTS; i++) qprob[i] = m_ctx[i].Quantize().m_qprob;
        return qprob;
    }
    SwiftHintsStats Aggregate() const {
        SwiftHintsStats agg;
        for (const auto& s : m_ctx) agg += s;
        return agg;
    }
    // ceil((cost_units/UNIT + 16) / 8) bytes: bitstream size plus 16 bits for the final ANS state.
    static uint64_t CostBitsToBytes(uint64_t cost_units) {
        return (cost_units + 16 * SWIFTHINTS_COST_UNIT + 8 * SWIFTHINTS_COST_UNIT - 1) / (8 * SWIFTHINTS_COST_UNIT);
    }
    uint64_t EstimatedBitstreamBytes() const {
        uint64_t cost_units = 0;
        for (int i = 0; i < SWIFTHINTS_NUM_CONTEXTS; i++) cost_units += m_ctx[i].Quantize().m_cost;
        return CostBitsToBytes(cost_units);
    }
    uint64_t EstimatedBitstreamBytesSingle() const { return CostBitsToBytes(Aggregate().Quantize().m_cost); }
    uint64_t EstimatedBytes() const { return EstimatedBitstreamBytes() + 2 + 2 + SWIFTHINTS_NUM_CONTEXTS; }
};

constexpr uint64_t SWIFTHINTS_SEGMENT_INF = std::numeric_limits<uint64_t>::max();

// Estimated total encoded bytes for a `nblocks`-block segment, minimized over full and compact modes;
// SWIFTHINTS_SEGMENT_INF if neither mode can encode it (bitstream over the 16-bit field, or too many
// blocks). Full mode pays 2+2+144 header bytes, compact mode 1+2+1.
uint64_t SwiftHintsSegmentBytes(const SwiftHintsGroupStats& seg, size_t nblocks) {
    uint64_t best = SWIFTHINTS_SEGMENT_INF;
    if (nblocks <= (size_t)MAX_BLOCKS_PER_GROUP) {
        uint64_t bs = seg.EstimatedBitstreamBytes();
        if (bs <= SWIFTHINTS_MAX_BITSTREAM_BYTES) best = std::min(best, bs + 2 + 2 + SWIFTHINTS_NUM_CONTEXTS);
    }
    if (nblocks <= MAX_BLOCKS_PER_GROUP_COMPACT) {
        uint64_t bs = seg.EstimatedBitstreamBytesSingle();
        if (bs <= SWIFTHINTS_MAX_BITSTREAM_BYTES) best = std::min(best, bs + 1 + 2 + 1);
    }
    return best;
}

// One block's buffered records plus its precomputed per-context statistics (and a little bookkeeping
// used only for the per-group log).
struct QueuedBlock {
    std::vector<std::pair<uint8_t, bool>> m_records;
    SwiftHintsGroupStats m_stats;
    int m_height;
    size_t m_txs;
};

// ===========================================================================
// rANS encoder.
// ===========================================================================

struct ANSEncoder {
    uint32_t m_state{0x10000};
    std::vector<uint8_t> m_out; // produced bytes, in reverse order
    void Put(bool is_unspent, uint8_t qprob) {
        if (qprob == 0) return;
        uint32_t freq = is_unspent ? (uint32_t)qprob : (256u - qprob);
        uint32_t start = is_unspent ? (256u - qprob) : 0u;
        while (m_state >= (freq << 16)) { m_out.push_back(m_state & 0xFF); m_state >>= 8; }
        m_state = ((m_state / freq) << 8) + start + (m_state % freq);
    }
    std::vector<uint8_t> Finish() {
        // Write high-to-low so that after reverse(), the decoder reads the state little-endian.
        m_out.push_back((m_state >> 16) & 0xFF);
        m_out.push_back((m_state >> 8) & 0xFF);
        m_out.push_back(m_state & 0xFF);
        std::reverse(m_out.begin(), m_out.end());
        return std::move(m_out);
    }
};

inline void put_u8(std::ostream& o, uint8_t b) { o.put((char)b); }
inline void put_u16le(std::ostream& o, uint16_t v) { o.put((char)(v & 0xFF)); o.put((char)((v >> 8) & 0xFF)); }

struct EncodeResult { size_t blocks; uint64_t outputs; size_t groups; uint64_t bytes; };

// ===========================================================================
// Encoder.
//
// SwiftHintsEncoder owns every encoding decision and the output stream. The driver feeds it blocks via
// StartBlock()/AddTx()/Finalize(); it knows nothing about the record text format -- only blocks and
// each transaction's per-output unspent flags, from which it derives contexts itself.
//
// Internally, each finished block becomes the (context, is_unspent) records of one block plus that
// block's per-context statistics, appended to a FIFO queue. The queue grows until it holds enough
// lookahead (num_candidates blocks and SWIFTHINTS_MIN_BYTES) or a hard cap is hit; then the first
// group is emitted and removed, and the process repeats. Finalize() drains whatever remains.
//
// FindGroupLength chooses each group boundary by a dynamic program over a candidate grid (denser at
// the front of the window), with oversize grid cells subdivided so a valid partition always exists.
// The DP partition is then improved at exact-block resolution by three local-search passes that split
// groups and move/merge splits. Only the first resulting group is committed each call.
// ===========================================================================

class SwiftHintsEncoder
{
public:
    SwiftHintsEncoder(std::ostream& out, size_t num_candidates) : m_out(out), m_num_candidates(num_candidates) {}

    // Begin a new block. The block in progress (if any) is committed to the lookahead queue first.
    void StartBlock() {
        FlushBlock();
        m_in_block = true;
        m_cur_records.clear();
        m_cur_stats = SwiftHintsGroupStats{};
        m_cur_txs = 0;
    }

    // Add one transaction of the current block. unspents[i] is nonzero iff output i is unspent at the
    // target height; the encoder derives each output's context itself.
    void AddTx(std::span<const uint8_t> unspents) {
        const int n = (int)unspents.size();
        int spent_before = 0;
        for (int i = 0; i < n; i++) {
            bool u = unspents[i] != 0;
            const int ctx = SwiftHintsContext(n, i, spent_before);
            m_cur_records.push_back({(uint8_t)ctx, u});
            m_cur_stats.m_ctx[ctx].m_unspent += u;
            m_cur_stats.m_ctx[ctx].m_total += 1;
            if (!u) spent_before++;
            m_nout++;
        }
        m_cur_txs++;
    }

    // Commit the final block and drain the queue. Returns the totals.
    EncodeResult Finalize() {
        FlushBlock();
        while (!m_queue.empty()) EmitGroup(FindGroupLength());
        return {m_nblocks, m_nout, m_ngroups, m_nbytes};
    }

private:
    // Commit the in-progress block to the queue, then emit groups while the window is full enough.
    void FlushBlock() {
        if (!m_in_block) return;
        m_in_block = false;
        m_queue_stats += m_cur_stats;
        m_queue.push_back({std::move(m_cur_records), m_cur_stats, (int)m_nblocks, m_cur_txs});
        m_cur_records.clear(); // restore to a known-empty state after the move
        m_nblocks++;

        // Emit groups while a hard cap forces it or the window has reached its soft minimum lookahead.
        for (;;) {
            bool force = m_queue.size() >= SWIFTHINTS_HARD_BLOCK_LIMIT ||
                         m_queue_stats.TotalOutputs() >= SWIFTHINTS_HARD_OUTPUT_LIMIT;
            bool have_lookahead = m_queue.size() >= m_num_candidates &&
                                  m_queue_stats.EstimatedBytes() >= SWIFTHINTS_MIN_BYTES;
            if (!force && !have_lookahead) break;
            EmitGroup(FindGroupLength());
        }
        if (m_nblocks % 100000 == 0) std::cerr << "swifthints: " << m_nblocks << " blocks read\n";
    }

    // Encode and write the first nblocks of the queue as one group, then remove them.
    void EmitGroup(size_t nblocks) {
        SwiftHintsGroupStats gstats;
        size_t group_outputs = 0, group_txs = 0;
        for (size_t b = 0; b < nblocks; b++) {
            gstats += m_queue[b].m_stats;
            group_outputs += m_queue[b].m_records.size();
            group_txs += m_queue[b].m_txs;
        }

        // Pick the cheaper of the two encodings. Compact mode (one shared probability instead of the
        // 144-byte table) is only available for short groups, and only chosen when it wins; the +4 /
        // +148 are the respective fixed-header overheads.
        bool compact = nblocks <= MAX_BLOCKS_PER_GROUP_COMPACT &&
                       gstats.EstimatedBitstreamBytesSingle() + 4 <
                           gstats.EstimatedBitstreamBytes() + (2 + 2 + SWIFTHINTS_NUM_CONTEXTS);

        std::array<uint8_t, SWIFTHINTS_NUM_CONTEXTS> qprob;
        uint8_t single_qprob = 0;
        if (compact) { single_qprob = gstats.Aggregate().Quantize().m_qprob; qprob.fill(single_qprob); }
        else { qprob = gstats.ComputeQuantizedProbabilities(); }

        // rANS-encode the group's records in reverse order (ANS is LIFO, so the decoder reads forward).
        ANSEncoder enc_ans;
        for (size_t b = nblocks; b-- > 0;) {
            const auto& recs = m_queue[b].m_records;
            for (size_t j = recs.size(); j-- > 0;) enc_ans.Put(recs[j].second, qprob[recs[j].first]);
        }
        auto enc = enc_ans.Finish(); // [3-byte ANS state][bitstream]

        if (enc.size() - 3 > 0xFFFF) throw std::runtime_error("Group bitstream too large for the file format");
        uint16_t bitstream_size = (uint16_t)(enc.size() - 3);
        size_t header_bytes;
        if (compact) {
            // 1-byte count (high bit set as the mode flag, low 7 bits = blocks-1), 2-byte size, 1 prob.
            put_u8(m_out, (uint8_t)(0x80 | (nblocks - 1)));
            put_u16le(m_out, bitstream_size);
            put_u8(m_out, single_qprob);
            header_bytes = 1 + 2 + 1;
        } else {
            // 2-byte count (high bit clear, remaining 15 bits = blocks-1, big-endian), 2-byte size,
            // 144-byte probability table.
            uint16_t nblocks_m1 = (uint16_t)(nblocks - 1);
            put_u8(m_out, (uint8_t)((nblocks_m1 >> 8) & 0x7F));
            put_u8(m_out, (uint8_t)(nblocks_m1 & 0xFF));
            put_u16le(m_out, bitstream_size);
            m_out.write((const char*)qprob.data(), (std::streamsize)qprob.size());
            header_bytes = 2 + 2 + SWIFTHINTS_NUM_CONTEXTS;
        }
        m_out.write((const char*)enc.data(), (std::streamsize)enc.size());

        size_t group_bytes = header_bytes + enc.size();
        m_nbytes += group_bytes;
        m_nout_encoded += group_outputs;

        // Detailed per-group progress to stderr.
        int gstart = m_queue.front().m_height;
        int gend = m_queue[nblocks - 1].m_height;
        double outs_per_tx = group_txs > 0 ? (double)group_outputs / group_txs : 0.0;
        double upct = group_outputs > 0 ? 100.0 * gstats.TotalUnspent() / group_outputs : 0.0;
        double bytes_per_block = (double)group_bytes / nblocks;
        double bits_per_output = group_outputs > 0 ? group_bytes * 8.0 / group_outputs : 0.0;
        char buf[384];
        std::snprintf(buf, sizeof(buf),
            "swifthints: group %zu (%s), %zu/%zu blocks (%d-%d), %zu txs, %zu outputs "
            "(%.2f/tx, %.2f%% unspent), %zu bytes (%.2f/block), %.4f bits/output, %llu outputs total",
            m_ngroups, compact ? "compact" : "full", nblocks, m_queue.size(), gstart, gend, group_txs,
            group_outputs, outs_per_tx, upct, group_bytes, bytes_per_block, bits_per_output,
            (unsigned long long)m_nout_encoded);
        std::cerr << buf << "\n";

        for (size_t b = 0; b < nblocks; b++) m_queue_stats -= m_queue[b].m_stats;
        m_queue.erase(m_queue.begin(), m_queue.begin() + nblocks);
        m_ngroups++;
    }

    // Choose how many leading blocks of the queue to emit as the next group.
    size_t FindGroupLength() {
        const size_t N = m_queue.size();

        // Candidate group-boundary positions: 0, N, and a grid in between, denser towards the front
        // (only the first boundary is committed, so near-term resolution matters most). The grid is
        // pos(i) = i + round((N-C) * i*(i-1) / (C*(C-1))), all-integer (deterministic); when candidates
        // are at least as plentiful as blocks (C >= N) every block boundary is a candidate.
        const size_t C = m_num_candidates;
        std::vector<size_t> pos;
        if (N <= C) {
            pos.reserve(N + 1);
            for (size_t b = 0; b <= N; b++) pos.push_back(b);
        } else {
            // The product (N-C)*i*(i-1) stays within uint64: this branch only runs when C < N, so both
            // factors are below N (at most SWIFTHINTS_HARD_BLOCK_LIMIT and the blocks in the file), so
            // it is below N^3 < 2^64 for any window under ~4.9 million blocks.
            std::vector<size_t> base;
            base.reserve(C + 1);
            const uint64_t a = N - C;
            const uint64_t denom = (uint64_t)C * (C - 1); // C^2 - C, with C >= 2 here
            for (size_t i = 0; i <= C; i++) {
                uint64_t num = a * (uint64_t)i * (uint64_t)(i - 1); // 0 for i = 0, 1
                size_t p = i + (size_t)((num + denom / 2) / denom);
                if (base.empty() || p != base.back()) base.push_back(p);
            }
            // A coarse back-of-window cell may exceed the per-group block or bitstream limit on its own,
            // leaving the DP no valid split inside it; subdivide any such cell (down to single blocks,
            // which always fit) so a valid partition always exists.
            pos.reserve(base.size());
            pos.push_back(0);
            std::function<void(size_t, size_t)> emit_fitting = [&](size_t lo, size_t hi) {
                if (hi - lo > 1) {
                    SwiftHintsGroupStats s;
                    for (size_t b = lo; b < hi; b++) s += m_queue[b].m_stats;
                    if (hi - lo > (size_t)MAX_BLOCKS_PER_GROUP ||
                        s.EstimatedBitstreamBytes() > SWIFTHINTS_MAX_BITSTREAM_BYTES) {
                        size_t mid = (lo + hi) / 2;
                        emit_fitting(lo, mid);
                        emit_fitting(mid, hi);
                        return;
                    }
                }
                pos.push_back(hi);
            };
            for (size_t g = 0; g + 1 < base.size(); g++) emit_fitting(base[g], base[g + 1]);
        }

        // Per-cell statistics: cell[g] aggregates the blocks [pos[g], pos[g+1]) of one grid cell.
        std::vector<SwiftHintsGroupStats> cell(pos.size() - 1);
        {
            size_t b = 0;
            for (size_t g = 0; g + 1 < pos.size(); g++)
                while (b < pos[g + 1]) cell[g] += m_queue[b++].m_stats;
        }

        // dp[k] = min total bytes to encode blocks [0, pos[k]) with boundaries only at candidates.
        constexpr uint64_t INF = SWIFTHINTS_SEGMENT_INF;
        std::vector<uint64_t> dp(pos.size(), INF);
        std::vector<size_t> prev(pos.size(), 0);
        dp[0] = 0;
        for (size_t k = 1; k < pos.size(); k++) {
            SwiftHintsGroupStats seg;
            for (size_t m = k; m-- > 0;) {
                seg += cell[m];
                if (pos[k] - pos[m] > (size_t)MAX_BLOCKS_PER_GROUP) break;
                uint64_t seg_total = SwiftHintsSegmentBytes(seg, pos[k] - pos[m]);
                if (seg_total == INF) break; // bitstream only grows; once no mode fits, stop
                if (dp[m] == INF) continue;
                uint64_t c = dp[m] + seg_total;
                if (c < dp[k]) { dp[k] = c; prev[k] = m; }
            }
        }
        // Largest candidate reachable by a valid partition (normally the last; safety net otherwise).
        size_t kmax = pos.size() - 1;
        while (kmax > 0 && dp[kmax] == INF) --kmax;

        // Reconstruct the partition of [0, pos[kmax]) front to back.
        std::vector<size_t> chain;
        for (size_t k = kmax;; k = prev[k]) { chain.push_back(k); if (k == 0) break; }
        std::reverse(chain.begin(), chain.end());
        if (chain.size() < 2) return std::min<size_t>(N, 1); // degenerate; emit one block

        // Boundaries in blocks; B[0]=0 and B.back()=pos[kmax] are fixed (the window end). The refinement
        // below moves boundaries to exact blocks and adds/removes them.
        std::vector<size_t> B(chain.size());
        for (size_t j = 0; j < chain.size(); j++) B[j] = pos[chain[j]];

        auto seg_cost = [&](size_t a, size_t c) -> uint64_t {
            SwiftHintsGroupStats s;
            for (size_t b = a; b < c; b++) s += m_queue[b].m_stats;
            return SwiftHintsSegmentBytes(s, c - a);
        };
        // Best block at which to split [a, c) into [a, p) + [p, c): {min combined size, p}.
        auto best_split = [&](size_t a, size_t c) -> std::pair<uint64_t, size_t> {
            SwiftHintsGroupStats segL; segL += m_queue[a].m_stats;          // [a, a+1)
            SwiftHintsGroupStats segR;
            for (size_t b = a + 1; b < c; b++) segR += m_queue[b].m_stats;  // [a+1, c)
            uint64_t best = INF; size_t bestp = a + 1;
            for (size_t p = a + 1; p < c; p++) {
                uint64_t t1 = SwiftHintsSegmentBytes(segL, p - a);          // [a, p); grows with p
                if (t1 == INF) break;
                uint64_t t2 = SwiftHintsSegmentBytes(segR, c - p);          // [p, c); shrinks with p
                if (t2 != INF && t1 + t2 < best) { best = t1 + t2; bestp = p; }
                if (p + 1 < c) { segL += m_queue[p].m_stats; segR -= m_queue[p].m_stats; }
            }
            return {best, bestp};
        };

        // One refinement pass: walk back to front, alternating split-group and move/merge-split. Every
        // applied operation strictly lowers the total estimated size, so a pass terminates.
        auto refine_pass = [&]() {
            size_t i = B.size() - 1; // group under consideration is [B[i-1], B[i])
            while (i >= 1) {
                if (B[i] - B[i - 1] >= 2) {
                    auto [bt, p] = best_split(B[i - 1], B[i]);
                    if (bt < seg_cost(B[i - 1], B[i])) {
                        B.insert(B.begin() + i, p);        // split into [B[i-1], p) and [p, old B[i])
                        continue;                          // re-attempt splitting the new left side
                    }
                }
                if (i >= 2) { // B[i-1] is an internal split
                    const size_t a = B[i - 2], b = B[i - 1], c = B[i];
                    const uint64_t cab = seg_cost(a, b), cbc = seg_cost(b, c);
                    const uint64_t cur = (cab == INF || cbc == INF) ? INF : cab + cbc;
                    const uint64_t rm = seg_cost(a, c);    // remove the split, merge into one group
                    auto [mb, mp] = best_split(a, c);      // best alternative split position (includes b)
                    if (rm != INF && (mb == INF || rm <= mb) && rm < cur) {
                        B.erase(B.begin() + (i - 1));       // merge
                        --i;
                        continue;
                    }
                    if (mb < cur) {
                        B[i - 1] = mp;                      // move the split
                        --i;
                        continue;
                    }
                }
                --i;
            }
        };
        for (int pass = 0; pass < 3; pass++) refine_pass();
        return B[1];
    }

    std::ostream& m_out;
    size_t m_num_candidates;

    // Lookahead queue of finished blocks and its running per-context statistics.
    std::deque<QueuedBlock> m_queue;
    SwiftHintsGroupStats m_queue_stats;

    // Running totals reported by Finalize() and used in the per-group log.
    uint64_t m_nout = 0, m_nbytes = 0, m_nout_encoded = 0;
    size_t m_ngroups = 0, m_nblocks = 0;

    // The block currently being assembled by StartBlock()/AddTx(), committed by FlushBlock().
    bool m_in_block = false;
    std::vector<std::pair<uint8_t, bool>> m_cur_records;
    SwiftHintsGroupStats m_cur_stats;
    size_t m_cur_txs = 0;
};

// ===========================================================================
// Record-file parser (higher-level driver).
//
// Parses the human-readable record text and feeds blocks/transactions into the encoder. This is the
// only code that understands the text format; the encoder above understands only blocks and flags.
// ===========================================================================

EncodeResult ParseRecordFile(std::istream& fin, std::ostream& out, size_t num_candidates)
{
    SwiftHintsEncoder enc(out, num_candidates);
    std::vector<uint8_t> unspents; // reused per-transaction scratch buffer
    std::string line;
    size_t lineno = 0;
    while (std::getline(fin, line)) {
        lineno++;
        const size_t colon = line.find(':');
        if (colon == std::string::npos)
            throw std::runtime_error("Malformed record line " + std::to_string(lineno) + " (missing ':')");

        enc.StartBlock();
        std::istringstream iss(line.substr(colon + 1));
        std::string tok;
        while (iss >> tok) {
            unspents.clear();
            unspents.reserve(tok.size());
            for (char ch : tok) {
                if (ch == 'U') unspents.push_back(1);
                else if (ch == 's') unspents.push_back(0);
                else throw std::runtime_error(std::string("Unexpected character '") + ch +
                                              "' in record line " + std::to_string(lineno));
            }
            enc.AddTx(unspents);
        }
    }
    return enc.Finalize();
}

} // namespace

int main(int argc, char* argv[])
{
    if (argc < 3 || argc > 4) {
        std::cerr << "Usage: " << (argc > 0 ? argv[0] : "bitcoin-swifthints")
                  << " <record.txt> <output.dat> [num_candidates]\n"
                     "  Compress a swifthints record file (as written by `bitcoin-cli swifthints dump`)\n"
                     "  into the binary swifthints format (decodable with `bitcoin-cli swifthints decode`).\n"
                     "  num_candidates (default " << SWIFTHINTS_DEFAULT_NUM_CANDIDATES
                  << ") trades a little size for speed. See doc/swifthints.md.\n"
                     "  Use /dev/stdin or /dev/stdout for the file arguments to pipe.\n";
        return 1;
    }
    const std::string in_path = argv[1], out_path = argv[2];
    size_t num_candidates = SWIFTHINTS_DEFAULT_NUM_CANDIDATES;
    if (argc == 4) {
        num_candidates = (size_t)std::strtoull(argv[3], nullptr, 10);
        if (num_candidates < 2) { std::cerr << "swifthints: error: num_candidates must be at least 2\n"; return 1; }
    }

    std::ifstream fin(in_path, std::ios::binary);
    if (!fin) { std::cerr << "swifthints: error: cannot open input file: " << in_path << "\n"; return 1; }
    std::ofstream fout(out_path, std::ios::binary | std::ios::trunc);
    if (!fout) { std::cerr << "swifthints: error: cannot open output file: " << out_path << "\n"; return 1; }

    try {
        EncodeResult r = ParseRecordFile(fin, fout, num_candidates);
        fout.flush();
        if (!fout) { std::cerr << "swifthints: error: writing output file failed\n"; return 1; }
        std::cerr << "swifthints: done. blocks=" << r.blocks << " outputs=" << r.outputs
                  << " groups=" << r.groups << " bytes=" << r.bytes << "\n";
    } catch (const std::exception& e) {
        std::cerr << "swifthints: error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
