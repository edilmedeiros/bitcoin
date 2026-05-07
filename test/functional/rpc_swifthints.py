#!/usr/bin/env python3
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the swifthints dump/decode RPC, the bitcoin-swifthints encoder tool, and the standalone
Python reference decoder in contrib/swifthints-decoder.py.

Builds a small chain with a mix of spent and unspent outputs, then checks that
  dump (RPC) -> encode (bitcoin-swifthints tool) -> decode (RPC)
round-trips the human-readable record file exactly. As an independent cross-check, the same encoded
files are also decoded by contrib/swifthints-decoder.py -- driven purely from block data fetched over
RPC -- which must reproduce the dump exactly. Encoding lives in the standalone tool (it needs no chain
data); the node only dumps and decodes.
"""

import importlib.util
import os
import re
import subprocess

from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)


class SwiftHintsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-fallbackfee=0.0002"]]
        self.rpc_timeout = 120

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def read_record(self, name):
        return (self.nodes[0].chain_path / name).read_text()

    def load_reference_decoder(self):
        """Import contrib/swifthints-decoder.py (its filename is not a valid module name, so load it
        by path) and stash its file decoder class."""
        path = os.path.join(self.config["environment"]["SRCDIR"], "contrib", "swifthints-decoder.py")
        spec = importlib.util.spec_from_file_location("swifthints_decoder", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.RefFileDecoder = module.SwiftHintsFileDecoder

    def reference_decode(self, node, dat_name, target_height):
        """Decode a .dat with the standalone Python reference decoder, driving it from block data
        fetched over RPC (one begin_block() per block, one decode_tx(n) per transaction with n its
        output count), and return the reconstructed record text in `swifthints dump` format. This
        exercises contrib/swifthints-decoder.py end to end without consulting the C++ decoder."""
        dec = self.RefFileDecoder((self.nodes[0].chain_path / dat_name).read_bytes())
        lines = []
        for h in range(target_height + 1):
            bh = node.getblockhash(h)
            block = node.getblock(bh, 2)  # verbosity 2: full transactions, so vout counts are present
            dec.begin_block()
            toks = ["".join("U" if u else "s" for u in dec.decode_tx(len(tx["vout"])))
                    for tx in block["tx"]]
            lines.append(f"{h} {bh}: " + " ".join(toks))
        dec.finalize()  # verifies every group's checksum and that the whole file was consumed
        return "\n".join(lines) + "\n"

    def encode(self, record_name, dat_name, num_candidates=None):
        """Run the bitcoin-swifthints encoder; return its parsed result dict ({blocks, outputs,
        groups, bytes}) on success or None on failure."""
        cmd = [self.swifthints_bin,
               str(self.nodes[0].chain_path / record_name),
               str(self.nodes[0].chain_path / dat_name)]
        if num_candidates is not None:
            cmd.append(str(num_candidates))
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return None
        m = re.search(r"blocks=(\d+) outputs=(\d+) groups=(\d+) bytes=(\d+)", res.stderr)
        assert m is not None, f"unexpected encoder output: {res.stderr!r}"
        return {"blocks": int(m.group(1)), "outputs": int(m.group(2)),
                "groups": int(m.group(3)), "bytes": int(m.group(4))}

    def run_test(self):
        node = self.nodes[0]
        self.swifthints_bin = os.path.join(self.config["environment"]["BUILDDIR"], "bin",
                                           "bitcoin-swifthints" + self.config["environment"]["EXEEXT"])
        if not os.path.isfile(self.swifthints_bin):
            raise SkipTest("bitcoin-swifthints has not been compiled")
        self.load_reference_decoder()

        # Build a chain that contains both spent and unspent outputs: mine past coinbase maturity, then
        # spend some coinbase outputs across several blocks.
        addr = node.getnewaddress()
        self.generatetoaddress(node, 150, addr)
        for _ in range(8):
            for _ in range(3):
                node.sendtoaddress(node.getnewaddress(), 0.1)
            self.generatetoaddress(node, 1, addr)
        self.generatetoaddress(node, 2, addr)

        tip = node.getbestblockhash()
        height = node.getblockcount()

        self.log.info("dump at the tip")
        d = node.swifthints(command="dump", blockhash=tip, record="rec.txt")
        assert_equal(d["blocks"], height + 1)
        assert_greater_than(d["outputs"], 0)
        assert_equal("groups" in d, False)  # dump returns only blocks/outputs
        assert_equal("bytes" in d, False)
        rec = self.read_record("rec.txt")
        # The record must contain both unspent ('U') and spent ('s') outputs.
        assert "U" in rec and "s" in rec
        assert_equal(rec.count("\n"), height + 1)  # one line per block, genesis..tip

        self.log.info("encode (standalone tool), then decode (RPC) and compare")
        e = self.encode("rec.txt", "sh.dat")
        assert e is not None
        assert_equal(e["blocks"], d["blocks"])
        assert_equal(e["outputs"], d["outputs"])
        assert_greater_than(e["groups"], 0)
        assert_greater_than(e["bytes"], 0)
        de = node.swifthints(command="decode", blockhash=tip, swifthints="sh.dat", record="rec_dec.txt")
        assert_equal(de["blocks"], d["blocks"])
        assert_equal(de["outputs"], d["outputs"])
        assert_equal(de["bytes"], e["bytes"])
        assert_equal(self.read_record("rec_dec.txt"), rec)

        self.log.info("decode with the Python reference decoder (contrib/swifthints-decoder.py)")
        assert_equal(self.reference_decode(node, "sh.dat", height), rec)

        self.log.info("encoding is deterministic (integer cost model, no floating point)")
        e2 = self.encode("rec.txt", "sh_det.dat")
        assert_equal(e2, e)  # identical reported stats
        assert_equal((node.chain_path / "sh.dat").read_bytes(),
                     (node.chain_path / "sh_det.dat").read_bytes())  # byte-identical output

        self.log.info("num_candidates argument is accepted and still round-trips")
        # num_candidates is the only encoder knob. A value below the chain length forces the
        # parabola-grid path; the result must still decode to the original record.
        for nc in (4, 2):
            assert self.encode("rec.txt", f"sh_nc{nc}.dat", num_candidates=nc) is not None
            node.swifthints(command="decode", blockhash=tip, swifthints=f"sh_nc{nc}.dat", record=f"rec_nc{nc}.txt")
            assert_equal(self.read_record(f"rec_nc{nc}.txt"), rec)
            # The reference decoder must agree on this differently-grouped file too.
            assert_equal(self.reference_decode(node, f"sh_nc{nc}.dat", height), rec)
        # num_candidates < 2 is rejected by the tool.
        assert_equal(self.encode("rec.txt", "bad.dat", num_candidates=1), None)

        self.log.info("dump/encode/decode at an earlier height exercises the chain rewind")
        early_height = height - 7
        early_hash = node.getblockhash(early_height)
        node.swifthints(command="dump", blockhash=early_hash, record="rec_e.txt")
        rec_e = self.read_record("rec_e.txt")
        assert_equal(rec_e.count("\n"), early_height + 1)
        assert rec_e != rec  # different target height -> different unspent set
        assert self.encode("rec_e.txt", "sh_e.dat") is not None
        node.swifthints(command="decode", blockhash=early_hash, swifthints="sh_e.dat", record="rec_e_dec.txt")
        assert_equal(self.read_record("rec_e_dec.txt"), rec_e)
        assert_equal(self.reference_decode(node, "sh_e.dat", early_height), rec_e)

        self.test_errors(node, tip)

    def test_errors(self, node, tip):
        self.log.info("RPC argument validation and error handling")

        # encode is no longer an RPC command.
        assert_raises_rpc_error(-8, "Unknown command",
                                node.swifthints, command="encode", record="rec.txt", swifthints="x.dat")
        assert_raises_rpc_error(-8, "Unknown command",
                                node.swifthints, command="frobnicate", blockhash=tip, record="x.txt")

        # Missing required, command-specific arguments.
        assert_raises_rpc_error(-8, "'dump' requires the 'blockhash' argument",
                                node.swifthints, command="dump", record="x.txt")
        assert_raises_rpc_error(-8, "'dump' requires the 'record' argument",
                                node.swifthints, command="dump", blockhash=tip)
        assert_raises_rpc_error(-8, "'decode' requires the 'swifthints' argument",
                                node.swifthints, command="decode", blockhash=tip, record="x.txt")
        assert_raises_rpc_error(-8, "'decode' requires the 'record' argument",
                                node.swifthints, command="decode", blockhash=tip, swifthints="x.dat")

        # Unknown block hash.
        assert_raises_rpc_error(-5, "Block not found",
                                node.swifthints, command="dump", blockhash="00" * 32, record="x.txt")

        # The encoder tool reports a clear failure on a missing input file.
        assert_equal(self.encode("does_not_exist.txt", "x.dat"), None)


if __name__ == '__main__':
    SwiftHintsTest(__file__).main()
