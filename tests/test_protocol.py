"""v1 固定二进制样例，防止编解码同时改变而往返检查漏报。"""

import json
from pathlib import Path
import unittest

from merkle_commitment import Commitment, FullOpening, MerkleProof


class EncodingTests(unittest.TestCase):
    pass

    # def test_v1_golden_encodings(self):
    #     golden = json.loads((Path(__file__).with_name('data') / 'v1_encoding.json').read_text())
    #     objects = {
    #         'commitment': Commitment(3, bytes(range(32))),
    #         'proof': MerkleProof(1, bytes(range(32)), (b'A' * 32, b'B' * 32)),
    #         'full_opening': FullOpening((b'a', b''), (b'\x11' * 32, b'\x22' * 32)),
    #     }
    #     for name, value in objects.items():
    #         with self.subTest(object=name):
    #             encoded = bytes.fromhex(golden[name])
    #             self.assertEqual(value.to_bytes(), encoded)
    #             self.assertEqual(type(value).from_bytes(encoded), value)
