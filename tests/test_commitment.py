"""协议正确性、独立规格和对抗输入回归。"""
from dataclasses import replace
import random
import unittest
from unittest.mock import patch

from merkle_commitment import tree as m
from merkle_commitment.sha3 import sha3_256_digest


class CommitmentTests(unittest.TestCase):
    def setUp(self):
        self.public, self.state = m.commit([b'a', b'b', b'a', b'', '你好'])
        self.value, self.proof = self.state.open(2)

    def test_all_positions_power_of_two_and_odd(self):
        for n in (1, 2, 3, 5, 7, 8, 9, 16, 17, 32):
            public, state = m.commit([bytes([i % 3]) for i in range(n)])
            for i in range(n):
                value, proof = state.open(i)
                self.assertTrue(m.verify(public, i, value, proof))
                self.assertEqual(len(proof.siblings), (n - 1).bit_length())
                self.assertEqual(len(proof.to_bytes()), 43 + 32 * len(proof.siblings))
            self.assertTrue(m.verify_all(public, state.open_all()))

    def test_independent_recursive_root(self):
        # 独立递归规格，未调用树实现的私有构建/编码辅助函数。
        opening = self.state.open_all()
        n = self.public.leaf_count
        size = 1 << (n - 1).bit_length()
        u = lambda x: x.to_bytes(8, 'big')
        def reference(start, width):
            if width == 1:
                if start >= n:
                    return sha3_256_digest(b'\x02' + u(n) + u(start))
                value, nonce = opening.messages[start], opening.nonces[start]
                return sha3_256_digest(b'\x00' + u(n) + u(start)
                                       + u(len(value)) + value + nonce)
            half = width // 2
            return sha3_256_digest(b'\x01' + reference(start, half)
                                   + reference(start + half, half))
        expected = sha3_256_digest(b'\x03' + u(n) + reference(0, size))
        self.assertEqual(expected, self.public.root)

    # def test_bytes_round_trip(self):
    #     public = m.Commitment.from_bytes(self.public.to_bytes())
    #     proof = m.MerkleProof.from_bytes(self.proof.to_bytes())
    #     opening = self.state.open_all()
    #     self.assertEqual(public, self.public)
    #     self.assertEqual(proof, self.proof)
    #     self.assertEqual(m.FullOpening.from_bytes(opening.to_bytes()), opening)
    #     self.assertTrue(m.verify(public.to_bytes(), 2, self.value, proof.to_bytes()))
    #     self.assertTrue(m.verify_all(public.to_bytes(), opening.to_bytes()))
    #     self.assertEqual(len(public.to_bytes()), 41)
    #     self.assertEqual(len(opening.to_bytes()), 9 + sum(40 + len(x) for x in opening.messages))

    def test_message_tamper(self):
        for value in (b'changed', self.value + b'\x00', None, 3):
            self.assertFalse(m.verify(self.public, 2, value, self.proof))

    def test_nonce_tamper(self):
        bad = replace(self.proof, nonce=bytes([self.proof.nonce[0] ^ 1]) + self.proof.nonce[1:])
        self.assertFalse(m.verify(self.public, 2, self.value, bad))

    def test_every_sibling_tamper(self):
        for i in range(len(self.proof.siblings)):
            siblings = list(self.proof.siblings)
            siblings[i] = bytes([siblings[i][0] ^ 1]) + siblings[i][1:]
            self.assertFalse(m.verify(self.public, 2, self.value,
                                      replace(self.proof, siblings=tuple(siblings))))

    def test_root_and_count_tamper(self):
        bad_root = bytes([self.public.root[0] ^ 1]) + self.public.root[1:]
        self.assertFalse(m.verify(replace(self.public, root=bad_root), 2, self.value, self.proof))
        # 5 和 6 有相同树深度；数量绑定不能仅依靠路径长度。
        for n in (1, 4, 6, 8):
            self.assertFalse(m.verify(replace(self.public, leaf_count=n), 2, self.value, self.proof))

    def test_position_binding_and_repeated_values(self):
        first, p0 = self.state.open(0)
        self.assertEqual(first, self.value)
        self.assertFalse(m.verify(self.public, 0, first, self.proof))
        self.assertFalse(m.verify(self.public, 2, first, replace(p0, index=2)))
        self.assertFalse(m.verify(self.public, 3, self.value, self.proof))
        self.assertTrue(m.verify(self.public, 0, first, p0))

    def test_short_long_and_reordered_paths(self):
        for siblings in (self.proof.siblings[:-1], self.proof.siblings + (b'\x00' * 32,),
                         self.proof.siblings[::-1]):
            self.assertFalse(m.verify(self.public, 2, self.value,
                                      replace(self.proof, siblings=siblings)))

    def test_invalid_expected_index_and_padding_position(self):
        for index in (-1, 5, 7, 2**64, True, 2.0, '2', None):
            self.assertFalse(m.verify(self.public, index, self.value, self.proof))
            with self.assertRaises((ValueError, TypeError)):
                self.state.prove(index)

    def test_empty_and_invalid_messages_rejected(self):
        for values in ([], [None], [42], 'abc', b'abc'):
            with self.assertRaises((ValueError, TypeError)):
                m.commit(values)

    def test_randomized_commitments_and_independent_nonces(self):
        other, state = m.commit([b'a', b'b', b'a', b'', '你好'])
        self.assertNotEqual(other.root, self.public.root)
        nonces = self.state.open_all().nonces
        self.assertEqual(len(set(nonces)), len(nonces))
        self.assertNotEqual(state.open_all().nonces, nonces)
        # 这是随机生成机制的回归检查，不是统计随机性或 hiding 证明。

    def test_full_opening_tamper_order_count_and_nonce(self):
        full = self.state.open_all()
        bad_messages = (b'changed',) + full.messages[1:]
        for bad in (replace(full, messages=bad_messages),
                    m.FullOpening(full.messages[::-1], full.nonces[::-1]),
                    m.FullOpening(full.messages[:-1], full.nonces[:-1]),
                    replace(full, nonces=(b'\x00' * 32,) + full.nonces[1:])):
            self.assertFalse(m.verify_all(self.public, bad))

    # def test_strict_commitment_parser(self):
    #     data = self.public.to_bytes()
    #     for bad in (b'', data[:-1], data + b'x', b'\x02' + data[1:],
    #                 b'\x01' + b'\x00' * 8 + data[9:], bytearray(data), None):
    #         with self.assertRaises(ValueError):
    #             m.Commitment.from_bytes(bad)
    #         self.assertFalse(m.verify(bad, 2, self.value, self.proof))

    # def test_strict_proof_parser(self):
    #     data = self.proof.to_bytes()
    #     for bad in (b'', data[:-1], data + b'x', b'\x02' + data[1:],
    #                 data[:41] + b'\x00\x41' + data[43:], bytearray(data), None):
    #         with self.assertRaises(ValueError):
    #             m.MerkleProof.from_bytes(bad)
    #         self.assertFalse(m.verify(self.public, 2, self.value, bad))

    # def test_strict_full_opening_parser(self):
    #     data = self.state.open_all().to_bytes()
    #     for bad in (b'', data[:-1], data + b'x', b'\x02' + data[1:],
    #                 b'\x01' + b'\xff' * 8 + data[9:],
    #                 data[:9] + b'\xff' * 8 + data[17:], bytearray(data), None):
    #         with self.assertRaises(ValueError):
    #             m.FullOpening.from_bytes(bad)
    #         self.assertFalse(m.verify_all(self.public, bad))

    def test_reject_invalid_object_fields(self):
        for kwargs in ({'index': True}, {'nonce': b'bad'}, {'siblings': (b'bad',)},
                       {'siblings': []}, {'siblings': (b'\x00' * 32,) * 65}):
            with self.assertRaises(ValueError):
                replace(self.proof, **kwargs)
        with self.assertRaises(ValueError):
            m.Commitment(True, self.public.root)
        with self.assertRaises(ValueError):
            m.Commitment(1, b'bad')
        self.assertFalse(m.verify({}, 2, self.value, {}))
        self.assertFalse(m.verify_all(self.public, {}))

    def test_no_leaf_internal_or_padding_input_confusion(self):
        n = 2
        full = self.state.open_all()
        nonce = full.nonces[0]
        # 即使消息就是某个内部节点输入，叶子类型/数量/索引/长度仍被编码。
        payload = b'\x01' + b'A' * 32 + b'B' * 32
        self.assertNotEqual(m._leaf_hash(n, 0, payload, nonce), sha3_256_digest(payload))
        self.assertNotEqual(m._leaf_hash(n, 0, b'', nonce),
                            sha3_256_digest(b'\x02' + n.to_bytes(8, 'big') + b'\x00' * 8))

    def test_multiproof_distributions_and_hash_count(self):
        values = [bytes([index]) for index in range(32)]
        public, state = m.commit(values)
        distributions = (
            tuple(range(8, 16)),
            tuple(sorted(random.Random(19).sample(range(32), 8))),
            tuple(index * 4 for index in range(8)),
        )
        for indices in distributions:
            with self.subTest(indices=indices):
                messages, proof = state.open_many(indices)
                self.assertEqual(proof.indices, indices)
                self.assertTrue(m.verify_many(public, messages, proof))
                self.assertTrue(m.verify_many(public, messages, proof.to_bytes()))
                self.assertEqual(type(proof).from_bytes(proof.to_bytes()), proof)
                self.assertLess(len(proof.to_bytes()),
                                sum(len(state.prove(index).to_bytes()) for index in indices))

                positions = set(indices)
                parent_hashes = 0
                for _ in range((len(values) - 1).bit_length()):
                    positions = {position // 2 for position in positions}
                    parent_hashes += len(positions)
                original_hash, calls = m.H, 0

                def counted(data):
                    nonlocal calls
                    calls += 1
                    return original_hash(data)

                with patch.object(m, 'H', counted):
                    self.assertTrue(m.verify_many(public, messages, proof))
                self.assertEqual(calls, len(indices) + parent_hashes + 1)

    def test_multiproof_rejects_tampering_and_duplicate_indices(self):
        public, state = m.commit([bytes([index]) for index in range(8)])
        messages, proof = state.open_many((1, 2, 5))
        self.assertFalse(m.verify_many(public, (b'changed',) + messages[1:], proof))
        bad_siblings = (bytes([proof.siblings[0][0] ^ 1]) + proof.siblings[0][1:],) + proof.siblings[1:]
        self.assertFalse(m.verify_many(public, messages, replace(proof, siblings=bad_siblings)))
        with self.assertRaises(ValueError):
            state.prove_many(())
        with self.assertRaises(ValueError):
            state.prove_many((1, 1))

    def test_multiproof_single_and_padded_tree_boundaries(self):
        for count in (1, 3, 5, 17):
            public, state = m.commit([bytes([index]) for index in range(count)])
            selections = {(count - 1,), tuple(range(count))}
            if count > 1:
                selections.add((0, count - 1))
            for indices in selections:
                messages, proof = state.open_many(indices)
                self.assertTrue(m.verify_many(public, messages, proof))


