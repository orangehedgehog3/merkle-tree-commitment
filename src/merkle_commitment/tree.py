"""把一组消息做成承诺，再用开封信息重算并核对承诺。"""

from secrets import token_bytes
from typing import Iterable, Sequence, Tuple, Union

from .sha3 import sha3_256_digest as H
from .protocol import (
    Commitment, FullOpening, MerkleProof, MultiProof, Message, NONCE_BYTES,
    encode_u64, message_bytes, tree_depth, validate_leaf_count, validate_u64,
)

# 前缀让四种哈希输入各有一个明确的类型。
LEAF_TAG = b'\x00'
PARENT_TAG = b'\x01'
PADDING_TAG = b'\x02'
COMMITMENT_TAG = b'\x03'


def _leaf_hash(n: int, index: int, message: bytes, nonce: bytes) -> bytes:
    # 记录数量、位置和消息长度，让同一段字节只有一种解释。
    return H(LEAF_TAG + encode_u64(n) + encode_u64(index)
             + encode_u64(len(message)) + message + nonce)


def _parent_hash(left: bytes, right: bytes) -> bytes:
    return H(PARENT_TAG + left + right)


def _levels(
    messages: Tuple[bytes, ...],
    nonces: Tuple[bytes, ...],
) -> Tuple[Tuple[bytes, ...], ...]:
    """第 0 层放叶子；每次两两合并，最后一层只剩树根。"""
    n = len(messages)
    capacity = 1 << tree_depth(n)
    leaves = [_leaf_hash(n, i, value, nonces[i])
              for i, value in enumerate(messages)]
    # 不够的位置填占位叶，使每层都能两两配对。
    leaves.extend(H(PADDING_TAG + encode_u64(n) + encode_u64(i))
                  for i in range(n, capacity))
    levels = [tuple(leaves)]
    while len(levels[-1]) > 1:
        row = levels[-1]
        levels.append(tuple(_parent_hash(row[i], row[i + 1])
                            for i in range(0, len(row), 2)))
    return tuple(levels)


def _root_hash(n: int, tree_root: bytes) -> bytes:
    """把真实叶子数量和树根一起哈希，得到最终承诺摘要。"""
    return H(COMMITMENT_TAG + encode_u64(n) + tree_root)


class MerkleTree:
    """承诺方保存的消息、随机值和各层摘要，用来生成开封。"""

    def __init__(self, messages: Iterable[Message]) -> None:
        if isinstance(messages, (str, bytes)):
            raise TypeError('expected a sequence of messages, not one string')
        self._messages = tuple(message_bytes(value) for value in messages)
        validate_leaf_count(len(self._messages))
        # 每个位置单独生成随机值，开封时只交出这个位置的随机值。
        self._nonces = tuple(token_bytes(NONCE_BYTES) for _ in self._messages)
        self._levels = _levels(self._messages, self._nonces)
        self.commitment = Commitment(
            len(self._messages),
            _root_hash(len(self._messages), self._levels[-1][0]),
        )

    def prove(self, index: int) -> MerkleProof:
        """按从叶子到根的顺序，收集这个位置的兄弟摘要。"""
        validate_u64(index)
        if index >= len(self._messages):
            raise ValueError('index outside committed vector')
        position, siblings = index, []
        for row in self._levels[:-1]:
            # 同层相邻两个节点是一对：0 和 1、2 和 3……
            # 翻转最低位找到兄弟，除以 2 则得到父节点的位置。
            siblings.append(row[position ^ 1])
            position //= 2
        return MerkleProof(index, self._nonces[index], tuple(siblings))

    def open(self, index: int) -> Tuple[bytes, MerkleProof]:
        """返回消息字节和证明；索引超出范围时抛出 ValueError。"""
        proof = self.prove(index)
        return self._messages[index], proof

    def prove_many(self, indices: Iterable[int]) -> MultiProof:
        """生成共享路径已合并的多位置证明，输入位置不可重复。"""
        selected = tuple(indices)
        if not selected:
            raise ValueError('at least one index is required')
        for index in selected:
            validate_u64(index)
            if index >= len(self._messages):
                raise ValueError('index outside committed vector')
        if len(set(selected)) != len(selected):
            raise ValueError('indices must be unique')
        selected = tuple(sorted(selected))
        positions = selected
        siblings = []
        for row in self._levels[:-1]:
            active = set(positions)
            for position in positions:
                sibling = position ^ 1
                if sibling not in active:
                    siblings.append(row[sibling])
            positions = tuple(sorted({position // 2 for position in positions}))
        return MultiProof(selected, tuple(self._nonces[index] for index in selected),
                          tuple(siblings))

    def open_many(self, indices: Iterable[int]) -> Tuple[Tuple[bytes, ...], MultiProof]:
        """返回按证明索引顺序排列的消息和合并证明。"""
        proof = self.prove_many(indices)
        return tuple(self._messages[index] for index in proof.indices), proof

    def open_all(self) -> FullOpening:
        """交出全部消息和随机值，供验证者重建整棵树。"""
        return FullOpening(self._messages, self._nonces)


def commit(messages: Iterable[Message]) -> Tuple[Commitment, MerkleTree]:
    """返回公开承诺和承诺方的树状态；输入应为非空消息列表或迭代器。"""
    tree = MerkleTree(messages)
    return tree.commitment, tree


def verify(
    commitment: Union[Commitment, bytes],
    index: int,
    message: Message,
    proof: Union[MerkleProof, bytes],
) -> bool:
    """用之前保存的承诺，检查指定位置的消息。

    承诺和证明可以传对象，也可以传编码后的字节。
    消息和位置都匹配时返回 True；不匹配或格式不对时返回 False。
    """
    try:
        if type(commitment) is bytes:
            commitment = Commitment.from_bytes(commitment)
        if type(proof) is bytes:
            proof = MerkleProof.from_bytes(proof)
        if type(commitment) is not Commitment or type(proof) is not MerkleProof:
            return False
        validate_u64(index)
        if index != proof.index or index >= commitment.leaf_count:
            return False
        if len(proof.siblings) != tree_depth(commitment.leaf_count):
            return False
        current = _leaf_hash(commitment.leaf_count, index, message_bytes(message), proof.nonce)
        position = index
        for sibling in proof.siblings:
            # 奇数位置是右孩子，兄弟放左边；偶数位置则相反。
            if position & 1:
                current = _parent_hash(sibling, current)
            else:
                current = _parent_hash(current, sibling)
            position //= 2
        return _root_hash(commitment.leaf_count, current) == commitment.root
    except (TypeError, ValueError, OverflowError):
        return False


def verify_many(
    commitment: Union[Commitment, bytes],
    messages: Sequence[Message],
    proof: Union[MultiProof, bytes],
) -> bool:
    """验证多个位置；消息顺序必须与 proof.indices 一致。"""
    try:
        if type(commitment) is bytes:
            commitment = Commitment.from_bytes(commitment)
        if type(proof) is bytes:
            proof = MultiProof.from_bytes(proof)
        if type(commitment) is not Commitment or type(proof) is not MultiProof:
            return False
        if isinstance(messages, (str, bytes)):
            return False
        values = tuple(message_bytes(value) for value in messages)
        if len(values) != len(proof.indices):
            return False
        if any(index >= commitment.leaf_count for index in proof.indices):
            return False

        active = {
            index: _leaf_hash(commitment.leaf_count, index, value, nonce)
            for index, value, nonce in zip(proof.indices, values, proof.nonces)
        }
        sibling_index = 0
        for _ in range(tree_depth(commitment.leaf_count)):
            parents = {}
            for position in sorted(active):
                parent = position // 2
                if parent in parents:
                    continue
                left_position = parent * 2
                right_position = left_position + 1
                left = active.get(left_position)
                right = active.get(right_position)
                if left is None:
                    left = proof.siblings[sibling_index]
                    sibling_index += 1
                if right is None:
                    right = proof.siblings[sibling_index]
                    sibling_index += 1
                parents[parent] = _parent_hash(left, right)
            active = parents
        if sibling_index != len(proof.siblings) or set(active) != {0}:
            return False
        return _root_hash(commitment.leaf_count, active[0]) == commitment.root
    except (IndexError, TypeError, ValueError, OverflowError):
        return False


def verify_all(
    commitment: Union[Commitment, bytes],
    opening: Union[FullOpening, bytes],
) -> bool:
    """按全部消息和随机值重建树，与保存的承诺比较。

    承诺和开封可以传对象或编码字节；不匹配或格式不对时返回 False。
    """
    try:
        if type(commitment) is bytes:
            commitment = Commitment.from_bytes(commitment)
        if type(opening) is bytes:
            opening = FullOpening.from_bytes(opening)
        if type(commitment) is not Commitment or type(opening) is not FullOpening:
            return False
        if len(opening.messages) != commitment.leaf_count:
            return False
        tree_root = _levels(opening.messages, opening.nonces)[-1][0]
        return _root_hash(commitment.leaf_count, tree_root) == commitment.root
    except (TypeError, ValueError, OverflowError):
        return False
