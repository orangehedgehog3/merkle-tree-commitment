"""定义承诺和开封包含哪些字段，以及怎样把它们读写成字节。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple, Union

Message = Union[str, bytes]

VERSION = 1
HASH_BYTES = 32
NONCE_BYTES = 32
MAX_U64 = (1 << 64) - 1
VERSION_BYTES = 1
U64_BYTES = 8
DEPTH_BYTES = 2
MAX_PROOF_DEPTH = 64
# 三种编码都先写版本，再写一个 8 字节整数（数量或索引）。
INTEGER_END = VERSION_BYTES + U64_BYTES
COMMITMENT_BYTES = INTEGER_END + HASH_BYTES
PROOF_NONCE_END = INTEGER_END + NONCE_BYTES
PROOF_HEADER_BYTES = PROOF_NONCE_END + DEPTH_BYTES
FULL_HEADER_BYTES = INTEGER_END


def validate_u64(value: int) -> None:
    """检查 value 是能装进 8 字节的非负整数。"""
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError('expected an unsigned 64-bit integer')


def validate_leaf_count(n: int) -> None:
    """叶子数量至少为 1，并且能写进数量字段。"""
    validate_u64(n)
    if n == 0:
        raise ValueError('empty vectors are not supported')


def encode_u64(value: int) -> bytes:
    """把整数写成 8 字节，大端序让高位字节排在前面。"""
    validate_u64(value)
    return value.to_bytes(U64_BYTES, 'big')


def message_bytes(value: Message) -> bytes:
    """字符串先转成 UTF-8 字节；字节消息直接使用。"""
    if isinstance(value, str):
        return value.encode('utf-8')
    if type(value) is not bytes:
        raise TypeError('message must be bytes or UTF-8 str')
    return value


def _fixed_bytes(value: bytes, size: int, field: str) -> None:
    if type(value) is not bytes or len(value) != size:
        raise ValueError(f'{field} must be exactly {size} bytes')


def tree_depth(n: int) -> int:
    """补齐到 2 的幂后，从叶子走到根需要多少步。"""
    validate_leaf_count(n)
    return (n - 1).bit_length()


@dataclass(frozen=True)
class Commitment:
    """公开的叶子数量和承诺摘要，供验证者保存和比较。"""
    leaf_count: int
    root: bytes

    def __post_init__(self) -> None:
        validate_leaf_count(self.leaf_count)
        _fixed_bytes(self.root, HASH_BYTES, 'digest')

    def to_bytes(self) -> bytes:
        """依次写入版本、叶子数量和承诺摘要。"""
        return bytes([VERSION]) + encode_u64(self.leaf_count) + self.root

    @classmethod
    def from_bytes(cls, data: bytes) -> Commitment:
        """读回承诺；格式不完整或版本不对时抛出 ValueError。"""
        if type(data) is not bytes or len(data) != COMMITMENT_BYTES or data[0] != VERSION:
            raise ValueError('invalid commitment encoding')
        return cls(int.from_bytes(data[VERSION_BYTES:INTEGER_END], 'big'),
                   data[INTEGER_END:])


@dataclass(frozen=True)
class MerkleProof:
    """证明一个位置的消息：带上随机值和从叶子到根的兄弟摘要。"""
    index: int
    nonce: bytes
    siblings: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        validate_u64(self.index)
        _fixed_bytes(self.nonce, NONCE_BYTES, 'opening randomness')
        if type(self.siblings) is not tuple or len(self.siblings) > MAX_PROOF_DEPTH:
            raise ValueError('siblings must be a tuple of at most 64 digests')
        for sibling in self.siblings:
            _fixed_bytes(sibling, HASH_BYTES, 'digest')

    def to_bytes(self) -> bytes:
        """依次写入版本、索引、随机值、路径长度和兄弟摘要。"""
        return (bytes([VERSION]) + encode_u64(self.index) + self.nonce
                + len(self.siblings).to_bytes(DEPTH_BYTES, 'big') + b''.join(self.siblings))

    @classmethod
    def from_bytes(cls, data: bytes) -> MerkleProof:
        """按路径长度读取兄弟摘要，多出或缺少字节都报 ValueError。"""
        if type(data) is not bytes or len(data) < PROOF_HEADER_BYTES or data[0] != VERSION:
            raise ValueError('invalid proof encoding')
        depth = int.from_bytes(data[PROOF_NONCE_END:PROOF_HEADER_BYTES], 'big')
        if depth > MAX_PROOF_DEPTH or len(data) != PROOF_HEADER_BYTES + HASH_BYTES * depth:
            raise ValueError('invalid proof length')
        return cls(int.from_bytes(data[VERSION_BYTES:INTEGER_END], 'big'),
                   data[INTEGER_END:PROOF_NONCE_END],
                   tuple(data[i:i + HASH_BYTES] for i in range(PROOF_HEADER_BYTES, len(data), HASH_BYTES)))


@dataclass(frozen=True)
class MultiProof:
    """多个位置的随机值和去重认证节点，索引必须严格递增。"""
    indices: Tuple[int, ...]
    nonces: Tuple[bytes, ...]
    siblings: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.indices) is not tuple or not self.indices:
            raise ValueError('multiproof requires a non-empty tuple of indices')
        if type(self.nonces) is not tuple or len(self.nonces) != len(self.indices):
            raise ValueError('multiproof indices and nonces must have equal lengths')
        if any(type(index) is not int for index in self.indices):
            raise ValueError('multiproof indices must be integers')
        for index in self.indices:
            validate_u64(index)
        if tuple(sorted(set(self.indices))) != self.indices:
            raise ValueError('multiproof indices must be unique and increasing')
        for nonce in self.nonces:
            _fixed_bytes(nonce, NONCE_BYTES, 'opening randomness')
        if type(self.siblings) is not tuple or len(self.siblings) > MAX_PROOF_DEPTH * len(self.indices):
            raise ValueError('invalid multiproof sibling list')
        for sibling in self.siblings:
            _fixed_bytes(sibling, HASH_BYTES, 'digest')

    def to_bytes(self) -> bytes:
        """编码索引/随机值和去重摘要；消息由调用方另行提供。"""
        entries = b''.join(encode_u64(index) + nonce
                           for index, nonce in zip(self.indices, self.nonces))
        return (bytes([VERSION]) + encode_u64(len(self.indices)) + entries
                + encode_u64(len(self.siblings)) + b''.join(self.siblings))

    @classmethod
    def from_bytes(cls, data: bytes) -> MultiProof:
        """解析 multiproof 编码并拒绝截断或尾随数据。"""
        if type(data) is not bytes or len(data) < VERSION_BYTES + 2 * U64_BYTES or data[0] != VERSION:
            raise ValueError('invalid multiproof encoding')
        count = int.from_bytes(data[VERSION_BYTES:INTEGER_END], 'big')
        entries_end = INTEGER_END + count * (U64_BYTES + NONCE_BYTES)
        if count == 0 or entries_end + U64_BYTES > len(data):
            raise ValueError('invalid multiproof entry count')
        sibling_count = int.from_bytes(data[entries_end:entries_end + U64_BYTES], 'big')
        siblings_end = entries_end + U64_BYTES + sibling_count * HASH_BYTES
        if siblings_end != len(data):
            raise ValueError('invalid multiproof length')
        indices, nonces = [], []
        offset = INTEGER_END
        for _ in range(count):
            indices.append(int.from_bytes(data[offset:offset + U64_BYTES], 'big'))
            offset += U64_BYTES
            nonces.append(data[offset:offset + NONCE_BYTES])
            offset += NONCE_BYTES
        siblings_offset = entries_end + U64_BYTES
        siblings = tuple(data[siblings_offset + i * HASH_BYTES:
                      siblings_offset + (i + 1) * HASH_BYTES]
                         for i in range(sibling_count))
        return cls(tuple(indices), tuple(nonces), siblings)


@dataclass(frozen=True)
class FullOpening:
    """全部消息及各自的随机值，用于重建整棵树。"""
    messages: Tuple[bytes, ...]
    nonces: Tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.messages) is not tuple or type(self.nonces) is not tuple:
            raise ValueError('full opening requires immutable tuples')
        validate_leaf_count(len(self.messages))
        if len(self.messages) != len(self.nonces):
            raise ValueError('message/nonce counts differ')
        for value in self.messages:
            if type(value) is not bytes:
                raise TypeError('encoded messages must be bytes')
            validate_u64(len(value))
        for nonce in self.nonces:
            _fixed_bytes(nonce, NONCE_BYTES, 'opening randomness')

    def to_bytes(self) -> bytes:
        """写入版本和数量，再逐项写入消息长度、消息和随机值。"""
        return (bytes([VERSION]) + encode_u64(len(self.messages))
                + b''.join(encode_u64(len(m)) + m + r
                           for m, r in zip(self.messages, self.nonces)))

    @classmethod
    def from_bytes(cls, data: bytes) -> FullOpening:
        """用每项的长度找到消息末尾，紧接着读取 32 字节随机值。"""
        if type(data) is not bytes or len(data) < FULL_HEADER_BYTES or data[0] != VERSION:
            raise ValueError('invalid full opening encoding')
        n = int.from_bytes(data[VERSION_BYTES:INTEGER_END], 'big')
        if n == 0 or n > (len(data) - FULL_HEADER_BYTES) // (U64_BYTES + NONCE_BYTES):
            raise ValueError('invalid full opening count')
        messages, nonces, offset = [], [], FULL_HEADER_BYTES
        for _ in range(n):
            if offset + U64_BYTES > len(data):
                raise ValueError('truncated message length')
            length = int.from_bytes(data[offset:offset + U64_BYTES], 'big')
            offset += U64_BYTES
            end = offset + length
            if end + NONCE_BYTES > len(data):
                raise ValueError('truncated message or nonce')
            messages.append(data[offset:end])
            nonces.append(data[end:end + NONCE_BYTES])
            offset = end + NONCE_BYTES
        if offset != len(data):
            raise ValueError('trailing full opening bytes')
        return cls(tuple(messages), tuple(nonces))


