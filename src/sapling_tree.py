"""Sapling commitment-tree roots and note authentication paths."""

from dataclasses import dataclass
from functools import lru_cache

from .coin_schemas import CoinNetworkConfig
from .jubjub import CURVE_D, FIELD_MODULUS, SCALAR_MODULUS, Point, find_group_hash

SAPLING_MERKLE_TREE_DEPTH = 32
_TREE_CAPACITY = 1 << SAPLING_MERKLE_TREE_DEPTH
_PEDERSEN_CHUNKS_PER_GENERATOR = 63
_PEDERSEN_GENERATOR_PERSONALIZATION = b"Zcash_PH"
_GROUP_IDENTITY = (0, 1, 1, 0)


class SaplingTreeError(ValueError):
    """Raised when commitment-tree input or witness data is invalid."""


def _validate_node(value, name):
    if not isinstance(value, bytes) or len(value) != 32:
        raise SaplingTreeError(f"{name} must be exactly 32 bytes")
    if int.from_bytes(value, "little") >= FIELD_MODULUS:
        raise SaplingTreeError(f"{name} is not a canonical Sapling field element")
    return value


def _point_add(left, right):
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % FIELD_MODULUS
    b = (y1 + x1) * (y2 + x2) % FIELD_MODULUS
    c = 2 * CURVE_D * t1 * t2 % FIELD_MODULUS
    d_term = 2 * z1 * z2 % FIELD_MODULUS
    e = (b - a) % FIELD_MODULUS
    f = (d_term - c) % FIELD_MODULUS
    g = (d_term + c) % FIELD_MODULUS
    h = (b + a) % FIELD_MODULUS
    return (
        e * f % FIELD_MODULUS,
        g * h % FIELD_MODULUS,
        f * g % FIELD_MODULUS,
        e * h % FIELD_MODULUS,
    )


def _point_multiply(point, scalar):
    x, y = point.u, point.v
    addend = (x, y, 1, x * y % FIELD_MODULUS)
    result = _GROUP_IDENTITY
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    z_inverse = pow(result[2], FIELD_MODULUS - 2, FIELD_MODULUS)
    return Point(
        result[0] * z_inverse % FIELD_MODULUS,
        result[1] * z_inverse % FIELD_MODULUS,
    )


@lru_cache(maxsize=1)
def _pedersen_generators():
    return tuple(
        find_group_hash(
            _PEDERSEN_GENERATOR_PERSONALIZATION,
            index.to_bytes(4, "little"),
        )
        for index in range(3)
    )


def _bits_le(value, count):
    return tuple((value >> bit) & 1 for bit in range(count))


def _pedersen_hash_point(bits):
    padded = list(bits)
    padded.extend((0,) * (-len(padded) % 3))
    result = None
    generators = _pedersen_generators()
    segment_count = (
        len(padded) + 3 * _PEDERSEN_CHUNKS_PER_GENERATOR - 1
    ) // (3 * _PEDERSEN_CHUNKS_PER_GENERATOR)
    if segment_count > len(generators):
        raise SaplingTreeError("Sapling Pedersen input exceeds supported length")

    for segment_index in range(segment_count):
        start = segment_index * 3 * _PEDERSEN_CHUNKS_PER_GENERATOR
        end = min(start + 3 * _PEDERSEN_CHUNKS_PER_GENERATOR, len(padded))
        accumulator = 0
        power = 1
        for offset in range(start, end, 3):
            s0, s1, s2 = padded[offset:offset + 3]
            chunk = (1 + s0 + 2 * s1) * (-1 if s2 else 1)
            accumulator = (
                accumulator + chunk * power
            ) % SCALAR_MODULUS
            power = power * 16 % SCALAR_MODULUS
        segment = _point_multiply(generators[segment_index], accumulator)
        result = segment if result is None else result + segment

    if result is None:
        raise SaplingTreeError("Sapling Pedersen input must not be empty")
    return result


def merkle_hash(depth, left, right):
    """Return a Sapling MerkleCRH parent for protocol personalization depth."""
    if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth < 32:
        raise SaplingTreeError("Sapling Merkle depth must be an integer in [0, 32)")
    left = _validate_node(left, "left node")
    right = _validate_node(right, "right node")
    bits = _bits_le(depth, 6)
    bits += _bits_le(int.from_bytes(left, "little"), 255)
    bits += _bits_le(int.from_bytes(right, "little"), 255)
    return _pedersen_hash_point(bits).u.to_bytes(32, "little")


def _combine_at_level(level, left, right):
    return merkle_hash(level, left, right)


@lru_cache(maxsize=1)
def _empty_roots():
    roots = [int(1).to_bytes(32, "little")]
    for depth in range(SAPLING_MERKLE_TREE_DEPTH):
        roots.append(_combine_at_level(depth, roots[depth], roots[depth]))
    return tuple(roots)


@dataclass(frozen=True)
class SaplingMerkleWitness:
    """A fixed-depth authentication path bound to a note and network."""

    note_commitment: bytes
    position: int
    tree_size: int
    authentication_path: tuple
    anchor: bytes
    coin_id: str
    network_id: str

    def __post_init__(self):
        _validate_node(self.note_commitment, "note commitment")
        _validate_node(self.anchor, "anchor")
        if (
            isinstance(self.position, bool)
            or not isinstance(self.position, int)
            or not 0 <= self.position < _TREE_CAPACITY
        ):
            raise SaplingTreeError(
                "Sapling note position must be an unsigned 32-bit integer"
            )
        if (
            isinstance(self.tree_size, bool)
            or not isinstance(self.tree_size, int)
            or not self.position < self.tree_size <= _TREE_CAPACITY
        ):
            raise SaplingTreeError(
                "witness tree size must be greater than its position and within capacity"
            )
        if not isinstance(self.authentication_path, tuple) or len(
            self.authentication_path
        ) != SAPLING_MERKLE_TREE_DEPTH:
            raise SaplingTreeError(
                "Sapling authentication path must contain exactly 32 nodes"
            )
        for node in self.authentication_path:
            _validate_node(node, "authentication path node")
        if not isinstance(self.coin_id, str) or not self.coin_id:
            raise SaplingTreeError("witness coin_id must be non-empty text")
        if not isinstance(self.network_id, str) or not self.network_id:
            raise SaplingTreeError("witness network_id must be non-empty text")
        if not self.verify():
            raise SaplingTreeError("Sapling authentication path does not match anchor")

    def calculate_root(self):
        node = self.note_commitment
        for depth, sibling in enumerate(self.authentication_path):
            if (self.position >> depth) & 1:
                node = _combine_at_level(depth, sibling, node)
            else:
                node = _combine_at_level(depth, node, sibling)
        return node

    def verify(self):
        return self.calculate_root() == self.anchor

    def update(self, tree):
        """Return this note's path at the current root of the same network tree."""
        if not isinstance(tree, SaplingCommitmentTree):
            raise TypeError("tree must be a SaplingCommitmentTree")
        if (self.coin_id, self.network_id) != (
            tree.network.coin_id,
            tree.network.network_id,
        ):
            raise SaplingTreeError("witness and tree network identities do not match")
        if tree.commitment_at(self.position) != self.note_commitment:
            raise SaplingTreeError("witness note is not present at this tree position")
        if tree.root_at(self.tree_size) != self.anchor:
            raise SaplingTreeError(
                "witness anchor does not match this tree's historical root"
            )
        return tree.witness(self.position)


class SaplingCommitmentTree:
    """Incremental Sapling commitment tree retaining leaves for path generation."""

    def __init__(self, network):
        if not isinstance(network, CoinNetworkConfig):
            raise TypeError("network must be a loaded coin network config")
        sapling = network.sapling
        if (
            sapling.get("status") not in (
                "supported_verified_parameters",
                "partial",
            )
            or sapling.get("activation_height") is None
        ):
            raise SaplingTreeError(
                f"Sapling commitment trees are not configured for {network.coin_id}"
            )
        self.network = network
        self._size = 0
        self._frontier = [None] * SAPLING_MERKLE_TREE_DEPTH
        self._leaves = []
        self._levels_cache = None
        self._roots = [self.root]

    @property
    def size(self):
        return self._size

    @property
    def root(self):
        if self._size == _TREE_CAPACITY:
            return self._frontier[SAPLING_MERKLE_TREE_DEPTH - 1]
        accumulator = _empty_roots()[0]
        count = self._size
        for depth in range(SAPLING_MERKLE_TREE_DEPTH):
            if count & 1:
                accumulator = _combine_at_level(
                    depth,
                    self._frontier[depth],
                    accumulator,
                )
            else:
                accumulator = _combine_at_level(
                    depth,
                    accumulator,
                    _empty_roots()[depth],
                )
            count >>= 1
        return accumulator

    def root_at(self, size):
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= self._size
        ):
            raise SaplingTreeError("tree size is outside the available history")
        return self._roots[size]

    def append(self, note_commitment):
        """Append one canonical Sapling commitment and return its global position."""
        node = _validate_node(note_commitment, "note commitment")
        if self._size >= _TREE_CAPACITY:
            raise SaplingTreeError("Sapling commitment tree is full")
        position = self._size
        carry = node
        cursor = position
        frontier = self._frontier.copy()
        for depth in range(SAPLING_MERKLE_TREE_DEPTH):
            if cursor & 1:
                left = frontier[depth]
                if left is None:
                    raise SaplingTreeError("Sapling tree frontier is inconsistent")
                carry = _combine_at_level(depth, left, carry)
                frontier[depth] = None
                cursor >>= 1
            else:
                frontier[depth] = carry
                break
        else:
            frontier[-1] = carry
        self._frontier = frontier
        self._leaves.append(node)
        self._levels_cache = None
        self._size += 1
        self._roots.append(self.root)
        return position

    def append_many(self, commitments):
        """Append commitments in caller-supplied consensus order."""
        positions = []
        for commitment in commitments:
            positions.append(self.append(commitment))
        return tuple(positions)

    def commitment_at(self, position):
        if (
            isinstance(position, bool)
            or not isinstance(position, int)
            or not 0 <= position < self._size
        ):
            raise SaplingTreeError("note position is outside this commitment tree")
        return self._leaves[position]

    def witness(self, position):
        if (
            isinstance(position, bool)
            or not isinstance(position, int)
            or not 0 <= position < self._size
        ):
            raise SaplingTreeError("note position is outside this commitment tree")
        levels = self._tree_levels()
        path = []
        for depth in range(SAPLING_MERKLE_TREE_DEPTH):
            sibling_index = (position >> depth) ^ 1
            level = levels[depth]
            path.append(
                level[sibling_index]
                if sibling_index < len(level)
                else _empty_roots()[depth]
            )
        return SaplingMerkleWitness(
            note_commitment=self._leaves[position],
            position=position,
            tree_size=self._size,
            authentication_path=tuple(path),
            anchor=self.root,
            coin_id=self.network.coin_id,
            network_id=self.network.network_id,
        )

    def _tree_levels(self):
        if self._levels_cache is not None:
            return self._levels_cache
        levels = [list(self._leaves)]
        for depth in range(SAPLING_MERKLE_TREE_DEPTH):
            current = levels[-1]
            following = [
                _combine_at_level(depth, current[index], current[index + 1])
                for index in range(0, len(current) - 1, 2)
            ]
            if len(current) & 1:
                following.append(
                    _combine_at_level(
                        depth,
                        current[-1],
                        _empty_roots()[depth],
                    )
                )
            levels.append(following)
        self._levels_cache = levels
        return levels


__all__ = [
    "SAPLING_MERKLE_TREE_DEPTH",
    "SaplingCommitmentTree",
    "SaplingMerkleWitness",
    "SaplingTreeError",
    "merkle_hash",
]
