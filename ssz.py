"""
ssz-lite: minimal Ethereum SSZ (Simple Serialize) in pure Python.

Implements the core of the SSZ spec (https://ethereum.github.io/consensus-specs/ssz/simple-serialize):
  * serialize / deserialize of uintN, boolean, BytesN, Bytes (variable),
    Vector / List of basic types, and Containers (fixed + variable fields)
  * merkleization: hash_tree_root with SHA-256

Zero dependencies — stdlib only.

Types are expressed as small tuples:
    ('uint', 64)              uint64
    ('bool',)                 boolean
    ('bytes', 32)             Bytes32
    ('vbytes',)               Bytes (variable length)
    ('vector', elem, n)       fixed-size Vector
    ('list', elem, limit)     variable-size List
    ('container', [('name', type), ...])

>>> serialize(('uint', 16), 0x1234).hex()
'3412'
>>> serialize(('bool',), True).hex()
'01'
>>> deserialize(('uint', 32), bytes.fromhex('78563412'))
(305419896, 4)
"""

from hashlib import sha256
import math

# ---------------------------------------------------------------- types

def is_fixed_size(typ):
    kind = typ[0]
    if kind in ('uint', 'bool', 'bytes'):
        return True
    if kind in ('vbytes', 'list'):
        return False
    if kind == 'vector':
        return is_fixed_size(typ[1])
    if kind == 'container':
        return all(is_fixed_size(t) for _, t in typ[1])
    raise TypeError('unknown SSZ type: %r' % (typ,))


def fixed_size(typ):
    kind = typ[0]
    if kind == 'uint':
        return typ[1] // 8
    if kind == 'bool':
        return 1
    if kind == 'bytes':
        return typ[1]
    if kind == 'vector':
        return typ[2] * fixed_size(typ[1])
    if kind == 'container':
        return sum(fixed_size(t) for _, t in typ[1])
    raise TypeError('variable-size type has no fixed size: %r' % (typ,))


def _ser_parts(typ, value):
    """Return list of (is_fixed, bytes) parts for a composite value."""
    kind = typ[0]
    if kind == 'vector':
        elems = list(value)
        if len(elems) != typ[2]:
            raise ValueError('Vector needs exactly %d elements' % typ[2])
        fx = is_fixed_size(typ[1])
        return [(fx, serialize(typ[1], v)) for v in elems]
    if kind == 'list':
        elems = list(value)
        if len(elems) > typ[2]:
            raise ValueError('List longer than limit %d' % typ[2])
        return [(False, serialize(typ[1], v)) if not is_fixed_size(typ[1])
                else (True, serialize(typ[1], v)) for v in elems]
    if kind == 'container':
        parts = []
        for name, t in typ[1]:
            b = serialize(t, value[name])
            parts.append((is_fixed_size(t), b))
        return parts
    raise TypeError('not a composite type: %r' % (typ,))


def serialize(typ, value):
    """Serialize `value` of SSZ `typ` to bytes."""
    kind = typ[0]
    if kind == 'uint':
        return int(value).to_bytes(typ[1] // 8, 'little')
    if kind == 'bool':
        return b'\x01' if value else b'\x00'
    if kind == 'bytes':
        if len(value) != typ[1]:
            raise ValueError('Bytes%d needs exactly %d bytes' % (typ[1], typ[1]))
        return bytes(value)
    if kind == 'vbytes':
        return bytes(value)
    if kind in ('vector', 'list', 'container'):
        parts = _ser_parts(typ, value)
        if all(fixed for fixed, _ in parts):
            return b''.join(b for _, b in parts)
        head_len = sum(len(b) if fixed else 4 for fixed, b in parts)
        head, tail, cursor = bytearray(), bytearray(), head_len
        for fixed, b in parts:
            if fixed:
                head += b
            else:
                head += cursor.to_bytes(4, 'little')
                tail += b
                cursor += len(b)
        return bytes(head + tail)
    raise TypeError('unknown SSZ type: %r' % (typ,))


def deserialize(typ, data):
    """Deserialize bytes of SSZ `typ`; returns (value, bytes_consumed)."""
    kind = typ[0]
    if kind == 'uint':
        n = typ[1] // 8
        return int.from_bytes(data[:n], 'little'), n
    if kind == 'bool':
        if data[0] not in (0, 1):
            raise ValueError('invalid boolean byte')
        return bool(data[0]), 1
    if kind == 'bytes':
        return bytes(data[:typ[1]]), typ[1]
    if kind == 'vbytes':
        return bytes(data), len(data)
    if kind == 'container':
        return _deserialize_container(typ[1], bytes(data))
    if kind in ('vector', 'list'):
        return _deserialize_seq(typ, bytes(data))
    raise TypeError('unknown SSZ type: %r' % (typ,))


def _deserialize_container(fields, data):
    # split fixed section and offsets
    fixed_fields, var_fields, cursor, offsets = [], [], 0, []
    for name, t in fields:
        if is_fixed_size(t):
            fixed_fields.append((name, t))
            cursor += fixed_size(t)
        else:
            var_fields.append((name, t))
            offsets.append(int.from_bytes(data[cursor:cursor + 4], 'little'))
            cursor += 4
    total_fixed = cursor
    for name, off in zip([n for n, _ in var_fields], offsets):
        if off < total_fixed or off > len(data):
            raise ValueError('bad offset for field %r' % name)
    value, pos = {}, 0
    vi = 0
    for name, t in fields:
        if is_fixed_size(t):
            n = fixed_size(t)
            v, _ = deserialize(t, data[pos:pos + n])
            value[name] = v
            pos += n
        else:
            start = offsets[vi]
            end = offsets[vi + 1] if vi + 1 < len(offsets) else len(data)
            v, _ = deserialize(t, data[start:end])
            value[name] = v
            vi += 1
            pos += 4
    return value, len(data)


def _deserialize_seq(typ, data):
    kind, elem = typ[0], typ[1]
    if is_fixed_size(elem):
        n = fixed_size(elem)
        if len(data) % n:
            raise ValueError('data length not a multiple of element size')
        vals = [deserialize(elem, data[i:i + n])[0] for i in range(0, len(data), n)]
    else:
        if len(data) < 4:
            raise ValueError('no offsets in variable-size sequence')
        first = int.from_bytes(data[:4], 'little')
        count = first // 4
        offs = [int.from_bytes(data[4 * i:4 * i + 4], 'little') for i in range(count)]
        offs.append(len(data))
        vals = [deserialize(elem, data[a:b])[0] for a, b in zip(offs, offs[1:])]
    if kind == 'vector' and len(vals) != typ[2]:
        raise ValueError('Vector needs exactly %d elements' % typ[2])
    if kind == 'list' and len(vals) > typ[2]:
        raise ValueError('List longer than limit %d' % typ[2])
    return vals, len(data)


# ---------------------------------------------------------------- merkleization

ZERO_HASHES = [b'\x00' * 32]
for _ in range(64):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())


def _pack(chunks):
    out = b''.join(chunks)
    out += b'\x00' * (-len(out) % 32)
    return [out[i:i + 32] for i in range(0, len(out), 32)] or [ZERO_HASHES[0]]


def _merkleize(chunks, limit):
    if limit == 0:
        return ZERO_HASHES[0]
    leaves = _pack(chunks)
    depth = max(1, math.ceil(math.log2(limit)))
    leaves += [ZERO_HASHES[0]] * (2 ** depth - len(leaves))
    layer = leaves
    for _ in range(depth):
        layer = [sha256(layer[i] + layer[i + 1]).digest()
                 for i in range(0, len(layer), 2)]
    return layer[0]


def _mix_in_length(root, length):
    return sha256(root + length.to_bytes(32, 'little')).digest()


def hash_tree_root(typ, value):
    """Compute the SSZ hash_tree_root of `value`."""
    kind = typ[0]
    if kind in ('uint', 'bool'):
        return _merkleize([serialize(typ, value)], 1)
    if kind == 'bytes':
        return _merkleize(_pack([bytes(value)]), max(1, (typ[1] + 31) // 32))
    if kind == 'vbytes':
        return _mix_in_length(
            _merkleize(_pack([bytes(value)]), 2 ** 32), len(value))
    if kind in ('vector', 'list'):
        leaves = _pack([serialize(typ[1], v) for v in value])
        elem_bytes = fixed_size(typ[1]) if is_fixed_size(typ[1]) else 32
        limit = (elem_bytes * typ[2] + 31) // 32
        root = _merkleize(leaves, max(1, limit))
        return root if kind == 'vector' else _mix_in_length(root, len(value))
    if kind == 'container':
        subs = [hash_tree_root(t, value[name]) for name, t in typ[1]]
        return _merkleize(subs, len(subs))
    raise TypeError('hash_tree_root not implemented for: %r' % (typ,))


# ---------------------------------------------------------------- demo

# Ethereum consensus-layer Fork container
Fork = ('container', [
    ('previous_version', ('bytes', 4)),
    ('current_version', ('bytes', 4)),
    ('epoch', ('uint', 64)),
])


def main():
    f = {'previous_version': b'\x00\x00\x00\x00',
         'current_version': b'\x01\x00\x00\x00', 'epoch': 74240}
    enc = serialize(Fork, f)
    print('Fork serialized (%d bytes): %s' % (len(enc), enc.hex()))

    back, n = deserialize(Fork, enc)
    assert n == len(enc) and back == f, 'round-trip failed'
    print('Round-trip OK:', back)

    root = hash_tree_root(Fork, f)
    print('hash_tree_root(Fork):', root.hex())

    vals = ('list', ('uint', 64), 8)
    print('hash_tree_root([1,2,3]):', hash_tree_root(vals, [1, 2, 3]).hex())

    # variable-size field inside a container (offsets in action)
    Msg = ('container', [
        ('sender', ('bytes', 20)),
        ('body', ('vbytes',)),
    ])
    m = {'sender': bytes(20), 'body': b'hello ssz'}
    enc2 = serialize(Msg, m)
    back2, _ = deserialize(Msg, enc2)
    assert back2 == m, 'variable container round-trip failed'
    print('Variable-size container round-trip OK (%d bytes)' % len(enc2))


if __name__ == '__main__':
    main()
