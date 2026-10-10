# ssz-lite

Minimal Ethereum **SSZ (Simple Serialize)** in pure Python — zero dependencies, stdlib only.

## What's inside

`ssz.py` implements the core of the [SSZ spec](https://ethereum.github.io/consensus-specs/ssz/simple-serialize):

- **Serialization / deserialization** of `uintN`, `boolean`, `BytesN`, variable-length `Bytes`, `Vector` / `List` of basic types, and `Container`s (fixed + variable-size fields with offsets)
- **Merkleization**: `hash_tree_root()` with SHA-256 (chunk packing, zero-hash padding, length mix-in)

## Types as tuples

```python
('uint', 64)              # uint64
('bool',)                 # boolean
('bytes', 32)             # Bytes32
('vbytes',)               # Bytes (variable length)
('vector', elem, n)       # fixed-size Vector
('list', elem, limit)     # variable-size List
('container', [('name', type), ...])
```

## Example

```python
from ssz import serialize, deserialize, hash_tree_root

Fork = ('container', [
    ('previous_version', ('bytes', 4)),
    ('current_version',  ('bytes', 4)),
    ('epoch',            ('uint', 64)),
])

f = {'previous_version': b'\x00\x00\x00\x00',
     'current_version':  b'\x01\x00\x00\x00',
     'epoch': 74240}

enc = serialize(Fork, f)            # 16 bytes, little-endian fields
back, n = deserialize(Fork, enc)    # round-trips exactly
root = hash_tree_root(Fork, f)      # 32-byte Merkle root
```

Run the demo:

```bash
python3 ssz.py
```

Doctests:

```bash
python3 -m doctest ssz.py -v
```

## Notes

- Only the consensus-critical subset is covered (no Bitvector/Bitlist packing, no generalized indices) — enough to understand how Ethereum serializes and Merkle-hashes its data structures.
- All math is explicit and commented, so the code doubles as a readable spec walkthrough.
