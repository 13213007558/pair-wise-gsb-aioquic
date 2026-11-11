# CRYPTO fragment reassembly benchmark

Measures the cost of the path from CRYPTO frame to TLS input buffer
(`QuicConnection._handle_crypto_frame` -> `QuicStreamReceiver.handle_frame`
-> TLS input) with a **fixed total payload** (256 KiB) while the **fragment
count grows** (fragment size 4096 down to 1 byte) and while **duplicate /
overlapping retransmissions grow**. Run from the repository root:

    .venv/bin/python .feedback/bench_crypto_fragments.py

## Growth term that was fixed

`RangeSet` stored its ranges in one flat `list`. Two of its operations cost
O(R) pointer moves each, where R is the number of disjoint buffered ranges:

- `add()` -> `list.insert()` / slice-merge for out-of-order fragments,
- `shift()` -> `list.pop(0)` when a filled gap releases the front range.

A peer sending many small, gapped, out-of-order CRYPTO fragments (up to
`MAX_PENDING_CRYPTO` = 512 KiB of buffering per epoch, i.e. up to ~512K
one-byte ranges) made reassembly cost **O(R^2)** pointer moves per
connection. `RangeSet` now stores ranges in blocks of at most
`2 * _BLOCK_SIZE` (128) ranges, so each operation only moves the ranges of
one block: O(R * B + R^2 / B^2), which is linear in R for the sizes at hand.
No limit on the number of legitimate fragments was added.

## Results (CPython 3.12.11, macOS arm64, 2026-11-11)

Connection-level path, gapped-reverse pattern (worst case: fragments at even
strides in reverse order, then the gaps filled front to back):

| fragment size | frames  | before    | after     | before us/frame | after us/frame |
|---------------|---------|-----------|-----------|-----------------|----------------|
| 4096          | 64      | 0.000 s   | 0.000 s   | 4.83            | 5.61           |
| 1024          | 256     | 0.001 s   | 0.001 s   | 3.11            | 3.33           |
| 256           | 1024    | 0.003 s   | 0.003 s   | 2.69            | 3.10           |
| 64            | 4096    | 0.011 s   | 0.011 s   | 2.69            | 2.81           |
| 16            | 16384   | 0.054 s   | 0.046 s   | 3.28            | 2.81           |
| 4             | 65536   | 0.364 s   | 0.178 s   | 5.56            | 2.72           |
| 1             | 262144  | 3.604 s   | 0.712 s   | 13.75           | 2.72           |

Before: per-frame cost grows with the fragment count (quadratic total).
After: per-frame cost is flat (linear total). Duplicate / overlapping
retransmissions were already linear and are unchanged:

| pattern         | frames  | before  | after   |
|-----------------|---------|---------|---------|
| dup+overlap x10 | 21474   | 0.043 s | 0.048 s |
| dup+overlap x40 | 82824   | 0.170 s | 0.183 s |
| dup+overlap x160| 328224  | 0.666 s | 0.729 s |

Correctness is covered by `tests/test_rangeset.py::RangeSetTest::test_stress`
(differential test against a naive model), and by receiver tests verifying
that gap placeholder bytes are never delivered as contiguous data and that
the per-epoch `MAX_PENDING_CRYPTO` limits are independent
(`tests/test_stream.py`, `tests/test_connection.py`).
