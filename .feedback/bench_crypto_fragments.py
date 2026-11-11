"""
Benchmark: cost of CRYPTO fragment reassembly versus fragment count.

The total payload is fixed; the number of CRYPTO fragments (and of duplicate
/ overlapping retransmissions) grows. Two layers are measured:

1. ``QuicStreamReceiver.handle_frame`` -- the reassembly buffer backing each
   crypto epoch's stream.
2. ``QuicConnection._handle_crypto_frame`` -- the full path from the CRYPTO
   frame to the TLS input buffer, with ``tls.handle_message`` replaced by a
   sink so no TLS parsing of the garbage payload takes place.

Run from the repository root:

    .venv/bin/python .feedback/bench_crypto_fragments.py

On the unpatched RangeSet (flat list), the gapped-reverse pattern costs
O(fragments^2) pointer moves; with the blocked RangeSet the per-fragment
cost is flat.
"""

import argparse
import sys
import time

sys.path.insert(0, "src")

from aioquic import tls  # noqa: E402
from aioquic.buffer import Buffer, encode_uint_var  # noqa: E402
from aioquic.quic.configuration import QuicConfiguration  # noqa: E402
from aioquic.quic.connection import QuicConnection, QuicReceiveContext  # noqa: E402
from aioquic.quic.packet import QuicFrameType, QuicStreamFrame  # noqa: E402
from aioquic.quic.stream import QuicStreamReceiver  # noqa: E402


def gapped_reverse_frames(total, frag_size):
    """
    Yield (offset, data) covering [0, total): fragments at even strides in
    reverse order (maximizing disjoint buffered ranges), then the gaps.
    """
    stride = 2 * frag_size
    first = [(off, bytes([off & 0xFF]) * frag_size) for off in range(0, total, stride)]
    second = [
        (off, bytes([off & 0xFF]) * frag_size)
        for off in range(frag_size, total, stride)
    ]
    return first[::-1] + second


def duplicate_frames(total, frag_size, rounds):
    """
    Yield the payload once, leaving a gap at the start, then `rounds` of
    duplicate and overlapping retransmissions of the buffered window, then
    the gap-filling fragment.
    """
    base = [(off, b"d" * frag_size) for off in range(frag_size, total, frag_size)]
    frames = list(base)
    for r in range(rounds):
        # exact duplicates
        frames.extend(base)
        # overlapping fragments, shifted by half a fragment
        frames.extend(
            (off + frag_size // 2, b"o" * frag_size)
            for off in range(frag_size, total - frag_size, frag_size)
        )
    frames.append((0, b"g" * frag_size))
    return frames


def bench_receiver(frames):
    receiver = QuicStreamReceiver(stream_id=None, readable=True)
    start = time.perf_counter()
    delivered = 0
    for offset, data in frames:
        event = receiver.handle_frame(QuicStreamFrame(offset=offset, data=data))
        if event is not None:
            delivered += len(event.data)
    elapsed = time.perf_counter() - start
    return elapsed, delivered


class ConnectionHarness:
    """
    Drive QuicConnection._handle_crypto_frame with a TLS input sink.
    """

    def __init__(self):
        self.client = QuicConnection(configuration=QuicConfiguration(is_client=True))
        self.client.connect(("1.2.3.4", 443), now=0.0)
        self.received = bytearray()

        def tls_input_sink(input_data, output_buf):
            self.received.extend(input_data)

        self.client.tls.handle_message = tls_input_sink
        self.context = QuicReceiveContext(
            epoch=tls.Epoch.INITIAL,
            host_cid=self.client.host_cid,
            network_path=self.client._network_paths[0],
            quic_logger_frames=[],
            time=0.0,
            version=None,
        )

    def handle_frame(self, offset, data):
        self.client._handle_crypto_frame(
            self.context,
            QuicFrameType.CRYPTO,
            Buffer(data=encode_uint_var(offset) + encode_uint_var(len(data)) + data),
        )


def bench_connection(frames):
    harness = ConnectionHarness()
    start = time.perf_counter()
    for offset, data in frames:
        harness.handle_frame(offset, data)
    elapsed = time.perf_counter() - start
    return elapsed, len(harness.received)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--total",
        type=int,
        default=256 * 1024,
        help="total payload bytes (default: 256 KiB)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="skip the largest fragment counts",
    )
    args = parser.parse_args()
    total = args.total

    print(f"total payload: {total} bytes\n")
    print(
        f"{'pattern':<16} {'frag':>6} {'frames':>8} {'receiver':>10} "
        f"{'connection':>11} {'conn us/frame':>14}"
    )
    frag_sizes = [4096, 1024, 256, 64, 16, 4, 1]
    if args.quick:
        frag_sizes = frag_sizes[:4]
    for frag_size in frag_sizes:
        frames = gapped_reverse_frames(total, frag_size)
        expected = sum(len(data) for _, data in frames)
        assert expected == total

        recv_time, recv_delivered = bench_receiver(frames)
        assert recv_delivered == total, (recv_delivered, total)

        conn_time, conn_delivered = bench_connection(frames)
        assert conn_delivered == total, (conn_delivered, total)

        n = len(frames)
        print(
            f"{'gapped-reverse':<16} {frag_size:>6} {n:>8} "
            f"{recv_time:>9.3f}s {conn_time:>10.3f}s {conn_time / n * 1e6:>13.2f}"
        )

    # duplicate / overlapping retransmissions over a fixed window
    print()
    for rounds in [10, 40] if args.quick else [10, 40, 160]:
        frames = duplicate_frames(total, 256, rounds)
        recv_time, recv_delivered = bench_receiver(frames)
        assert recv_delivered == total, (recv_delivered, total)
        conn_time, conn_delivered = bench_connection(frames)
        assert conn_delivered == total, (conn_delivered, total)
        n = len(frames)
        print(
            f"{'dup+overlap x' + str(rounds):<16} {256:>6} {n:>8} "
            f"{recv_time:>9.3f}s {conn_time:>10.3f}s {conn_time / n * 1e6:>13.2f}"
        )


if __name__ == "__main__":
    main()
