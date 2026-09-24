from enum import IntEnum
from typing import List, Optional, Tuple

from aioquic.buffer import UINT_VAR_MAX_SIZE, Buffer, BufferReadError


class CapsuleType(IntEnum):
    # https://datatracker.ietf.org/doc/html/rfc9297#section-3.2
    DATAGRAM = 0x00


# Capsule types which are delivered to the application, all other capsule
# types are skipped without buffering their value.
DELIVERED_CAPSULE_TYPES = frozenset([CapsuleType.DATAGRAM])


class CapsuleProtocolError(Exception):
    """
    The capsule protocol was violated, for instance a capsule was truncated.
    """


def encode_capsule(capsule_type: int, capsule_value: bytes) -> bytes:
    """
    Encode a capsule as defined by RFC 9297.

    :param capsule_type: The capsule type.
    :param capsule_value: The capsule value.
    """
    buf = Buffer(capacity=2 * UINT_VAR_MAX_SIZE + len(capsule_value))
    buf.push_uint_var(capsule_type)
    buf.push_uint_var(len(capsule_value))
    buf.push_bytes(capsule_value)
    return buf.data


class CapsuleDecoder:
    """
    Incremental decoder for RFC 9297 capsules.

    The capsule type and length are QUIC variable-length integers, and both
    the header and the value can be split at arbitrary byte boundaries.

    Capsules with an unknown type are skipped as their value trickles in,
    and values are only ever buffered up to the amount of data actually
    received, so a peer cannot force a large memory allocation by declaring
    a huge capsule length.
    """

    def __init__(self) -> None:
        self._header = b""
        self._value = b""
        self._capsule_type: Optional[int] = None
        self._remaining: Optional[int] = None

    def feed(self, data: bytes) -> List[Tuple[int, bytes]]:
        """
        Feed received data and return any completed capsules of known types
        as (capsule_type, capsule_value) tuples.
        """
        capsules: List[Tuple[int, bytes]] = []
        while data:
            if self._remaining is None:
                # we are still reading the capsule header
                self._header += data
                data = b""
                buf = Buffer(data=self._header)
                try:
                    capsule_type = buf.pull_uint_var()
                    capsule_length = buf.pull_uint_var()
                except BufferReadError:
                    break
                self._capsule_type = capsule_type
                self._remaining = capsule_length
                data = self._header[buf.tell() :]
                self._header = b""
                if not self._remaining:
                    # zero-length capsule
                    if self._capsule_type in DELIVERED_CAPSULE_TYPES:
                        capsules.append((self._capsule_type, b""))
                    self._capsule_type = None
                    self._remaining = None
            else:
                # we are reading the capsule value
                chunk_size = min(self._remaining, len(data))
                if self._capsule_type in DELIVERED_CAPSULE_TYPES:
                    self._value += data[:chunk_size]
                data = data[chunk_size:]
                self._remaining -= chunk_size
                if not self._remaining:
                    if self._capsule_type in DELIVERED_CAPSULE_TYPES:
                        capsules.append((self._capsule_type, self._value))
                        self._value = b""
                    self._capsule_type = None
                    self._remaining = None
        return capsules

    def finalize(self) -> None:
        """
        Check the capsule sequence ended on a capsule boundary, and raise a
        CapsuleProtocolError if a capsule was truncated.
        """
        if self._header or self._remaining is not None:
            raise CapsuleProtocolError("Truncated capsule")
