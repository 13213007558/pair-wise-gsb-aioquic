"""
RFC 9297 - HTTP Datagrams and the Capsule Protocol
"""

from collections.abc import Container
from typing import Optional

from aioquic.buffer import Buffer, BufferReadError, encode_uint_var


class CapsuleType:
    """
    Capsule types registered by RFC 9297.
    """

    DATAGRAM = 0x00


class CapsuleError(Exception):
    """
    The capsule protocol was violated.
    """


def encode_capsule(capsule_type: int, capsule_value: bytes) -> bytes:
    """
    Encode a capsule.

    A capsule consists of a variable-length integer type, a variable-length
    integer length and the value.
    """
    return (
        encode_uint_var(capsule_type)
        + encode_uint_var(len(capsule_value))
        + capsule_value
    )


class CapsuleParser:
    """
    Incremental parser for the RFC 9297 capsule protocol.

    Data can be fed in arbitrarily-sized chunks, the capsule header and value
    may be split at any byte boundary. Complete capsules with a known type
    are returned, capsules with an unknown type are skipped according to
    their declared length.

    The parser never allocates memory based on the declared capsule length,
    it only stores data which was actually received.
    """

    def __init__(self, known_types: Container[int] = (CapsuleType.DATAGRAM,)) -> None:
        self._known_types = known_types
        self._buffer = b""
        self._capsule_type: Optional[int] = None
        self._capsule_remaining = 0
        self._capsule_value = b""
        self._skip = False

    def feed_data(self, data: bytes) -> list[tuple[int, bytes]]:
        """
        Feed some received data and return any complete capsules as
        (capsule_type, capsule_value) tuples.
        """
        capsules: list[tuple[int, bytes]] = []
        self._buffer += data

        while self._buffer:
            # parse the capsule header
            if self._capsule_type is None:
                buf = Buffer(data=self._buffer)
                try:
                    capsule_type = buf.pull_uint_var()
                    capsule_length = buf.pull_uint_var()
                except BufferReadError:
                    # the header is incomplete, wait for more data
                    break
                self._capsule_type = capsule_type
                self._capsule_remaining = capsule_length
                self._capsule_value = b""
                self._skip = capsule_type not in self._known_types
                self._buffer = self._buffer[buf.tell() :]

            # consume capsule value bytes
            chunk = self._buffer[: self._capsule_remaining]
            if not self._skip:
                self._capsule_value += chunk
            self._capsule_remaining -= len(chunk)
            self._buffer = self._buffer[len(chunk) :]

            if self._capsule_remaining:
                # the capsule value is incomplete, wait for more data
                break

            # the capsule is complete
            if not self._skip:
                capsules.append((self._capsule_type, self._capsule_value))
            self._capsule_type = None

        return capsules

    def finalize(self) -> None:
        """
        Check that no truncated capsule remains.

        This must be called when the stream carrying the capsules is closed,
        a :class:`~aioquic.h3.capsule.CapsuleError` is raised if a capsule
        was truncated.
        """
        if self._capsule_type is not None or self._buffer:
            raise CapsuleError("Truncated capsule")
