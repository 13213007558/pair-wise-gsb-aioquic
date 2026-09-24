from typing import Optional

from .configuration import SMALLEST_MAX_DATAGRAM_SIZE

# RFC 8899 section 5.1.2: the number of consecutive probe losses after
# which a datagram size is considered to be black-holed.
MAX_PROBE_FAILURES = 3

# RFC 9000 section 18.2: the default value of the max_udp_payload_size
# transport parameter.
DEFAULT_MAX_UDP_PAYLOAD_SIZE = 65527


class QuicMtuProber:
    """
    DPLPMTUD prober for a single network path, as described in RFC 8899
    and applied to QUIC by RFC 9000 section 14.4.

    The usable datagram size for the path starts at the base size (the
    smallest allowed QUIC datagram size) and is only raised once a probe
    of a larger size has been acknowledged by the peer.
    """

    def __init__(self, *, max_size: int) -> None:
        # the largest datagram size confirmed to work on the path
        self.validated_size = SMALLEST_MAX_DATAGRAM_SIZE

        # the search bounds
        self._max_size = max(max_size, SMALLEST_MAX_DATAGRAM_SIZE)
        self._search_max = self._max_size

        # the outstanding probe, if any
        self._probe_size: Optional[int] = None
        self._probe_failures = 0

    @property
    def max_size(self) -> int:
        """
        The maximum datagram size which can be probed.
        """
        return self._max_size

    def set_max_size(self, max_size: int) -> None:
        """
        Update the maximum datagram size which can be probed, for instance
        when the peer's max_udp_payload_size becomes known.
        """
        self._max_size = max(max_size, SMALLEST_MAX_DATAGRAM_SIZE)
        self._search_max = min(self._search_max, self._max_size)
        if self._probe_size is not None and self._probe_size > self._max_size:
            self._probe_size = None
            self._probe_failures = 0

    def get_probe(self) -> Optional[int]:
        """
        Return the size of the next probe to send, or None if no probe
        is currently needed.
        """
        if self._probe_size is not None or self.validated_size >= self._search_max:
            return None
        self._probe_size = (self.validated_size + self._search_max + 1) // 2
        return self._probe_size

    def on_probe_acked(self, size: int) -> Optional[int]:
        """
        Handle the acknowledgement of a probe, returning the newly
        validated datagram size if it increased.
        """
        if size != self._probe_size:
            return None
        self._probe_size = None
        self._probe_failures = 0
        if size > self.validated_size:
            self.validated_size = size
            return size
        return None

    def on_probe_lost(self, size: int) -> None:
        """
        Handle the loss of a probe.

        A single lost probe does not indicate the path cannot sustain the
        probed size, only repeated losses lower the search ceiling.
        """
        if size != self._probe_size:
            return
        self._probe_size = None
        self._probe_failures += 1
        if self._probe_failures >= MAX_PROBE_FAILURES:
            # the probed size is persistently black-holed, lower the
            # search ceiling and keep using the last validated size
            self._probe_failures = 0
            self._search_max = size - 1

    def reset(self) -> None:
        """
        Fall back to the base datagram size after a persistent black hole
        and restart probing.
        """
        self.validated_size = SMALLEST_MAX_DATAGRAM_SIZE
        self._search_max = self._max_size
        self._probe_size = None
        self._probe_failures = 0
