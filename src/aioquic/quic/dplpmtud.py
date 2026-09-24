import enum
import logging
from typing import Optional

from .configuration import SMALLEST_MAX_DATAGRAM_SIZE

# RFC 8899 section 5.1.2: the number of consecutive probe failures which
# are tolerated before the size being probed is considered too big.
K_MAX_PROBES = 3

# Stop the binary search once the remaining search interval is smaller
# than this number of bytes.
K_SEARCH_THRESHOLD = 16

# Interval between confirmation probes once the search has completed, used
# to detect changes in the size the path can sustain.
K_PROBE_INTERVAL = 30.0


class DplpmtudState(enum.Enum):
    # Probing to find a size larger than the current PLPMTU.
    SEARCH = 0
    # The search converged, the PLPMTU is periodically re-confirmed.
    SEARCH_COMPLETE = 1


class DplpmtudProber:
    """
    Sender-side DPLPMTUD state machine, as described in RFC 8899 and
    RFC 9000 section 14.3.

    The size currently validated for the path is available as `plpmtu`,
    it starts at the smallest allowed QUIC datagram size and is only ever
    raised when a probe is acknowledged.
    """

    def __init__(
        self,
        *,
        max_datagram_size: int,
        logger: Optional[logging.LoggerAdapter] = None,
    ) -> None:
        self.plpmtu = SMALLEST_MAX_DATAGRAM_SIZE
        self.state = DplpmtudState.SEARCH

        self._logger = logger

        # `cap` is the absolute ceiling (configuration and peer transport
        # parameters), `ceiling` is the current upper bound of the search.
        self._cap = max_datagram_size
        self._ceiling = max_datagram_size

        self._probe_count = 0
        self._probe_id = 0
        self._probe_in_flight: Optional[tuple[int, int]] = None
        self._probe_sent_at = 0.0

        self._confirm_pending = False
        self._timer_at: Optional[float] = None

    def get_timeout(self) -> Optional[float]:
        """
        Return the time at which the prober next needs to be woken up.
        """
        return self._timer_at

    def next_probe(self, now: float) -> Optional[tuple[int, int]]:
        """
        Return a `(probe_id, size)` tuple if a probe packet of `size` bytes
        should be sent, or `None` if no probe is currently due.
        """
        if self._probe_in_flight is not None:
            return None

        if self.state == DplpmtudState.SEARCH:
            if self._ceiling - self.plpmtu <= K_SEARCH_THRESHOLD:
                self._enter_search_complete(now=now)
                return None
            size = self.plpmtu + (self._ceiling - self.plpmtu) // 2
            return self._start_probe(size=size, now=now)

        if self.state == DplpmtudState.SEARCH_COMPLETE and self._confirm_pending:
            self._confirm_pending = False
            return self._start_probe(size=self.plpmtu, now=now)

        return None

    def on_probe_acked(self, probe_id: int) -> None:
        """
        Handle the acknowledgement of a probe packet.
        """
        if self._probe_in_flight is None or self._probe_in_flight[0] != probe_id:
            return
        _, size = self._probe_in_flight
        self._probe_in_flight = None
        self._probe_count = 0

        if size > self.plpmtu:
            if self._logger is not None:
                self._logger.debug("Path MTU raised to %d bytes", size)
            self.plpmtu = size

        if self.state == DplpmtudState.SEARCH_COMPLETE:
            # The confirmation probe succeeded, check whether the path can
            # now sustain a larger size.
            if self._cap - self.plpmtu > K_SEARCH_THRESHOLD:
                self._ceiling = self._cap
                self.state = DplpmtudState.SEARCH
                self._timer_at = None
            else:
                self._timer_at = self._probe_sent_at + K_PROBE_INTERVAL

    def on_probe_lost(self, probe_id: int) -> None:
        """
        Handle the loss of a probe packet.
        """
        if self._probe_in_flight is None or self._probe_in_flight[0] != probe_id:
            return
        _, size = self._probe_in_flight
        self._probe_in_flight = None
        self._probe_count += 1

        # A single lost probe is not enough to draw any conclusion.
        if self._probe_count < K_MAX_PROBES:
            if self.state == DplpmtudState.SEARCH_COMPLETE:
                self._confirm_pending = True
            return
        self._probe_count = 0

        if self.state == DplpmtudState.SEARCH:
            # The probed size is consistently lost, lower the search ceiling.
            self._ceiling = size - 1
            if self._ceiling - self.plpmtu <= K_SEARCH_THRESHOLD:
                self._enter_search_complete(now=self._probe_sent_at)
        else:
            # The path can no longer sustain the current PLPMTU, fall back
            # to the validated base size and start searching again.
            if self._logger is not None:
                self._logger.debug(
                    "Path MTU blackhole detected, falling back to %d bytes",
                    SMALLEST_MAX_DATAGRAM_SIZE,
                )
            self.plpmtu = SMALLEST_MAX_DATAGRAM_SIZE
            self._ceiling = self._cap
            self.state = DplpmtudState.SEARCH
            self._timer_at = None

    def on_timeout(self, now: float) -> None:
        """
        Handle the prober timer firing.
        """
        if (
            self.state == DplpmtudState.SEARCH_COMPLETE
            and self._timer_at is not None
            and now >= self._timer_at
        ):
            # Schedule a confirmation probe at the current PLPMTU.
            self._confirm_pending = True
            self._timer_at = None

    def reset(self) -> None:
        """
        Re-establish the probing state, for use when the network path changes.
        """
        self.plpmtu = SMALLEST_MAX_DATAGRAM_SIZE
        self.state = DplpmtudState.SEARCH
        self._ceiling = self._cap
        self._probe_count = 0
        self._probe_in_flight = None
        self._confirm_pending = False
        self._timer_at = None

    def set_ceiling(self, max_datagram_size: int) -> None:
        """
        Update the absolute ceiling for probes, for instance as the result
        of the peer's `max_udp_payload_size` transport parameter.
        """
        self._cap = max_datagram_size
        if self._ceiling > self._cap:
            self._ceiling = self._cap

    def _enter_search_complete(self, now: float) -> None:
        self.state = DplpmtudState.SEARCH_COMPLETE
        self._probe_count = 0
        if self.plpmtu > SMALLEST_MAX_DATAGRAM_SIZE:
            # Periodically confirm the path can still sustain the PLPMTU.
            self._timer_at = now + K_PROBE_INTERVAL
        else:
            self._timer_at = None

    def _start_probe(self, size: int, now: float) -> tuple[int, int]:
        self._probe_id += 1
        self._probe_in_flight = (self._probe_id, size)
        self._probe_sent_at = now
        return self._probe_in_flight
