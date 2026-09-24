from unittest import TestCase

from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE, QuicConfiguration
from aioquic.quic.connection import END_STATES, QuicConnection
from aioquic.quic.dplpmtud import (
    K_MAX_PROBES,
    K_SEARCH_THRESHOLD,
    DplpmtudProber,
    DplpmtudState,
)
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicTransportParameters
from aioquic.quic.recovery import QuicPacketPacer

from .test_connection import encode_transport_parameters
from .utils import SERVER_CACERTFILE, SERVER_CERTFILE, SERVER_KEYFILE

CLIENT_ADDR = ("1.2.3.4", 1234)
CLIENT_ADDR_2 = ("1.2.3.4", 9999)

SERVER_ADDR = ("2.3.4.5", 4433)

# the link capacity used by most tests, and the configured ceiling
PATH_CAPACITY = 1400
MAX_DATAGRAM_SIZE = 1500


def disable_packet_pacing(connection):
    class DummyPacketPacer(QuicPacketPacer):
        def __init__(self):
            super().__init__(max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE)

        def next_send_time(self, now):
            return None

    connection._loss._pacer = DummyPacketPacer()


def run_prober(prober, capacity, now=0.0):
    """
    Drive a DplpmtudProber against a link which drops probes larger
    than `capacity` until no more probes are emitted.
    """
    while True:
        probe = prober.next_probe(now=now)
        if probe is None:
            break
        probe_id, size = probe
        if size <= capacity:
            prober.on_probe_acked(probe_id)
        else:
            prober.on_probe_lost(probe_id)
        now += 1.0


class Link:
    """
    An in-memory link which drops datagrams larger than a given size.
    """

    def __init__(self, max_datagram_size):
        self.max_datagram_size = max_datagram_size
        self.dropped = []
        self.delivered = []


class ConnectionTestBed:
    """
    A client and a server connected by an in-memory link which drops
    datagrams by size, driven by a virtual clock.
    """

    def __init__(self, capacity, max_datagram_size=MAX_DATAGRAM_SIZE):
        self.now = 0.0
        self.link = Link(capacity)

        self.client_configuration = QuicConfiguration(
            is_client=True,
            idle_timeout=300.0,
            max_datagram_size=max_datagram_size,
            quic_logger=QuicLogger(),
        )
        self.client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
        self.client = QuicConnection(configuration=self.client_configuration)

        self.server_configuration = QuicConfiguration(
            is_client=False,
            idle_timeout=300.0,
            max_datagram_size=max_datagram_size,
            quic_logger=QuicLogger(),
        )
        self.server_configuration.load_cert_chain(SERVER_CERTFILE, SERVER_KEYFILE)
        self.server = QuicConnection(
            configuration=self.server_configuration,
            original_destination_connection_id=self.client.original_destination_connection_id,
        )

        self.sent_packets = {}
        for connection in (self.client, self.server):
            connection._ack_delay = 0
            disable_packet_pacing(connection)
            self.sent_packets[connection] = self._spy_sent_packets(connection)

    def _spy_sent_packets(self, connection):
        packets = []
        on_packet_sent = connection._loss.on_packet_sent

        def wrapper(packet, space):
            packets.append(packet)
            on_packet_sent(packet=packet, space=space)

        connection._loss.on_packet_sent = wrapper
        return packets

    def handshake(self):
        self.client.connect(SERVER_ADDR, now=self.now)
        for _ in range(3):
            self.roundtrip()

    def transfer(self, sender, receiver, from_addr):
        count = 0
        for data, addr in sender.datagrams_to_send(now=self.now):
            count += 1
            if len(data) <= self.link.max_datagram_size:
                self.link.delivered.append(len(data))
                receiver.receive_datagram(data, from_addr, now=self.now)
            else:
                self.link.dropped.append(len(data))
        return count

    def roundtrip(self, client_addr=CLIENT_ADDR):
        self.transfer(self.client, self.server, client_addr)
        self.transfer(self.server, self.client, SERVER_ADDR)

    def next_timer(self):
        timers = []
        for connection in (self.client, self.server):
            if connection._state not in END_STATES:
                timer = connection.get_timer()
                if timer is not None:
                    timers.append(timer)
        return min(timers) if timers else None

    def run_until(self, condition, max_steps=2000):
        """
        Exchange datagrams and fire timers until `condition` is met.
        """
        for _ in range(max_steps):
            self.roundtrip()
            if condition():
                return
            timer = self.next_timer()
            if timer is None:
                break
            self.now = max(self.now, timer)
            for connection in (self.client, self.server):
                if connection._state not in END_STATES:
                    connection.handle_timer(self.now)
        self.roundtrip()
        if not condition():
            raise AssertionError("condition was not met")

    def search_complete(self):
        return (
            self.client._mtu.state == DplpmtudState.SEARCH_COMPLETE
            and self.server._mtu.state == DplpmtudState.SEARCH_COMPLETE
        )


class DplpmtudProberTest(TestCase):
    def test_base_size_only(self):
        # nothing to discover when the ceiling is the base size
        prober = DplpmtudProber(max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertIsNone(prober.next_probe(now=0.0))
        self.assertEqual(prober.state, DplpmtudState.SEARCH_COMPLETE)
        self.assertEqual(prober.plpmtu, SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertIsNone(prober.get_timeout())

    def test_search_converges(self):
        prober = DplpmtudProber(max_datagram_size=MAX_DATAGRAM_SIZE)
        self.assertEqual(prober.state, DplpmtudState.SEARCH)
        self.assertEqual(prober.plpmtu, SMALLEST_MAX_DATAGRAM_SIZE)

        # first probe at the midpoint, a single probe at a time
        probe = prober.next_probe(now=0.0)
        self.assertEqual(probe, (1, 1350))
        self.assertIsNone(prober.next_probe(now=0.0))

        # probe acknowledged: the PLPMTU is raised
        prober.on_probe_acked(1)
        self.assertEqual(prober.plpmtu, 1350)

        # a stale acknowledgement is ignored
        prober.on_probe_acked(1)
        self.assertEqual(prober.plpmtu, 1350)

        # the next probe fails K_MAX_PROBES times: the ceiling is lowered
        for _ in range(K_MAX_PROBES):
            probe_id, size = prober.next_probe(now=1.0)
            self.assertEqual(size, 1425)
            prober.on_probe_lost(probe_id)
        probe_id, size = prober.next_probe(now=2.0)
        self.assertEqual(size, 1387)

        # let the search run to completion against a 1400 byte path
        prober.on_probe_acked(probe_id)
        run_prober(prober, capacity=PATH_CAPACITY, now=3.0)
        self.assertEqual(prober.state, DplpmtudState.SEARCH_COMPLETE)
        self.assertGreaterEqual(prober.plpmtu, PATH_CAPACITY - K_SEARCH_THRESHOLD)
        self.assertLessEqual(prober.plpmtu, PATH_CAPACITY)

        # a confirmation timer is armed
        self.assertIsNotNone(prober.get_timeout())

    def test_confirmation_probe_success(self):
        prober = DplpmtudProber(max_datagram_size=MAX_DATAGRAM_SIZE)
        run_prober(prober, capacity=PATH_CAPACITY)
        self.assertEqual(prober.state, DplpmtudState.SEARCH_COMPLETE)

        # the confirmation timer fires, a probe at the PLPMTU is sent
        prober.on_timeout(now=prober.get_timeout())
        probe_id, size = prober.next_probe(now=100.0)
        self.assertEqual(size, prober.plpmtu)

        # the path still has headroom: resume searching
        prober.on_probe_acked(probe_id)
        self.assertEqual(prober.state, DplpmtudState.SEARCH)
        probe_id, size = prober.next_probe(now=101.0)
        self.assertGreater(size, prober.plpmtu)

    def test_confirmation_probe_blackhole(self):
        prober = DplpmtudProber(max_datagram_size=MAX_DATAGRAM_SIZE)
        run_prober(prober, capacity=PATH_CAPACITY)
        plpmtu = prober.plpmtu
        self.assertGreater(plpmtu, SMALLEST_MAX_DATAGRAM_SIZE)

        # the path degrades: confirmation probes are lost
        prober.on_timeout(now=prober.get_timeout())
        for _ in range(K_MAX_PROBES):
            probe_id, size = prober.next_probe(now=100.0)
            self.assertEqual(size, plpmtu)
            prober.on_probe_lost(probe_id)

        # fall back to the validated base size and search again
        self.assertEqual(prober.plpmtu, SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertEqual(prober.state, DplpmtudState.SEARCH)

        # the search converges to the new capacity
        run_prober(prober, capacity=1300, now=101.0)
        self.assertEqual(prober.state, DplpmtudState.SEARCH_COMPLETE)
        self.assertGreaterEqual(prober.plpmtu, 1300 - K_SEARCH_THRESHOLD)
        self.assertLessEqual(prober.plpmtu, 1300)

    def test_reset(self):
        prober = DplpmtudProber(max_datagram_size=MAX_DATAGRAM_SIZE)
        run_prober(prober, capacity=PATH_CAPACITY)
        self.assertGreater(prober.plpmtu, SMALLEST_MAX_DATAGRAM_SIZE)

        # a migration re-establishes the probing state
        prober.reset()
        self.assertEqual(prober.plpmtu, SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertEqual(prober.state, DplpmtudState.SEARCH)
        self.assertIsNone(prober.get_timeout())

        # deliveries for probes sent before the reset are ignored
        prober.on_probe_acked(1)
        prober.on_probe_lost(1)
        self.assertEqual(prober.plpmtu, SMALLEST_MAX_DATAGRAM_SIZE)

    def test_set_ceiling(self):
        prober = DplpmtudProber(max_datagram_size=MAX_DATAGRAM_SIZE)
        prober.set_ceiling(1350)
        run_prober(prober, capacity=PATH_CAPACITY)
        self.assertLessEqual(prober.plpmtu, 1350)


class DplpmtudTest(TestCase):
    def test_discovery_converges(self):
        bed = ConnectionTestBed(capacity=PATH_CAPACITY)
        bed.handshake()

        # sending started at the base size
        self.assertEqual(bed.link.delivered[0], SMALLEST_MAX_DATAGRAM_SIZE)

        bed.run_until(bed.search_complete)

        # the limit converged to the link capacity
        self.assertGreaterEqual(
            bed.client._max_datagram_size, PATH_CAPACITY - K_SEARCH_THRESHOLD
        )
        self.assertLessEqual(bed.client._max_datagram_size, PATH_CAPACITY)
        self.assertGreaterEqual(
            bed.server._max_datagram_size, PATH_CAPACITY - K_SEARCH_THRESHOLD
        )
        self.assertLessEqual(bed.server._max_datagram_size, PATH_CAPACITY)

        # probes were sent, and are distinguishable from regular packets
        probes = [p for p in bed.sent_packets[bed.client] if p.is_mtu_probe]
        self.assertTrue(len(probes) > 0)
        for packet in probes:
            self.assertTrue(packet.is_ack_eliciting)
            self.assertFalse(packet.in_flight)

        # probe datagrams of exactly the probed sizes were emitted
        emitted = bed.link.delivered + bed.link.dropped
        for packet in probes:
            self.assertIn(packet.sent_bytes, emitted)

        # probe packets only contain PING and PADDING frames
        log = bed.client_configuration.quic_logger.to_dict()
        probe_events = [
            event["data"]
            for event in log["traces"][0]["events"]
            if event["name"] == "transport:packet_sent"
            and event["data"]["raw"]["length"] > SMALLEST_MAX_DATAGRAM_SIZE
        ]
        self.assertTrue(len(probe_events) > 0)
        for data in probe_events:
            frame_types = set(frame["frame_type"] for frame in data["frames"])
            self.assertEqual(frame_types, set(["ping", "padding"]))

    def test_probe_loss_does_not_penalize_congestion(self):
        bed = ConnectionTestBed(capacity=PATH_CAPACITY)
        bed.handshake()
        congestion_window = bed.client._loss.congestion_window

        bed.run_until(bed.search_complete)

        # probes larger than the link capacity were dropped
        self.assertTrue(any(size > PATH_CAPACITY for size in bed.link.dropped))

        # the congestion window was never reduced
        self.assertGreaterEqual(bed.client._loss.congestion_window, congestion_window)
        self.assertEqual(bed.client._loss.bytes_in_flight, 0)

    def test_single_large_packet_loss_keeps_mtu(self):
        bed = ConnectionTestBed(capacity=PATH_CAPACITY)
        bed.handshake()
        bed.run_until(bed.search_complete)
        mtu = bed.client._max_datagram_size

        # send stream data, drop exactly one full-sized datagram
        bed.client.send_stream_data(stream_id=0, data=b"x" * 5000)
        dropped = 0
        for data, addr in bed.client.datagrams_to_send(now=bed.now):
            if len(data) > SMALLEST_MAX_DATAGRAM_SIZE and dropped == 0:
                dropped += 1
                bed.link.dropped.append(len(data))
            else:
                bed.server.receive_datagram(data, CLIENT_ADDR, now=bed.now)
        self.assertEqual(dropped, 1)

        # the loss is detected and repaired, the MTU is unaffected
        bed.run_until(lambda: bed.client._loss.bytes_in_flight == 0)
        self.assertEqual(bed.client._max_datagram_size, mtu)

    def test_blackhole_falls_back_and_recovers(self):
        bed = ConnectionTestBed(capacity=PATH_CAPACITY)
        bed.handshake()
        bed.run_until(bed.search_complete)
        self.assertGreater(bed.client._max_datagram_size, SMALLEST_MAX_DATAGRAM_SIZE)

        # the link capacity drops below the discovered size
        bed.link.max_datagram_size = 1300

        # the persistent blackhole causes a fallback to the base size
        bed.run_until(
            lambda: bed.client._max_datagram_size == SMALLEST_MAX_DATAGRAM_SIZE
        )

        # the path is probed again and converges to the new capacity
        bed.run_until(bed.search_complete)
        self.assertGreaterEqual(
            bed.client._max_datagram_size, 1300 - K_SEARCH_THRESHOLD
        )
        self.assertLessEqual(bed.client._max_datagram_size, 1300)

    def test_migration_triggers_reprobe(self):
        bed = ConnectionTestBed(capacity=PATH_CAPACITY)
        bed.handshake()
        bed.run_until(bed.search_complete)
        self.assertGreater(bed.server._max_datagram_size, SMALLEST_MAX_DATAGRAM_SIZE)

        # the client migrates to a new address
        bed.client.send_ping(uid=1)
        bed.transfer(bed.client, bed.server, CLIENT_ADDR_2)
        bed.transfer(bed.server, bed.client, SERVER_ADDR)

        # the server re-established the probing state for the new path
        self.assertEqual(bed.server._max_datagram_size, SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertEqual(bed.server._mtu.state, DplpmtudState.SEARCH)

        # the new path is probed and converges to the link capacity
        def migrated_and_converged():
            bed.roundtrip(client_addr=CLIENT_ADDR_2)
            return bed.server._mtu.state == DplpmtudState.SEARCH_COMPLETE

        for _ in range(2000):
            if migrated_and_converged():
                break
            timer = bed.next_timer()
            self.assertIsNotNone(timer)
            bed.now = max(bed.now, timer)
            for connection in (bed.client, bed.server):
                if connection._state not in END_STATES:
                    connection.handle_timer(bed.now)
        else:
            self.fail("server did not converge after migration")
        self.assertGreaterEqual(
            bed.server._max_datagram_size, PATH_CAPACITY - K_SEARCH_THRESHOLD
        )
        self.assertLessEqual(bed.server._max_datagram_size, PATH_CAPACITY)

    def test_peer_max_udp_payload_size_limits_probes(self):
        bed = ConnectionTestBed(capacity=PATH_CAPACITY)

        # the peer advertises a limit lower than our configuration
        bed.client._parse_transport_parameters(
            encode_transport_parameters(
                QuicTransportParameters(
                    max_udp_payload_size=1350,
                    original_destination_connection_id=bed.client.original_destination_connection_id,
                )
            )
        )
        self.assertEqual(bed.client._remote_max_udp_payload_size, 1350)

        bed.handshake()
        bed.run_until(bed.search_complete)

        # probes never exceeded the peer's limit
        probes = [p for p in bed.sent_packets[bed.client] if p.is_mtu_probe]
        self.assertTrue(len(probes) > 0)
        self.assertLessEqual(max(p.sent_bytes for p in probes), 1350)
        self.assertLessEqual(bed.client._max_datagram_size, 1350)
