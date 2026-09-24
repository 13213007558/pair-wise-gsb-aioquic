import contextlib
import time
from unittest import TestCase

from aioquic import tls
from aioquic.quic.packet import QuicEcnMarking

from .test_connection import (
    CLIENT_ADDR,
    SERVER_ADDR,
    client_and_server,
    consume_events,
)


def ecn_transfer(sender, receiver, ecn_map=None):
    """
    Send datagrams from sender to receiver over an in-memory link
    which propagates ECN markings, optionally rewriting them.
    """
    datagrams = 0
    from_addr = CLIENT_ADDR if sender._is_client else SERVER_ADDR
    now = time.time()
    for data, addr, ecn in sender.datagrams_to_send(now=now):
        datagrams += 1
        if ecn_map is not None:
            ecn = ecn_map(ecn)
        receiver.receive_datagram(data, from_addr, now=now, ecn=ecn)
    return datagrams


def ecn_roundtrip(sender, receiver, ecn_map=None):
    return (
        ecn_transfer(sender, receiver, ecn_map),
        ecn_transfer(receiver, sender, ecn_map),
    )


def ecn_roundtrip_until_done(sender, receiver, ecn_map=None):
    rounds = 0
    while ecn_roundtrip(sender, receiver, ecn_map) != (0, 0):
        rounds += 1
        assert rounds < 10, "Too many roundtrips!"


def mark_ce(ecn):
    """
    Rewrite ECT(0) markings to CE, as a congested router would.
    """
    if ecn == QuicEcnMarking.ECT_0:
        return QuicEcnMarking.CE
    return ecn


def one_rtt_space(connection):
    return connection._spaces[tls.Epoch.ONE_RTT]


def ecn_counts_tuple(space):
    return (
        space.ecn_counts[QuicEcnMarking.ECT_0],
        space.ecn_counts[QuicEcnMarking.ECT_1],
        space.ecn_counts[QuicEcnMarking.CE],
    )


@contextlib.contextmanager
def ecn_client_and_server(**kwargs):
    with client_and_server(handshake=False, **kwargs) as (client, server):
        client.connect(SERVER_ADDR, now=time.time())
        for i in range(3):
            ecn_roundtrip(client, server)
        consume_events(client)
        consume_events(server)
        yield client, server


class CongestionEventCounter:
    def __init__(self, connection):
        self.count = 0
        cc = connection._loss._cc
        self._original = cc.on_congestion_event
        cc.on_congestion_event = self._on_congestion_event

    def _on_congestion_event(self, *, now, packet_sent_time):
        self.count += 1
        return self._original(now=now, packet_sent_time=packet_sent_time)


class EcnTest(TestCase):
    def test_ecn_marking_and_ack_ecn(self):
        """
        Datagrams are sent with an ECT(0) marking, received markings are
        counted per packet number space and reported back in ACK_ECN frames.
        """
        with ecn_client_and_server() as (client, server):
            # outgoing datagrams are marked ECT(0)
            client.send_ping(uid=1)
            for data, addr, ecn in client.datagrams_to_send(now=time.time()):
                self.assertEqual(ecn, QuicEcnMarking.ECT_0)
                server.receive_datagram(data, CLIENT_ADDR, now=time.time(), ecn=ecn)

            # the server counted the marked packet
            server_counts = ecn_counts_tuple(one_rtt_space(server))
            self.assertGreater(server_counts[0], 0)
            self.assertEqual(server_counts[1], 0)
            self.assertEqual(server_counts[2], 0)

            # the server reports the counts back in an ACK_ECN frame
            self.assertEqual(ecn_transfer(server, client), 1)
            client_space = one_rtt_space(client)
            self.assertEqual(client_space.ecn_acked_counts, server_counts)

            # feedback was valid, ECN remains enabled
            self.assertTrue(client._loss.ecn_enabled)

            # the client also reports counts to the server
            server.send_ping(uid=2)
            self.assertEqual(ecn_transfer(server, client), 1)
            client_counts = ecn_counts_tuple(client_space)
            self.assertEqual(ecn_transfer(client, server), 1)
            self.assertEqual(
                one_rtt_space(server).ecn_acked_counts,
                client_counts,
            )
            self.assertTrue(server._loss.ecn_enabled)

    def test_ecn_not_counted_when_not_ect(self):
        with ecn_client_and_server() as (client, server):
            counts_before = ecn_counts_tuple(one_rtt_space(server))

            # receive a datagram without ECN information
            client.send_ping(uid=1)
            for data, addr, ecn in client.datagrams_to_send(now=time.time()):
                server.receive_datagram(data, CLIENT_ADDR, now=time.time())

            self.assertEqual(ecn_counts_tuple(one_rtt_space(server)), counts_before)

    def test_ecn_ce_marking_triggers_congestion_once(self):
        """
        A link which rewrites ECT(0) to CE causes a congestion response,
        exactly once per reported CE mark.
        """
        with ecn_client_and_server() as (client, server):
            counter = CongestionEventCounter(client)
            cwnd_before = client._loss.congestion_window

            # send data over a link which marks CE
            client.send_stream_data(0, b"01234567")
            self.assertEqual(ecn_transfer(client, server, ecn_map=mark_ce), 1)
            self.assertEqual(one_rtt_space(server).ecn_counts[QuicEcnMarking.CE], 1)

            # the ACK_ECN reports the CE mark, triggering congestion response
            now = time.time()
            ack_datagrams = server.datagrams_to_send(now=now)
            self.assertEqual(len(ack_datagrams), 1)
            for data, addr, ecn in ack_datagrams:
                client.receive_datagram(data, SERVER_ADDR, now=now, ecn=ecn)
            self.assertEqual(counter.count, 1)
            self.assertLess(client._loss.congestion_window, cwnd_before)

            # a duplicate ACK does not trigger another congestion response
            for data, addr, ecn in ack_datagrams:
                client.receive_datagram(data, SERVER_ADDR, now=now, ecn=ecn)
            self.assertEqual(counter.count, 1)

            # ECN feedback was consistent, ECN remains enabled
            self.assertTrue(client._loss.ecn_enabled)

    def test_ecn_reordered_ack_does_not_retrigger(self):
        """
        A reordered ACK does not trigger another congestion response and
        does not disable ECN.
        """
        with ecn_client_and_server() as (client, server):
            counter = CongestionEventCounter(client)

            # send two batches of data, each marked CE by the link
            client.send_stream_data(0, b"01234567")
            self.assertEqual(ecn_transfer(client, server, ecn_map=mark_ce), 1)
            now = time.time()
            ack_datagrams_1 = server.datagrams_to_send(now=now)

            client.send_stream_data(0, b"89abcdef")
            self.assertEqual(ecn_transfer(client, server, ecn_map=mark_ce), 1)
            now = time.time()
            ack_datagrams_2 = server.datagrams_to_send(now=now)

            # deliver the newer ACK first, then the stale one
            for data, addr, ecn in ack_datagrams_2 + ack_datagrams_1:
                client.receive_datagram(data, SERVER_ADDR, now=now, ecn=ecn)

            # the congestion response only happened once
            self.assertEqual(counter.count, 1)
            self.assertTrue(client._loss.ecn_enabled)

    def test_ecn_counts_cleared_by_peer(self):
        """
        If the peer's ECN counts do not cover the newly acknowledged
        ECT-marked packets, ECN is disabled on the path.
        """
        with ecn_client_and_server() as (client, server):
            counter = CongestionEventCounter(client)

            # ensure the client has a valid ECN baseline
            client.send_ping(uid=1)
            ecn_roundtrip(client, server)
            client_space = one_rtt_space(client)
            self.assertIsNotNone(client_space.ecn_acked_counts)

            # client sends data, server clears its ECN counts
            client.send_stream_data(0, b"01234567")
            self.assertEqual(ecn_transfer(client, server), 1)
            server_space = one_rtt_space(server)
            previous = client_space.ecn_acked_counts
            server_space.ecn_counts = {
                QuicEcnMarking.ECT_0: previous[0],
                QuicEcnMarking.ECT_1: previous[1],
                QuicEcnMarking.CE: previous[2],
            }

            # the ACK_ECN does not account for the ECT-marked packet
            self.assertEqual(ecn_transfer(server, client), 1)

            # ECN is disabled, subsequent datagrams are sent Not-ECT
            self.assertFalse(client._loss.ecn_enabled)
            self.assertEqual(counter.count, 0)

            # ... but the ACK was processed normally
            self.assertEqual(client._loss.bytes_in_flight, 0)

            client.send_ping(uid=2)
            for data, addr, ecn in client.datagrams_to_send(now=time.time()):
                self.assertEqual(ecn, QuicEcnMarking.NOT_ECT)
                server.receive_datagram(data, CLIENT_ADDR, now=time.time(), ecn=ecn)

            # the connection otherwise continues to work
            ecn_roundtrip_until_done(client, server)
            self.assertEqual(client._loss.bytes_in_flight, 0)

    def test_ecn_counts_forged_by_peer(self):
        """
        If the peer reports more CE marks than newly acknowledged packets,
        ECN is disabled on the path and no congestion response occurs.
        """
        with ecn_client_and_server() as (client, server):
            counter = CongestionEventCounter(client)

            # ensure the client has a valid ECN baseline
            client.send_ping(uid=1)
            ecn_roundtrip(client, server)
            client_space = one_rtt_space(client)
            self.assertIsNotNone(client_space.ecn_acked_counts)

            # client sends data, server inflates its CE count
            client.send_stream_data(0, b"01234567")
            self.assertEqual(ecn_transfer(client, server), 1)
            server_space = one_rtt_space(server)
            previous = client_space.ecn_acked_counts
            server_space.ecn_counts = {
                QuicEcnMarking.ECT_0: previous[0],
                QuicEcnMarking.ECT_1: previous[1],
                QuicEcnMarking.CE: previous[2] + 100,
            }

            cwnd_before = client._loss.congestion_window
            self.assertEqual(ecn_transfer(server, client), 1)

            # ECN is disabled, no congestion response occurred
            self.assertFalse(client._loss.ecn_enabled)
            self.assertEqual(counter.count, 0)
            self.assertGreaterEqual(client._loss.congestion_window, cwnd_before)

    def test_ecn_counts_regression(self):
        """
        If the peer's ECN counts decrease, ECN is disabled on the path.
        """
        with ecn_client_and_server() as (client, server):
            # ensure the client has a valid ECN baseline
            client.send_ping(uid=1)
            ecn_roundtrip(client, server)
            client_space = one_rtt_space(client)
            previous = client_space.ecn_acked_counts
            self.assertGreater(previous[0], 0)

            # client sends data, server's ECT(0) count goes backwards
            client.send_stream_data(0, b"01234567")
            self.assertEqual(ecn_transfer(client, server), 1)
            server_space = one_rtt_space(server)
            server_space.ecn_counts = {
                QuicEcnMarking.ECT_0: previous[0] - 1,
                QuicEcnMarking.ECT_1: previous[1],
                QuicEcnMarking.CE: previous[2],
            }

            self.assertEqual(ecn_transfer(server, client), 1)

            # ECN is disabled, subsequent datagrams are sent Not-ECT
            self.assertFalse(client._loss.ecn_enabled)
            client.send_ping(uid=2)
            for data, addr, ecn in client.datagrams_to_send(now=time.time()):
                self.assertEqual(ecn, QuicEcnMarking.NOT_ECT)
