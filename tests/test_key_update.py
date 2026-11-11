"""
Tests for the rejection paths of QUIC key updates (RFC 9001 section 6).

A flipped Key Phase bit does not prove that the peer holds the next generation
of keys. An endpoint only commits to a new key phase once a packet has been
fully authenticated with it, so a packet whose payload cannot be decrypted
must be discarded and must leave every piece of receive state untouched:

* the receive key phase is not advanced,
* the packet number is neither acknowledged nor recorded as received,
* no application event is emitted,
* the connection stays open.

The tests use a different marker payload for each key phase, so that a
successful decryption is always backed by the expected plaintext: a test
which merely observed "no exception" could not tell an authenticated packet
apart from one that was silently ignored.
"""

import time

from aioquic import tls
from aioquic.buffer import Buffer
from aioquic.quic import events
from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE, QuicConfiguration
from aioquic.quic.connection import QuicConnection, QuicConnectionState
from aioquic.quic.crypto import (
    CryptoContext,
    CryptoError,
    CryptoPair,
    derive_key_iv_hp,
    next_key_phase,
)
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import (
    PACKET_FIXED_BIT,
    QuicFrameType,
    QuicPacketType,
    QuicProtocolVersion,
)
from aioquic.quic.packet_builder import QuicPacketBuilder
from aioquic.quic.recovery import QuicPacketSpace

from .utils import (
    SERVER_CACERTFILE,
    SERVER_CERTFILE,
    SERVER_KEYFILE,
    TestCase,
    load_cert_chain,
)

CLIENT_ADDR = ("1.2.3.4", 1234)
SERVER_ADDR = ("2.3.4.5", 4433)

# Marker payloads, one per key phase. A phase-N packet must only ever surface
# the PHASE_N marker, which makes a wrong-key "success" impossible to miss.
PHASE_0_MARKER = b"phase-0-marker"
PHASE_1_MARKER = b"phase-1-marker"
FORGED_MARKER = b"forged-phase-marker"


def build_short_header(key_phase: int, packet_number: int, dcid: bytes) -> bytes:
    buf = Buffer(capacity=64)
    buf.push_uint8(PACKET_FIXED_BIT | (key_phase << 2) | 1)
    buf.push_bytes(dcid)
    buf.push_uint16(packet_number)
    return buf.data


class CryptoKeyUpdateRejectionTest(TestCase):
    """
    Rejection paths at the CryptoPair boundary, where the Key Phase bit is
    inspected and keys are rolled.
    """

    VERSION = QuicProtocolVersion.VERSION_1

    def create_pairs(self) -> tuple[CryptoPair, CryptoPair]:
        sender = CryptoPair()
        sender.setup_initial(
            cid=bytes.fromhex("8394c8f03e515708"),
            is_client=True,
            version=self.VERSION,
        )
        receiver = CryptoPair()
        receiver.setup_initial(
            cid=bytes.fromhex("8394c8f03e515708"),
            is_client=False,
            version=self.VERSION,
        )
        return sender, receiver

    def encrypt(
        self, sender: CryptoPair, key_phase: int, packet_number: int, payload: bytes
    ) -> bytes:
        plain_header = build_short_header(
            key_phase=key_phase,
            packet_number=packet_number,
            dcid=bytes.fromhex("8394c8f03e515708"),
        )
        return sender.encrypt_packet(plain_header, payload, packet_number)

    def test_forged_key_phase_bit_does_not_advance_receive_key(self) -> None:
        """
        RFC 9001 section 6.2: a packet whose Key Phase bit announces a new
        phase, but whose payload is not protected by the corresponding keys,
        fails authentication. The provisional next-phase context is thrown
        away and the receive key phase stays on its current value.
        """
        sender, receiver = self.create_pairs()
        self.assertEqual(receiver.recv.key_phase, 0)

        # Flip the Key Phase bit while keeping the phase-0 payload keys: the
        # receiver derives phase-1 keys to try the payload, and the AEAD tag
        # cannot validate.
        forged = self.encrypt(
            sender,
            key_phase=1,
            packet_number=0,
            payload=FORGED_MARKER,
        )
        with self.assertRaises(CryptoError):
            receiver.decrypt_packet(
                forged, encrypted_offset=9, expected_packet_number=0
            )

        # No key material was committed: phase, secret and key are unchanged.
        self.assertEqual(receiver.recv.key_phase, 0)
        self.assertEqual(receiver.key_phase, 0)

        # A genuine phase-0 packet is still accepted, proving the receiver
        # kept using the old keys and the old marker.
        packet = self.encrypt(sender, 0, 1, PHASE_0_MARKER)
        _, payload, packet_number = receiver.decrypt_packet(
            packet, encrypted_offset=9, expected_packet_number=0
        )
        self.assertEqual(payload, PHASE_0_MARKER)
        self.assertEqual(packet_number, 1)
        self.assertEqual(receiver.recv.key_phase, 0)

    def test_genuine_key_update_authenticates_and_advances_phase(self) -> None:
        """
        Positive control: a packet genuinely protected with the next key
        generation authenticates, surfaces the phase-1 marker and commits the
        receiver to phase 1 (RFC 9001 section 6.3).
        """
        sender, receiver = self.create_pairs()

        # Phase 0 baseline.
        packet = self.encrypt(sender, 0, 0, PHASE_0_MARKER)
        _, payload, _ = receiver.decrypt_packet(
            packet, encrypted_offset=9, expected_packet_number=0
        )
        self.assertEqual(payload, PHASE_0_MARKER)
        self.assertEqual(receiver.recv.key_phase, 0)

        # The sender rolls its keys, then sends a phase-1 packet.
        sender.update_key()
        packet = self.encrypt(sender, 1, 1, PHASE_1_MARKER)
        _, payload, packet_number = receiver.decrypt_packet(
            packet, encrypted_offset=9, expected_packet_number=1
        )
        self.assertEqual(payload, PHASE_1_MARKER)
        self.assertEqual(packet_number, 1)
        self.assertEqual(receiver.recv.key_phase, 1)
        self.assertEqual(receiver.key_phase, 1)

    def test_old_phase_packet_after_update_is_rejected(self) -> None:
        """
        RFC 9001 section 6.2: once the receiver has committed to phase 1, a
        delayed packet still protected with the discarded phase-0 keys cannot
        be authenticated and must not roll the receiver back.
        """
        sender, receiver = self.create_pairs()

        # A phase-0 packet is delayed in the network.
        delayed = self.encrypt(sender, 0, 1, PHASE_0_MARKER)

        # The receiver genuinely moves to phase 1.
        sender.update_key()
        packet = self.encrypt(sender, 1, 2, PHASE_1_MARKER)
        _, payload, _ = receiver.decrypt_packet(
            packet, encrypted_offset=9, expected_packet_number=0
        )
        self.assertEqual(payload, PHASE_1_MARKER)
        self.assertEqual(receiver.recv.key_phase, 1)

        # The delayed phase-0 packet arrives: the receiver tentatively derives
        # a phase-0 context, the tag fails and the phase-1 keys stay in place.
        with self.assertRaises(CryptoError):
            receiver.decrypt_packet(
                delayed, encrypted_offset=9, expected_packet_number=2
            )
        self.assertEqual(receiver.recv.key_phase, 1)

        # Phase-1 traffic continues to authenticate with the phase-1 marker.
        packet = self.encrypt(sender, 1, 3, PHASE_1_MARKER)
        _, payload, _ = receiver.decrypt_packet(
            packet, encrypted_offset=9, expected_packet_number=2
        )
        self.assertEqual(payload, PHASE_1_MARKER)
        self.assertEqual(receiver.recv.key_phase, 1)

    def test_repeated_update_request_before_send_is_a_single_pending_update(
        self,
    ) -> None:
        """
        RFC 9001 section 6.3: an endpoint must not initiate more than one key
        update at a time. Requesting an update again while one is already
        pending must not queue a second key derivation; the first packet sent
        performs exactly one roll.
        """
        sender, receiver = self.create_pairs()

        sender.update_key()
        first_request = sender._update_key_requested
        sender.update_key()
        second_request = sender._update_key_requested
        self.assertTrue(first_request)
        self.assertTrue(second_request)

        # The advertised phase flips exactly once.
        self.assertEqual(sender.key_phase, 1)

        # Sending performs the single pending roll, then clears the flag.
        packet = self.encrypt(sender, 1, 0, PHASE_1_MARKER)
        self.assertFalse(sender._update_key_requested)
        self.assertEqual(sender.send.key_phase, 1)

        # The peer follows with one roll and reads the phase-1 marker.
        _, payload, _ = receiver.decrypt_packet(
            packet, encrypted_offset=9, expected_packet_number=0
        )
        self.assertEqual(payload, PHASE_1_MARKER)
        self.assertEqual(receiver.recv.key_phase, 1)

    def test_next_key_phase_contexts_are_distinct_generations(self) -> None:
        """
        The keys derived for the next phase differ from the current ones, so a
        packet protected by the old generation cannot pass under the new
        Key Phase bit (the foundation of the rejection guarantees above).
        """
        pair = CryptoPair()
        pair.setup_initial(
            cid=bytes.fromhex("8394c8f03e515708"),
            is_client=True,
            version=self.VERSION,
        )
        current = pair.recv
        updated = next_key_phase(current)
        self.assertEqual(updated.key_phase, 1)
        self.assertNotEqual(updated.secret, current.secret)

        # The payload and header-protection keys are derived from the secret,
        # so distinct generations produce distinct keys.
        current_keys = derive_key_iv_hp(
            cipher_suite=current.cipher_suite,
            secret=current.secret,
            version=self.VERSION,
        )
        updated_keys = derive_key_iv_hp(
            cipher_suite=updated.cipher_suite,
            secret=updated.secret,
            version=self.VERSION,
        )
        self.assertNotEqual(updated_keys, current_keys)
        self.assertEqual(current.key_phase, 0)


class ConnectionKeyUpdateRejectionTest(TestCase):
    """
    End-to-end rejection paths driven through QuicConnection, checking the
    application events, the acknowledged packet numbers and the final state
    of the connection.
    """

    def setUp(self) -> None:
        client_configuration = QuicConfiguration(
            is_client=True, quic_logger=QuicLogger()
        )
        client_configuration.load_verify_locations(cafile=SERVER_CACERTFILE)
        self.client = QuicConnection(configuration=client_configuration)
        self.client._ack_delay = 0

        server_configuration = QuicConfiguration(
            is_client=False, quic_logger=QuicLogger()
        )
        load_cert_chain(server_configuration, SERVER_CERTFILE, SERVER_KEYFILE)
        self.server = QuicConnection(
            configuration=server_configuration,
            original_destination_connection_id=self.client.original_destination_connection_id,
        )
        self.server._ack_delay = 0

        self.client.connect(SERVER_ADDR, now=time.time())
        for _ in range(3):
            self.transfer(self.client, self.server)
            self.transfer(self.server, self.client)
        self.drain_events(self.client)
        self.drain_events(self.server)

    def tearDown(self) -> None:
        self.client.close()
        self.server.close()

    def drain_events(self, connection: QuicConnection) -> list[events.QuicEvent]:
        received: list[events.QuicEvent] = []
        while True:
            event = connection.next_event()
            if event is None:
                return received
            received.append(event)

    def transfer(self, sender: QuicConnection, receiver: QuicConnection) -> int:
        datagrams = 0
        from_addr = CLIENT_ADDR if sender._is_client else SERVER_ADDR
        for data, addr in sender.datagrams_to_send(now=time.time()):
            receiver.receive_datagram(data, from_addr, now=time.time())
            datagrams += 1
        return datagrams

    def dropped(self, connection: QuicConnection) -> list[str]:
        log = connection.configuration.quic_logger.to_dict()
        return [
            event["data"]["trigger"]
            for event in log["traces"][0]["events"]
            if event["name"] == "transport:packet_dropped"
        ]

    @property
    def one_rtt_space(self) -> QuicPacketSpace:
        return self.server._spaces[tls.Epoch.ONE_RTT]

    @property
    def one_rtt_crypto(self) -> CryptoPair:
        return self.client._cryptos[tls.Epoch.ONE_RTT]

    def snapshot_send_context(self) -> CryptoContext:
        """
        Return an independent copy of the client's current 1-RTT send context,
        so a packet can later be built with keys the connection has discarded.
        """
        send = self.one_rtt_crypto.send
        snapshot = CryptoContext(key_phase=send.key_phase)
        snapshot.setup(
            cipher_suite=send.cipher_suite,
            secret=send.secret,
            version=send.version,
        )
        return snapshot

    def build_one_rtt_datagram(
        self,
        *,
        packet_number: int,
        stream_id: int,
        marker: bytes,
        force_key_phase: int | None = None,
        send_context: CryptoContext | None = None,
    ) -> bytes:
        """
        Build a 1-RTT datagram carrying a STREAM frame with `marker`, using the
        client's current keys. `force_key_phase` overrides the Key Phase bit in
        the protected header, which lets a packet advertise a phase its payload
        keys do not match. `send_context` builds the payload with captured keys
        instead, modelling a delayed packet from an earlier key generation.
        """
        pair = self.one_rtt_crypto
        real_encrypt = pair.encrypt_packet

        def encrypt(plain_header: bytes, plain_payload: bytes, pn: int) -> bytes:
            if force_key_phase is not None:
                plain_header = (
                    bytes([(plain_header[0] & ~0x04) | (force_key_phase << 2)])
                    + plain_header[1:]
                )
            if send_context is not None:
                return send_context.encrypt_packet(plain_header, plain_payload, pn)
            return real_encrypt(plain_header, plain_payload, pn)

        pair.encrypt_packet = encrypt  # type: ignore[assignment,method-assign]
        try:
            builder = QuicPacketBuilder(
                host_cid=self.client.host_cid,
                is_client=True,
                max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE,
                packet_number=packet_number,
                peer_cid=self.server.host_cid,
                version=self.client._version,
            )
            builder.start_packet(QuicPacketType.ONE_RTT, pair)
            buf = builder.start_frame(QuicFrameType.STREAM_BASE | 2, capacity=16)
            buf.push_uint_var(stream_id)
            buf.push_uint16(len(marker) | 0x4000)
            buf.push_bytes(marker)
            return builder.flush()[0][0]
        finally:
            pair.encrypt_packet = real_encrypt  # type: ignore[method-assign]

    def assertConnected(self, connection: QuicConnection) -> None:
        self.assertEqual(connection._state, QuicConnectionState.CONNECTED)
        self.assertFalse(connection._close_pending)

    def test_forged_new_phase_packet_is_discarded_without_state_change(self) -> None:
        """
        An attacker flips the Key Phase bit without possessing the new keys.
        The server discards the packet with a payload decryption error and keeps
        phase 0: the packet number is not acknowledged, no stream data reaches
        the application and the connection does not close.
        """
        stream_id = self.client.get_next_available_stream_id()
        forged_pn = self.one_rtt_space.expected_packet_number
        ack_queue_before = list(self.one_rtt_space.ack_queue)

        forged = self.build_one_rtt_datagram(
            packet_number=forged_pn,
            stream_id=stream_id,
            marker=FORGED_MARKER,
            force_key_phase=1,
        )
        # Reserve the forged packet number on the client so the genuine packets
        # which follow use distinct numbers and cannot be mistaken for replays.
        self.client._packet_number = forged_pn + 1
        dropped_before = len(self.dropped(self.server))
        self.server.receive_datagram(forged, CLIENT_ADDR, now=time.time())

        # RFC 9001 section 6.2: the unauthenticatable packet is dropped, not
        # treated as a key update.
        self.assertEqual(
            self.dropped(self.server)[dropped_before:], ["payload_decrypt_error"]
        )
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 0)

        # Receive state did not advance: no ACK range, no expected PN change.
        largest_before = self.one_rtt_space.largest_received_packet
        self.assertEqual(list(self.one_rtt_space.ack_queue), ack_queue_before)
        self.assertEqual(self.one_rtt_space.expected_packet_number, forged_pn)
        self.assertEqual(self.one_rtt_space.largest_received_packet, largest_before)

        # No application event, no termination, and nothing is sent in reply.
        self.assertIsNone(self.server.next_event())
        self.assertEqual(self.server.datagrams_to_send(now=time.time()), [])
        self.assertConnected(self.server)

        # A genuine update still works and surfaces only the phase-1 marker.
        self.client.request_key_update()
        self.client.send_stream_data(stream_id, PHASE_1_MARKER)
        self.assertEqual(self.transfer(self.client, self.server), 1)
        event = self.server.next_event()
        self.assertIsInstance(event, events.StreamDataReceived)
        assert isinstance(event, events.StreamDataReceived)
        self.assertEqual(event.data, PHASE_1_MARKER)
        self.assertIsNone(self.server.next_event())
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 1)

        # Replaying the forged packet after the real phase-1 roll still fails,
        # because its payload was never protected with phase-1 keys.
        dropped_before = len(self.dropped(self.server))
        self.server.receive_datagram(forged, CLIENT_ADDR, now=time.time())
        self.assertEqual(
            self.dropped(self.server)[dropped_before:], ["payload_decrypt_error"]
        )
        self.assertIsNone(self.server.next_event())
        self.assertConnected(self.server)

    def test_delayed_old_phase_packet_is_discarded_after_update(self) -> None:
        """
        After a genuine update commits the server to phase 1, a delayed packet
        still protected by the phase-0 keys is rejected. It cannot roll the
        server back, cannot be acknowledged and delivers no stale marker.
        """
        stream_id = self.client.get_next_available_stream_id()
        delayed_pn = self.one_rtt_space.expected_packet_number

        # Build and hold back a genuine phase-0 packet.
        delayed = self.build_one_rtt_datagram(
            packet_number=delayed_pn,
            stream_id=stream_id,
            marker=PHASE_0_MARKER,
        )

        # Perform the real key update, which consumes the next packet number.
        self.client.request_key_update()
        self.client.send_stream_data(stream_id, PHASE_1_MARKER)
        self.assertEqual(self.transfer(self.client, self.server), 1)
        event = self.server.next_event()
        self.assertIsInstance(event, events.StreamDataReceived)
        assert isinstance(event, events.StreamDataReceived)
        self.assertEqual(event.data, PHASE_1_MARKER)
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 1)
        self.transfer(self.server, self.client)

        # The delayed phase-0 packet now arrives.
        dropped_before = len(self.dropped(self.server))
        ack_queue_before = list(self.one_rtt_space.ack_queue)
        self.server.receive_datagram(delayed, CLIENT_ADDR, now=time.time())
        self.assertEqual(
            self.dropped(self.server)[dropped_before:], ["payload_decrypt_error"]
        )

        # The server stays on phase 1 and the old packet number is not ACKed.
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 1)
        self.assertEqual(list(self.one_rtt_space.ack_queue), ack_queue_before)
        self.assertIsNone(self.server.next_event())
        self.assertConnected(self.server)

        # Further phase-1 traffic is unaffected and carries the phase-1 marker.
        self.client.send_stream_data(stream_id, PHASE_1_MARKER)
        self.assertEqual(self.transfer(self.client, self.server), 1)
        event = self.server.next_event()
        self.assertIsInstance(event, events.StreamDataReceived)
        assert isinstance(event, events.StreamDataReceived)
        self.assertEqual(event.data, PHASE_1_MARKER)
        self.assertConnected(self.server)

    def test_double_update_request_converges_on_a_single_roll(self) -> None:
        """
        Requesting two updates before any packet is sent must not skip a key
        generation: the connection rolls exactly once, the peer follows once,
        and traffic remains authenticated end to end.
        """
        pair = self.client._cryptos[tls.Epoch.ONE_RTT]

        self.client.request_key_update()
        self.assertTrue(pair._update_key_requested)
        self.client.request_key_update()
        self.assertTrue(pair._update_key_requested)
        self.assertEqual(pair.key_phase, 1)

        # The first 1-RTT packet sent performs exactly one roll.
        self.client.send_stream_data(0, PHASE_1_MARKER)
        self.assertEqual(self.transfer(self.client, self.server), 1)
        self.assertFalse(pair._update_key_requested)
        self.assertEqual(pair.send.key_phase, 1)
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 1)

        event = self.server.next_event()
        self.assertIsInstance(event, events.StreamDataReceived)
        assert isinstance(event, events.StreamDataReceived)
        self.assertEqual(event.data, PHASE_1_MARKER)
        self.assertIsNone(self.server.next_event())
        self.assertConnected(self.client)
        self.assertConnected(self.server)

        # The ACK round trip works with the single new generation.
        self.assertEqual(self.transfer(self.server, self.client), 1)
        self.assertConnected(self.client)

    def test_rejection_sequence_leaves_connection_connected_and_syncable(self) -> None:
        """
        Combined adversarial sequence: a forged phase-1 packet, a genuine
        update, a delayed phase-0 packet and a second genuine update. Every
        bad packet is dropped without advancing receive state, every good
        packet delivers its phase-specific marker, and the connection ends
        connected with both peers on the same key phase.
        """
        stream_id = self.client.get_next_available_stream_id()
        space = self.one_rtt_space

        # Reserve distinct packet numbers for every hand-built packet, so the
        # duplicate-packet check (which runs before decryption) never masks a
        # payload decryption error.
        forged_pn = space.expected_packet_number
        delayed_pn = forged_pn + 1
        self.client._packet_number = delayed_pn + 1

        # 1. Forged phase-1 packet while both peers are still on phase 0.
        forged = self.build_one_rtt_datagram(
            packet_number=forged_pn,
            stream_id=stream_id,
            marker=FORGED_MARKER,
            force_key_phase=1,
        )
        dropped_before = len(self.dropped(self.server))
        self.server.receive_datagram(forged, CLIENT_ADDR, now=time.time())
        self.assertEqual(
            self.dropped(self.server)[dropped_before:], ["payload_decrypt_error"]
        )
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 0)
        self.assertEqual(space.expected_packet_number, forged_pn)
        self.assertIsNone(self.server.next_event())

        # 2. Genuine update to phase 1.
        phase_zero_context = self.snapshot_send_context()
        self.client.request_key_update()
        self.client.send_stream_data(stream_id, PHASE_1_MARKER)
        self.assertEqual(self.transfer(self.client, self.server), 1)
        event = self.server.next_event()
        self.assertIsInstance(event, events.StreamDataReceived)
        assert isinstance(event, events.StreamDataReceived)
        self.assertEqual(event.data, PHASE_1_MARKER)
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 1)
        self.transfer(self.server, self.client)

        # 3. A delayed phase-0 packet, built with the pre-update keys, arrives
        # once phase 1 is committed.
        delayed = self.build_one_rtt_datagram(
            packet_number=delayed_pn,
            stream_id=stream_id,
            marker=PHASE_0_MARKER,
            send_context=phase_zero_context,
        )
        dropped_before = len(self.dropped(self.server))
        self.server.receive_datagram(delayed, CLIENT_ADDR, now=time.time())
        self.assertEqual(
            self.dropped(self.server)[dropped_before:], ["payload_decrypt_error"]
        )
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 1)
        self.assertNotIn(delayed_pn, space.ack_queue)
        self.assertIsNone(self.server.next_event())

        # 4. A second genuine update rolls back to phase 0 and still works.
        self.client.request_key_update()
        self.client.send_stream_data(stream_id, PHASE_0_MARKER)
        self.assertEqual(self.transfer(self.client, self.server), 1)
        event = self.server.next_event()
        self.assertIsInstance(event, events.StreamDataReceived)
        assert isinstance(event, events.StreamDataReceived)
        self.assertEqual(event.data, PHASE_0_MARKER)
        self.assertEqual(self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase, 0)
        self.transfer(self.server, self.client)

        # The forged marker never reached the application, no ConnectionTerminated
        # event was queued and both peers are connected on the same phase.
        self.assertIsNone(self.server.next_event())
        self.assertIsNone(self.client.next_event())
        self.assertConnected(self.client)
        self.assertConnected(self.server)
        self.assertEqual(
            self.client._cryptos[tls.Epoch.ONE_RTT].recv.key_phase,
            self.server._cryptos[tls.Epoch.ONE_RTT].recv.key_phase,
        )
