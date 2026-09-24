from unittest import TestCase

from aioquic.buffer import UINT_VAR_MAX, encode_uint_var
from aioquic.h3.capsule import (
    CapsuleDecoder,
    CapsuleProtocolError,
    CapsuleType,
    encode_capsule,
)
from aioquic.h3.connection import H3_ALPN, ErrorCode, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    DatagramTransport,
    DataReceived,
    HeadersReceived,
)

from .test_h3 import h3_client_and_server, h3_fake_client_and_server, h3_transfer

QUIC_CONFIGURATION_OPTIONS = {
    "alpn_protocols": H3_ALPN,
    "max_datagram_frame_size": 65536,
}

REQUEST_HEADERS = [
    (b":method", b"GET"),
    (b":scheme", b"https"),
    (b":authority", b"localhost"),
    (b":path", b"/"),
    (b"capsule-protocol", b"?1"),
]


class CapsuleDecoderTest(TestCase):
    def test_roundtrip(self):
        decoder = CapsuleDecoder()
        self.assertEqual(
            decoder.feed(encode_capsule(CapsuleType.DATAGRAM, b"foo")),
            [(CapsuleType.DATAGRAM, b"foo")],
        )
        decoder.finalize()

    def test_zero_length_value(self):
        decoder = CapsuleDecoder()
        self.assertEqual(
            decoder.feed(encode_capsule(CapsuleType.DATAGRAM, b"")),
            [(CapsuleType.DATAGRAM, b"")],
        )
        decoder.finalize()

    def test_fragmented(self):
        # the capsule header and value can be split at any byte boundary
        data = encode_capsule(CapsuleType.DATAGRAM, b"hello world")
        for size in range(1, len(data)):
            decoder = CapsuleDecoder()
            self.assertEqual(decoder.feed(data[:size]), [])
            self.assertEqual(
                decoder.feed(data[size:]), [(CapsuleType.DATAGRAM, b"hello world")]
            )
            decoder.finalize()

    def test_byte_by_byte(self):
        data = (
            encode_capsule(CapsuleType.DATAGRAM, b"foo")
            + encode_capsule(0xFF, b"unknown")
            + encode_capsule(CapsuleType.DATAGRAM, b"bar")
        )
        decoder = CapsuleDecoder()
        capsules = []
        for i in range(len(data)):
            capsules.extend(decoder.feed(data[i : i + 1]))
        self.assertEqual(
            capsules,
            [(CapsuleType.DATAGRAM, b"foo"), (CapsuleType.DATAGRAM, b"bar")],
        )
        decoder.finalize()

    def test_unknown_capsule_type_is_skipped(self):
        decoder = CapsuleDecoder()
        self.assertEqual(
            decoder.feed(
                encode_capsule(0x1234, b"unknown")
                + encode_capsule(CapsuleType.DATAGRAM, b"foo")
            ),
            [(CapsuleType.DATAGRAM, b"foo")],
        )
        decoder.finalize()

    def test_unknown_capsule_type_huge_length(self):
        # a huge declared length must not trigger a matching memory allocation
        decoder = CapsuleDecoder()
        self.assertEqual(
            decoder.feed(encode_uint_var(0xFF) + encode_uint_var(UINT_VAR_MAX)), []
        )
        self.assertEqual(decoder.feed(b"x" * 1024), [])
        self.assertEqual(decoder._header, b"")
        self.assertEqual(decoder._value, b"")
        self.assertEqual(decoder._remaining, UINT_VAR_MAX - 1024)
        with self.assertRaises(CapsuleProtocolError):
            decoder.finalize()

    def test_known_capsule_type_huge_length(self):
        # only data which was actually received is buffered
        decoder = CapsuleDecoder()
        self.assertEqual(
            decoder.feed(encode_uint_var(CapsuleType.DATAGRAM) + encode_uint_var(1024)),
            [],
        )
        self.assertEqual(decoder.feed(b"x" * 16), [])
        self.assertEqual(decoder._value, b"x" * 16)
        with self.assertRaises(CapsuleProtocolError):
            decoder.finalize()

    def test_truncated_header(self):
        decoder = CapsuleDecoder()
        self.assertEqual(decoder.feed(b"\x3f"), [])
        with self.assertRaises(CapsuleProtocolError) as cm:
            decoder.finalize()
        self.assertEqual(str(cm.exception), "Truncated capsule")

    def test_truncated_value(self):
        decoder = CapsuleDecoder()
        self.assertEqual(
            decoder.feed(encode_capsule(CapsuleType.DATAGRAM, b"foo")[:-1]), []
        )
        with self.assertRaises(CapsuleProtocolError) as cm:
            decoder.finalize()
        self.assertEqual(str(cm.exception), "Truncated capsule")


class H3CapsuleTest(TestCase):
    def _make_capsule_request(self, h3_client, h3_server):
        quic_client = h3_client._quic

        # send request headers, opting into the capsule protocol
        stream_id = quic_client.get_next_available_stream_id()
        h3_client.send_headers(stream_id=stream_id, headers=REQUEST_HEADERS)

        # receive request headers
        events = h3_transfer(quic_client, h3_server)
        self.assertEqual(
            events,
            [
                HeadersReceived(
                    headers=REQUEST_HEADERS,
                    stream_id=stream_id,
                    stream_ended=False,
                ),
            ],
        )
        return stream_id

    def test_datagram_via_capsule(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_request(h3_client, h3_server)

            # client -> server, the payload is used as-is, no request ID
            # is parsed from it
            h3_client.send_datagram(
                stream_id=stream_id,
                data=b"\x01hello",
                transport=DatagramTransport.CAPSULE,
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"\x01hello",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    )
                ],
            )

            # server -> client
            h3_server.send_headers(stream_id=stream_id, headers=[(b":status", b"200")])
            h3_server.send_datagram(
                stream_id=stream_id,
                data=b"\x02world",
                transport=DatagramTransport.CAPSULE,
            )
            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[(b":status", b"200")],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    DatagramReceived(
                        data=b"\x02world",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    ),
                ],
            )

    def test_datagram_transports_payload_consistency(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_request(h3_client, h3_server)

            # unreliable transport: QUIC DATAGRAM frame
            h3_client.send_datagram(
                stream_id=stream_id,
                data=b"same-payload",
                transport=DatagramTransport.QUIC_DATAGRAM,
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"same-payload",
                        stream_id=stream_id,
                        transport=DatagramTransport.QUIC_DATAGRAM,
                    )
                ],
            )

            # reliable transport: DATAGRAM capsule, the datagram is not
            # sent a second time
            h3_client.send_datagram(
                stream_id=stream_id,
                data=b"same-payload",
                transport=DatagramTransport.CAPSULE,
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"same-payload",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    )
                ],
            )

    def test_datagram_via_capsule_fragmented(self):
        # the fake QUIC connection delivers stream data one byte at a time
        with h3_fake_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_request(h3_client, h3_server)

            h3_client.send_datagram(
                stream_id=stream_id,
                data=b"fragmented",
                transport=DatagramTransport.CAPSULE,
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"fragmented",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    )
                ],
            )

    def test_datagram_via_capsule_truncated(self):
        with h3_fake_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_request(h3_client, h3_server)

            # send a capsule declaring 5 bytes of payload but only 2 bytes,
            # then close the stream
            h3_client.send_data(
                stream_id=stream_id, data=b"\x00\x05ab", end_stream=True
            )
            h3_transfer(quic_client, h3_server)
            self.assertEqual(
                quic_server.closed,
                (ErrorCode.H3_MESSAGE_ERROR, "Truncated capsule"),
            )

    def test_http_body_not_misinterpreted(self):
        # without the Capsule-Protocol header field, request bodies are
        # delivered as-is even if they look like capsules
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            body = encode_capsule(CapsuleType.DATAGRAM, b"foo")

            # send a plain request whose body looks like a capsule
            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(
                stream_id=stream_id,
                headers=[
                    (b":method", b"POST"),
                    (b":scheme", b"https"),
                    (b":authority", b"localhost"),
                    (b":path", b"/"),
                ],
            )
            h3_client.send_data(stream_id=stream_id, data=body, end_stream=True)

            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=[
                            (b":method", b"POST"),
                            (b":scheme", b"https"),
                            (b":authority", b"localhost"),
                            (b":path", b"/"),
                        ],
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    DataReceived(data=body, stream_id=stream_id, stream_ended=True),
                ],
            )

    def test_capsule_protocol_requires_h3_datagram_setting(self):
        # without the H3_DATAGRAM setting, the capsule protocol is not in
        # use even if the request contains a Capsule-Protocol header field
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            body = encode_capsule(CapsuleType.DATAGRAM, b"foo")

            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(stream_id=stream_id, headers=REQUEST_HEADERS)
            h3_client.send_data(stream_id=stream_id, data=body, end_stream=True)

            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=REQUEST_HEADERS,
                        stream_id=stream_id,
                        stream_ended=False,
                    ),
                    DataReceived(data=body, stream_id=stream_id, stream_ended=True),
                ],
            )
