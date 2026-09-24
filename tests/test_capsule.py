from unittest import TestCase

from aioquic.buffer import encode_uint_var
from aioquic.h3.capsule import (
    CapsuleError,
    CapsuleParser,
    CapsuleType,
    encode_capsule,
)
from aioquic.h3.connection import H3_ALPN, ErrorCode, FrameUnexpected, H3Connection
from aioquic.h3.events import (
    DatagramReceived,
    DatagramTransport,
    DataReceived,
    HeadersReceived,
)

from .test_h3 import h3_client_and_server, h3_transfer

QUIC_CONFIGURATION_OPTIONS = {
    "alpn_protocols": H3_ALPN,
    "max_datagram_frame_size": 65536,
}


class CapsuleParserTest(TestCase):
    def test_encode_capsule(self):
        self.assertEqual(encode_capsule(CapsuleType.DATAGRAM, b"hi"), b"\x00\x02hi")
        self.assertEqual(encode_capsule(CapsuleType.DATAGRAM, b""), b"\x00\x00")

    def test_roundtrip(self):
        parser = CapsuleParser()
        self.assertEqual(
            parser.feed_data(encode_capsule(CapsuleType.DATAGRAM, b"hello")),
            [(CapsuleType.DATAGRAM, b"hello")],
        )
        parser.finalize()

    def test_empty_value(self):
        parser = CapsuleParser()
        self.assertEqual(
            parser.feed_data(encode_capsule(CapsuleType.DATAGRAM, b"")),
            [(CapsuleType.DATAGRAM, b"")],
        )
        parser.finalize()

    def test_split_at_every_byte(self):
        # the header and value can be split at any byte boundary
        data = encode_capsule(CapsuleType.DATAGRAM, bytes(range(200)))
        for i in range(len(data) + 1):
            parser = CapsuleParser()
            capsules = parser.feed_data(data[:i])
            capsules += parser.feed_data(data[i:])
            self.assertEqual(
                capsules,
                [(CapsuleType.DATAGRAM, bytes(range(200)))],
                "split at %d" % i,
            )
            parser.finalize()

    def test_feed_byte_by_byte(self):
        data = (
            encode_capsule(CapsuleType.DATAGRAM, b"first")
            + encode_capsule(0x21, b"skipped")
            + encode_capsule(CapsuleType.DATAGRAM, b"second")
        )
        parser = CapsuleParser()
        capsules = []
        for i in range(len(data)):
            capsules += parser.feed_data(data[i : i + 1])
        self.assertEqual(
            capsules,
            [
                (CapsuleType.DATAGRAM, b"first"),
                (CapsuleType.DATAGRAM, b"second"),
            ],
        )
        parser.finalize()

    def test_unknown_type_skipped(self):
        data = encode_capsule(0x1E, b"unknown payload") + encode_capsule(
            CapsuleType.DATAGRAM, b"hello"
        )
        parser = CapsuleParser()
        capsules = []
        for i in range(0, len(data), 3):
            capsules += parser.feed_data(data[i : i + 3])
        self.assertEqual(capsules, [(CapsuleType.DATAGRAM, b"hello")])
        parser.finalize()

    def test_huge_declared_length(self):
        # a capsule declaring a huge length must not trigger a
        # corresponding memory allocation
        parser = CapsuleParser()
        data = encode_uint_var(CapsuleType.DATAGRAM) + encode_uint_var(2**62 - 1)
        self.assertEqual(parser.feed_data(data), [])
        self.assertEqual(parser.feed_data(b"partial"), [])
        with self.assertRaises(CapsuleError):
            parser.finalize()

    def test_truncated_value(self):
        parser = CapsuleParser()
        data = encode_capsule(CapsuleType.DATAGRAM, b"hello")
        self.assertEqual(parser.feed_data(data[:-1]), [])
        with self.assertRaises(CapsuleError) as cm:
            parser.finalize()
        self.assertEqual(str(cm.exception), "Truncated capsule")

    def test_truncated_header(self):
        parser = CapsuleParser()
        self.assertEqual(parser.feed_data(b"\x40"), [])
        with self.assertRaises(CapsuleError):
            parser.finalize()


class H3CapsuleTest(TestCase):
    def _make_capsule_stream(self, h3_client, h3_server):
        """
        Perform a capsule protocol negotiation and return the stream ID.
        """
        quic_client = h3_client._quic
        quic_server = h3_server._quic

        request_headers = [
            (b":method", b"CONNECT"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", b"/"),
            (b":protocol", b"webtransport"),
            (b"capsule-protocol", b"?1"),
        ]
        response_headers = [
            (b":status", b"200"),
            (b"capsule-protocol", b"?1"),
        ]

        # send request
        stream_id = quic_client.get_next_available_stream_id()
        h3_client.send_headers(stream_id=stream_id, headers=request_headers)

        # receive request
        events = h3_transfer(quic_client, h3_server)
        self.assertEqual(
            events,
            [
                HeadersReceived(
                    headers=request_headers,
                    stream_id=stream_id,
                    stream_ended=False,
                    push_id=None,
                )
            ],
        )

        # send response
        h3_server.send_headers(stream_id=stream_id, headers=response_headers)

        # receive response
        events = h3_transfer(quic_server, h3_client)
        self.assertEqual(
            events,
            [
                HeadersReceived(
                    headers=response_headers,
                    stream_id=stream_id,
                    stream_ended=False,
                    push_id=None,
                )
            ],
        )

        return stream_id

    def test_datagram_reliable_and_unreliable(self):
        """
        The same payload is delivered whether it is carried reliably by a
        DATAGRAM capsule or unreliably by a QUIC DATAGRAM frame, and the
        event indicates the actual transport.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_stream(h3_client, h3_server)

            # send the datagram reliably, as a DATAGRAM capsule
            h3_client.send_datagram(
                stream_id=stream_id,
                data=b"foo",
                transport=DatagramTransport.CAPSULE,
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"foo",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    )
                ],
            )

            # send the same payload unreliably, as a QUIC DATAGRAM frame
            h3_client.send_datagram(stream_id=stream_id, data=b"foo")
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"foo",
                        stream_id=stream_id,
                        transport=DatagramTransport.QUIC_DATAGRAM,
                    )
                ],
            )

    def test_datagram_capsule_server_to_client(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_stream(h3_client, h3_server)

            # the server sends a datagram reliably, as a DATAGRAM capsule
            h3_server.send_datagram(
                stream_id=stream_id,
                data=b"bar",
                transport=DatagramTransport.CAPSULE,
            )
            events = h3_transfer(quic_server, h3_client)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"bar",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    )
                ],
            )

    def test_datagram_capsule_split_across_data_frames(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_stream(h3_client, h3_server)

            # a capsule split across several DATA frames is reassembled
            capsule = encode_capsule(CapsuleType.DATAGRAM, b"hello")
            h3_client.send_data(stream_id=stream_id, data=capsule[:3], end_stream=False)
            h3_client.send_data(stream_id=stream_id, data=capsule[3:], end_stream=False)
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"hello",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    )
                ],
            )

    def test_unknown_capsule_type_skipped(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_stream(h3_client, h3_server)

            # an unknown capsule is skipped, the DATAGRAM capsule is delivered
            h3_client.send_data(
                stream_id=stream_id,
                data=encode_capsule(0x1E, b"unknown")
                + encode_capsule(CapsuleType.DATAGRAM, b"foo"),
                end_stream=False,
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    DatagramReceived(
                        data=b"foo",
                        stream_id=stream_id,
                        transport=DatagramTransport.CAPSULE,
                    )
                ],
            )

    def test_truncated_capsule_on_stream_close(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client, enable_webtransport=True)
            h3_server = H3Connection(quic_server, enable_webtransport=True)

            stream_id = self._make_capsule_stream(h3_client, h3_server)

            # the capsule declares a 10 byte payload but only 3 bytes are
            # sent before the stream is closed
            h3_client.send_data(
                stream_id=stream_id, data=b"\x00\x0afoo", end_stream=True
            )
            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(events, [])
            self.assertIsNotNone(quic_server._close_event)
            self.assertEqual(
                quic_server._close_event.error_code, ErrorCode.H3_MESSAGE_ERROR
            )

    def test_http_body_not_mistaken_for_capsule(self):
        """
        Without capsule protocol negotiation, DATA frames are a plain HTTP
        body even if their content looks like a capsule.
        """
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client)
            h3_server = H3Connection(quic_server)

            body = encode_capsule(CapsuleType.DATAGRAM, b"foo")
            headers = [
                (b":method", b"POST"),
                (b":scheme", b"https"),
                (b":authority", b"localhost"),
                (b":path", b"/"),
            ]

            stream_id = quic_client.get_next_available_stream_id()
            h3_client.send_headers(stream_id=stream_id, headers=headers)
            h3_client.send_data(stream_id=stream_id, data=body, end_stream=True)

            events = h3_transfer(quic_client, h3_server)
            self.assertEqual(
                events,
                [
                    HeadersReceived(
                        headers=headers,
                        stream_id=stream_id,
                        stream_ended=False,
                        push_id=None,
                    ),
                    DataReceived(
                        data=body,
                        stream_id=stream_id,
                        stream_ended=True,
                        push_id=None,
                    ),
                ],
            )

    def test_send_datagram_capsule_requires_negotiation(self):
        with h3_client_and_server(QUIC_CONFIGURATION_OPTIONS) as (
            quic_client,
            quic_server,
        ):
            h3_client = H3Connection(quic_client)

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

            # the capsule protocol was not negotiated for this stream
            with self.assertRaises(FrameUnexpected):
                h3_client.send_datagram(
                    stream_id=stream_id,
                    data=b"foo",
                    transport=DatagramTransport.CAPSULE,
                )
