HTTP/3 critical stream checklist
================================

HTTP/3 requires each peer to maintain exactly one control stream, one QPACK
encoder stream and one QPACK decoder stream for the lifetime of the
connection. These are the *critical streams*: closing, resetting or
duplicating any of them is a connection error, not a stream error.

This page is the regression checklist for that behaviour. Every entry names
the test in ``tests/test_h3.py`` which proves it, so a failing test maps
directly back to a protocol constraint. The *Outcome* column tells the
maintainer whether the connection must be terminated or the stream is
handled locally.

When adding a constraint, add its test first; an entry without a passing
test does not belong in this list.

Closing a critical stream
-------------------------

Closure covers all three QUIC signals: a FIN (``StreamDataReceived`` with
``end_stream``), a ``RESET_STREAM`` and a ``STOP_SENDING`` on our own
critical stream. All of them are connection errors of type
``H3_CLOSED_CRITICAL_STREAM`` (0x104), see RFC 9114 section 6.2.1 and
RFC 9204 section 4.2.

.. list-table::
   :header-rows: 1

   * - Scenario
     - Outcome
     - Test
   * - Peer closes the control stream (FIN)
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_control_stream_close``
   * - Peer closes the control stream before SETTINGS
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_control_stream_close_before_settings``
   * - Peer resets the control stream
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_control_stream_reset``
   * - Peer sends STOP_SENDING for our control stream
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_control_stream_stop_sending``
   * - Peer closes the QPACK encoder stream (FIN)
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_qpack_encoder_stream_close``
   * - Peer resets the QPACK encoder stream
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_qpack_encoder_stream_reset``
   * - Peer sends STOP_SENDING for our QPACK encoder stream
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_qpack_encoder_stream_stop_sending``
   * - Peer closes the QPACK decoder stream (FIN)
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_qpack_decoder_stream_close``
   * - Peer resets the QPACK decoder stream
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_qpack_decoder_stream_reset``
   * - Peer sends STOP_SENDING for our QPACK decoder stream
     - Connection error ``H3_CLOSED_CRITICAL_STREAM``
     - ``test_handle_qpack_decoder_stream_stop_sending``

Duplicating a critical stream
-----------------------------

Each critical stream type may appear at most once per peer (RFC 9114
section 6.2.1, RFC 9204 section 4.2). A second stream of the same type is a
connection error of type ``H3_STREAM_CREATION_ERROR`` (0x103).

.. list-table::
   :header-rows: 1

   * - Scenario
     - Outcome
     - Test
   * - Peer opens a second control stream
     - Connection error ``H3_STREAM_CREATION_ERROR``
     - ``test_handle_control_stream_duplicate``
   * - Peer opens a second QPACK encoder stream
     - Connection error ``H3_STREAM_CREATION_ERROR``
     - ``test_handle_qpack_encoder_duplicate``
   * - Peer opens a second QPACK decoder stream
     - Connection error ``H3_STREAM_CREATION_ERROR``
     - ``test_handle_qpack_decoder_duplicate``

Push streams
------------

Only servers may open push streams (RFC 9114 section 6.2.2), and aioquic
never sends ``MAX_PUSH_ID``, so it never accepts a push (RFC 9114 section
4.6).

.. list-table::
   :header-rows: 1

   * - Scenario
     - Outcome
     - Test
   * - Client opens a push stream
     - Connection error ``H3_STREAM_CREATION_ERROR``
     - ``test_handle_push_stream_from_client``
   * - Server opens a push stream
     - Connection error ``H3_ID_ERROR``
     - ``test_handle_push_stream_from_server``

Garbage on a QPACK stream
-------------------------

Malformed encoder or decoder instructions are connection errors (RFC 9204
section 4.2).

.. list-table::
   :header-rows: 1

   * - Scenario
     - Outcome
     - Test
   * - Garbage on the QPACK encoder stream
     - Connection error ``QPACK_ENCODER_STREAM_ERROR`` (0x201)
     - ``test_handle_qpack_encoder_stream_error``
   * - Garbage on the QPACK decoder stream
     - Connection error ``QPACK_DECODER_STREAM_ERROR`` (0x202)
     - ``test_handle_qpack_decoder_stream_error``

Unknown stream types are not critical
-------------------------------------

Unknown and reserved (grease) unidirectional stream types MUST be ignored
(RFC 9114 sections 6.2 and 6.2.3): their data is discarded and they may be
closed or reset without any error. The stream type is a variable-length
integer, so it may arrive split across packets; the type must be buffered
until complete before any critical-stream rule is applied.

.. list-table::
   :header-rows: 1

   * - Scenario
     - Outcome
     - Test
   * - Reserved (grease) stream type, closed with FIN
     - Stream ignored, connection stays open
     - ``test_uni_stream_grease``
   * - Unknown stream type, reset by the peer
     - Stream ignored, connection stays open
     - ``test_uni_stream_reset``
   * - Stream type delivered one byte at a time
     - Type buffered until complete, then stream ignored
     - ``test_uni_stream_type``
