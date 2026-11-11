"""
Demonstration: what an HTTP/3 application actually sees with aioquic 0-RTT.

Three in-memory scenarios (no sockets, simulated time):

  A. Valid resumption     -> H3 request events arrive BEFORE HandshakeCompleted.
  B. Early data rejected  -> client learns early_data_accepted=False only at
                             HandshakeCompleted; QUIC retransmits the request
                             in 1-RTT; the server app sees it exactly once,
                             after the handshake.
  C. Ticket reuse/replay  -> a second connection with the same ticket (and a
                             verbatim replay of captured first-flight datagrams)
                             is accepted again: the application sees the
                             side-effecting request TWICE. QUIC packet-number
                             dedup only works within one connection.

Run with: .venv/bin/python zero_rtt_demo.py
"""

import sys

from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE
from aioquic.quic.recovery import QuicPacketPacer

sys.path.insert(0, "tests")
from utils import (  # noqa: E402
    SERVER_CACERTFILE,
    SERVER_CERTFILE,
    SERVER_KEYFILE,
    load_cert_chain,
)

CLIENT_ADDR = ("1.2.3.4", 1234)
SERVER_ADDR = ("2.3.4.5", 4433)


def disable_packet_pacing(connection: QuicConnection) -> None:
    class DummyPacketPacer(QuicPacketPacer):
        def __init__(self) -> None:
            super().__init__(max_datagram_size=SMALLEST_MAX_DATAGRAM_SIZE)

        def next_send_time(self, now: float) -> float | None:
            return None

    connection._loss._pacer = DummyPacketPacer()


class TicketStore:
    """Server-side ticket store. `single_use=True` mimics tests' pop() store."""

    def __init__(self, single_use: bool = False) -> None:
        self.tickets = {}
        self.single_use = single_use

    def add(self, ticket) -> None:
        self.tickets[ticket.ticket] = ticket

    def fetch(self, label: bytes):
        if self.single_use:
            return self.tickets.pop(label, None)
        return self.tickets.get(label)


class Endpoint:
    """A QuicConnection plus H3 layer, recording every event it emits."""

    def __init__(self, quic: QuicConnection, name: str, start: float) -> None:
        self.quic = quic
        self.name = name
        self.start = start
        self.h3 = H3Connection(quic)
        self.log: list[str] = []

    def record(self, now: float, message: str) -> None:
        self.log.append(f"t={now - self.start:5.2f}s  {message}")

    def poll(self, now: float) -> None:
        while True:
            event = self.quic.next_event()
            if event is None:
                return
            if isinstance(event, events.ProtocolNegotiated):
                self.record(now, f"QUIC ProtocolNegotiated(alpn={event.alpn_protocol})")
            elif isinstance(event, events.HandshakeCompleted):
                self.record(
                    now,
                    "QUIC HandshakeCompleted("
                    f"early_data_accepted={event.early_data_accepted}, "
                    f"session_resumed={event.session_resumed})",
                )
            elif isinstance(event, events.StreamDataReceived):
                self.record(
                    now,
                    f"QUIC StreamDataReceived(stream={event.stream_id}, "
                    f"len={len(event.data)}, end={event.end_stream})",
                )
            elif isinstance(event, events.ConnectionTerminated):
                self.record(now, "QUIC ConnectionTerminated")
            for h3_event in self.h3.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    headers = {
                        k.decode(): v.decode() for k, v in h3_event.headers
                    }
                    self.record(
                        now,
                        f"H3   HeadersReceived(stream={h3_event.stream_id}, "
                        f":method={headers.get(':method')}, "
                        f":path={headers.get(':path')}, "
                        f"idempotency-key={headers.get('idempotency-key')})",
                    )
                elif isinstance(h3_event, DataReceived):
                    self.record(
                        now,
                        f"H3   DataReceived(stream={h3_event.stream_id}, "
                        f"data={h3_event.data!r})",
                    )


def make_client(ticket=None, ticket_sink=None) -> QuicConnection:
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    config.load_verify_locations(cafile=SERVER_CACERTFILE)
    if ticket is not None:
        config.session_ticket = ticket
    client = QuicConnection(
        configuration=config, session_ticket_handler=ticket_sink
    )
    disable_packet_pacing(client)
    return client


def make_server(client: QuicConnection, store: TicketStore) -> QuicConnection:
    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    load_cert_chain(config, SERVER_CERTFILE, SERVER_KEYFILE)
    server = QuicConnection(
        configuration=config,
        original_destination_connection_id=client.original_destination_connection_id,
        session_ticket_fetcher=store.fetch,
        session_ticket_handler=store.add,
    )
    disable_packet_pacing(server)
    return server


def pump(client: Endpoint, server: Endpoint, now: float) -> float:
    """Exchange datagrams and run timers until both sides go quiet."""
    for _ in range(500):
        activity = False
        for src, dst, src_addr in (
            (client, server, CLIENT_ADDR),
            (server, client, SERVER_ADDR),
        ):
            timer = src.quic.get_timer()
            if timer is not None and timer <= now:
                src.quic.handle_timer(now=now)
                activity = True
            for data, _addr in src.quic.datagrams_to_send(now=now):
                dst.quic.receive_datagram(data, src_addr, now=now)
                activity = True
        client.poll(now)
        server.poll(now)
        if not activity:
            timers = [
                t
                for t in (client.quic.get_timer(), server.quic.get_timer())
                if t is not None and t > now
            ]
            # stop once only the idle timeout (60s) remains
            if not timers or min(timers) > now + 2.0:
                break
            now = min(timers)
    return now


def send_post(endpoint: Endpoint, now: float) -> int:
    """Send a side-effecting POST as early as possible (0-RTT if usable)."""
    stream_id = endpoint.quic.get_next_available_stream_id()
    endpoint.h3.send_headers(
        stream_id,
        [
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/charge"),
            (b"idempotency-key", b"charge-7f3a9c"),
        ],
    )
    endpoint.h3.send_data(stream_id, b"amount=100&currency=USD", end_stream=True)
    endpoint.record(now, f"app  submitted POST /charge on stream {stream_id}")
    return stream_id


def show(title: str, *endpoints: Endpoint) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")
    for endpoint in endpoints:
        print(f"--- {endpoint.name} sees: ---")
        for line in endpoint.log:
            print(f"  {line}")


def bootstrap_ticket(store: TicketStore):
    """Plain 1-RTT handshake so the client obtains a session ticket."""
    tickets = []
    client = make_client(ticket_sink=tickets.append)
    server = make_server(client, store)
    now = 0.0
    client.connect(SERVER_ADDR, now=now)
    pump(Endpoint(client, "c", 0.0), Endpoint(server, "s", 0.0), now)
    assert tickets, "client did not receive a session ticket"
    return tickets[0]


def scenario_a(ticket, store) -> None:
    start = 100.0
    client = Endpoint(make_client(ticket=ticket), "CLIENT", start)
    server = Endpoint(make_server(client.quic, store), "SERVER", start)
    client.quic.connect(SERVER_ADDR, now=start)
    send_post(client, start)  # goes out as 0-RTT in the first flight
    pump(client, server, start)
    show("SCENARIO A - valid resumption, server accepts early data", client, server)


def scenario_b(ticket) -> None:
    start = 200.0
    empty_store = TicketStore()  # server restarted / ticket unknown
    client = Endpoint(make_client(ticket=ticket), "CLIENT", start)
    server = Endpoint(make_server(client.quic, empty_store), "SERVER", start)
    client.quic.connect(SERVER_ADDR, now=start)
    send_post(client, start)  # offered as 0-RTT, will be rejected
    pump(client, server, start)
    show("SCENARIO B - server rejects early data (ticket unknown)", client, server)


def scenario_c(ticket, store) -> None:
    start = 300.0

    # C.1 - first connection: request processed once.
    client1 = Endpoint(make_client(ticket=ticket), "CLIENT#1", start)
    server1 = Endpoint(make_server(client1.quic, store), "SERVER conn#1", start)
    client1.quic.connect(SERVER_ADDR, now=start)
    send_post(client1, start)
    first_flight = [data for data, _ in client1.quic.datagrams_to_send(now=start)]
    for data in first_flight:
        server1.quic.receive_datagram(data, CLIENT_ADDR, now=start)
    server1.poll(start)

    # In-connection dedup: deliver the SAME datagrams again -> dropped.
    before = len(server1.log)
    for data in first_flight:
        server1.quic.receive_datagram(data, CLIENT_ADDR, now=start)
    server1.poll(start)
    dup = len(server1.log) - before
    server1.record(start, f"app  note: re-delivered first flight -> {dup} new events (packet-number dedup)")
    pump(client1, server1, start)

    # C.2 - legitimate ticket reuse: a brand-new connection, same ticket.
    start2 = start + 10.0
    client2 = Endpoint(make_client(ticket=ticket), "CLIENT#2 (same ticket)", start2)
    server2 = Endpoint(make_server(client2.quic, store), "SERVER conn#2", start2)
    client2.quic.connect(SERVER_ADDR, now=start2)
    send_post(client2, start2)
    pump(client2, server2, start2)

    # C.3 - attacker replays conn#1's captured first flight to a fresh
    # server connection (no client cooperation at all).
    start3 = start + 20.0
    server3 = Endpoint(make_server(client1.quic, store), "SERVER conn#3 (replay victim)", start3)
    for data in first_flight:
        server3.quic.receive_datagram(data, CLIENT_ADDR, now=start3)
    server3.poll(start3)

    show(
        "SCENARIO C.1 - first connection processes POST /charge once",
        client1,
        server1,
    )
    show(
        "SCENARIO C.2 - same ticket reused by a new connection: accepted again",
        client2,
        server2,
    )
    show(
        "SCENARIO C.3 - verbatim replay of conn#1 datagrams: accepted again",
        server3,
    )


def main() -> None:
    store = TicketStore(single_use=False)  # typical deployment: reusable tickets
    ticket = bootstrap_ticket(store)
    print(f"bootstrap: ticket issued, max_early_data_size="
          f"{ticket.max_early_data_size:#x}, valid={ticket.is_valid}")
    scenario_a(ticket, store)
    scenario_b(ticket)
    scenario_c(ticket, store)


if __name__ == "__main__":
    main()
