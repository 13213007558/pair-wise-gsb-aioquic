import binascii
from typing import Callable, Optional

from .._crypto import AEAD, CryptoError, HeaderProtection
from ..tls import CipherSuite, cipher_suite_hash, hkdf_expand_label, hkdf_extract
from .packet import (
    QuicProtocolVersion,
    decode_packet_number,
    is_long_header,
)

CIPHER_SUITES = {
    CipherSuite.AES_128_GCM_SHA256: (b"aes-128-ecb", b"aes-128-gcm"),
    CipherSuite.AES_256_GCM_SHA384: (b"aes-256-ecb", b"aes-256-gcm"),
    CipherSuite.CHACHA20_POLY1305_SHA256: (b"chacha20", b"chacha20-poly1305"),
}
# Confidentiality and integrity limits for the AEAD algorithms, expressed as
# a number of packets, see RFC 9001 section 6.6.
AEAD_LIMITS = {
    CipherSuite.AES_128_GCM_SHA256: (1 << 23, 1 << 52),
    CipherSuite.AES_256_GCM_SHA384: (1 << 23, 1 << 52),
    CipherSuite.CHACHA20_POLY1305_SHA256: (1 << 62, 1 << 36),
}
INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_VERSION_2 = binascii.unhexlify("0dede3def700a6db819381be6e269dcbf9bd2ed9")
SAMPLE_SIZE = 16


Callback = Callable[[str], None]


def NoCallback(trigger: str) -> None:
    pass


class KeyUnavailableError(CryptoError):
    pass


def derive_key_iv_hp(
    *, cipher_suite: CipherSuite, secret: bytes, version: int
) -> tuple[bytes, bytes, bytes]:
    algorithm = cipher_suite_hash(cipher_suite)
    if cipher_suite in [
        CipherSuite.AES_256_GCM_SHA384,
        CipherSuite.CHACHA20_POLY1305_SHA256,
    ]:
        key_size = 32
    else:
        key_size = 16
    if version == QuicProtocolVersion.VERSION_2:
        return (
            hkdf_expand_label(algorithm, secret, b"quicv2 key", b"", key_size),
            hkdf_expand_label(algorithm, secret, b"quicv2 iv", b"", 12),
            hkdf_expand_label(algorithm, secret, b"quicv2 hp", b"", key_size),
        )
    else:
        return (
            hkdf_expand_label(algorithm, secret, b"quic key", b"", key_size),
            hkdf_expand_label(algorithm, secret, b"quic iv", b"", 12),
            hkdf_expand_label(algorithm, secret, b"quic hp", b"", key_size),
        )


class CryptoContext:
    def __init__(
        self,
        key_phase: int = 0,
        setup_cb: Callback = NoCallback,
        teardown_cb: Callback = NoCallback,
    ) -> None:
        self.aead: Optional[AEAD] = None
        self.cipher_suite: Optional[CipherSuite] = None
        self.hp: Optional[HeaderProtection] = None
        self.key_phase = key_phase
        self.secret: Optional[bytes] = None
        self.version: Optional[int] = None
        self._setup_cb = setup_cb
        self._teardown_cb = teardown_cb

        # AEAD usage tracking, see RFC 9001 section 6.6
        self.aead_count = 0
        self.aead_fail = 0
        self.aead_limit = 0
        self.aead_fail_limit = 0

    def decrypt_packet(
        self, packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int, bool]:
        if self.aead is None:
            raise KeyUnavailableError("Decryption key is not available")

        # header protection
        plain_header, packet_number = self.hp.remove(packet, encrypted_offset)
        first_byte = plain_header[0]

        # packet number
        pn_length = (first_byte & 0x03) + 1
        packet_number = decode_packet_number(
            packet_number, pn_length * 8, expected_packet_number
        )

        # detect key phase change
        crypto = self
        if not is_long_header(first_byte):
            key_phase = (first_byte & 4) >> 2
            if key_phase != self.key_phase:
                crypto = next_key_phase(self)

        # payload protection
        payload = crypto.aead.decrypt(
            packet[len(plain_header) :], plain_header, packet_number
        )

        return plain_header, payload, packet_number, crypto != self

    def encrypt_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        assert self.is_valid(), "Encryption key is not available"

        # payload protection
        protected_payload = self.aead.encrypt(
            plain_payload, plain_header, packet_number
        )
        self.aead_count += 1

        # header protection
        return self.hp.apply(plain_header, protected_payload)

    def is_valid(self) -> bool:
        return self.aead is not None

    def setup(self, *, cipher_suite: CipherSuite, secret: bytes, version: int) -> None:
        hp_cipher_name, aead_cipher_name = CIPHER_SUITES[cipher_suite]

        key, iv, hp = derive_key_iv_hp(
            cipher_suite=cipher_suite,
            secret=secret,
            version=version,
        )
        self.aead = AEAD(aead_cipher_name, key, iv)
        self.cipher_suite = cipher_suite
        self.hp = HeaderProtection(hp_cipher_name, hp)
        self.secret = secret
        self.version = version
        self.aead_limit, self.aead_fail_limit = AEAD_LIMITS[cipher_suite]

        # trigger callback
        self._setup_cb("tls")

    def teardown(self) -> None:
        self.aead = None
        self.cipher_suite = None
        self.hp = None
        self.secret = None

        # trigger callback
        self._teardown_cb("tls")


def apply_key_phase(self: CryptoContext, crypto: CryptoContext, trigger: str) -> None:
    self.aead = crypto.aead
    self.key_phase = crypto.key_phase
    self.secret = crypto.secret
    self.aead_limit = crypto.aead_limit
    self.aead_fail_limit = crypto.aead_fail_limit

    # reset the AEAD usage counters, the limits apply per key phase
    self.aead_count = 0
    self.aead_fail = 0

    # trigger callback
    self._setup_cb(trigger)


def next_key_phase(self: CryptoContext) -> CryptoContext:
    algorithm = cipher_suite_hash(self.cipher_suite)

    crypto = CryptoContext(key_phase=int(not self.key_phase))
    crypto.setup(
        cipher_suite=self.cipher_suite,
        secret=hkdf_expand_label(
            algorithm, self.secret, b"quic ku", b"", algorithm.digest_size
        ),
        version=self.version,
    )
    # preserve the configured limits, which may have been overridden
    crypto.aead_limit = self.aead_limit
    crypto.aead_fail_limit = self.aead_fail_limit
    return crypto


class CryptoPair:
    def __init__(
        self,
        recv_setup_cb: Callback = NoCallback,
        recv_teardown_cb: Callback = NoCallback,
        send_setup_cb: Callback = NoCallback,
        send_teardown_cb: Callback = NoCallback,
    ) -> None:
        self.aead_tag_size = 16
        self.recv = CryptoContext(setup_cb=recv_setup_cb, teardown_cb=recv_teardown_cb)
        self.send = CryptoContext(setup_cb=send_setup_cb, teardown_cb=send_teardown_cb)
        self._update_key_requested = False

        # receive keys from the previous key phase, retained for a limited
        # time to handle packets reordered across a key update
        self.recv_prev: Optional[CryptoContext] = None

        # a key update is only confirmed once a packet sent with the
        # current keys has been acknowledged, see RFC 9001 section 6
        self._update_key_unconfirmed = False
        self._update_key_first_sent: Optional[int] = None

    def decrypt_packet(
        self, packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int]:
        try:
            plain_header, payload, packet_number, update_key = self.recv.decrypt_packet(
                packet, encrypted_offset, expected_packet_number
            )
        except KeyUnavailableError:
            raise
        except CryptoError:
            # the packet may have been protected with the previous keys
            if self.recv_prev is None:
                self.recv.aead_fail += 1
                raise
            try:
                plain_header, payload, packet_number, update_key = (
                    self.recv_prev.decrypt_packet(
                        packet, encrypted_offset, expected_packet_number
                    )
                )
            except CryptoError:
                self.recv.aead_fail += 1
                raise
            # never trigger a key update based on the previous keys
            update_key = False
        if update_key:
            self._update_key("remote_update")
        return plain_header, payload, packet_number

    def encrypt_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        if self._update_key_requested:
            self._update_key("local_update")
        if self._update_key_unconfirmed and self._update_key_first_sent is None:
            self._update_key_first_sent = packet_number
        return self.send.encrypt_packet(plain_header, plain_payload, packet_number)

    def setup_initial(self, cid: bytes, is_client: bool, version: int) -> None:
        if is_client:
            recv_label, send_label = b"server in", b"client in"
        else:
            recv_label, send_label = b"client in", b"server in"

        if version == QuicProtocolVersion.VERSION_2:
            initial_salt = INITIAL_SALT_VERSION_2
        else:
            initial_salt = INITIAL_SALT_VERSION_1

        algorithm = cipher_suite_hash(INITIAL_CIPHER_SUITE)
        initial_secret = hkdf_extract(algorithm, initial_salt, cid)
        self.recv.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=hkdf_expand_label(
                algorithm, initial_secret, recv_label, b"", algorithm.digest_size
            ),
            version=version,
        )
        self.send.setup(
            cipher_suite=INITIAL_CIPHER_SUITE,
            secret=hkdf_expand_label(
                algorithm, initial_secret, send_label, b"", algorithm.digest_size
            ),
            version=version,
        )

    def teardown(self) -> None:
        self.recv.teardown()
        self.send.teardown()

    def update_key(self) -> None:
        self._update_key_requested = True

    @property
    def update_key_allowed(self) -> bool:
        """
        Whether a local key update may be initiated. A new update cannot
        be started while one is already scheduled, or while the previous
        update has not been confirmed by the peer.
        """
        return not self._update_key_requested and not self._update_key_unconfirmed

    @property
    def update_key_pending(self) -> bool:
        """
        Whether a key update has been requested but not yet applied.
        """
        return self._update_key_requested

    def confirm_key_update(self, packet_number: int) -> None:
        """
        Note that the peer acknowledged a packet up to `packet_number`, which
        confirms the key update if it covered a packet sent with current keys.
        """
        if (
            self._update_key_unconfirmed
            and self._update_key_first_sent is not None
            and packet_number >= self._update_key_first_sent
        ):
            self._update_key_unconfirmed = False

    def discard_previous_keys(self) -> None:
        """
        Stop accepting packets protected with the previous keys.
        """
        self.recv_prev = None

    @property
    def key_phase(self) -> int:
        if self._update_key_requested:
            return int(not self.recv.key_phase)
        else:
            return self.recv.key_phase

    def _update_key(self, trigger: str) -> None:
        # retain the previous receive keys for a limited time, to handle
        # packets reordered across the key update
        recv_prev = CryptoContext(key_phase=self.recv.key_phase)
        recv_prev.aead = self.recv.aead
        recv_prev.cipher_suite = self.recv.cipher_suite
        recv_prev.hp = self.recv.hp
        recv_prev.secret = self.recv.secret
        recv_prev.version = self.recv.version
        recv_prev.aead_limit = self.recv.aead_limit
        recv_prev.aead_fail_limit = self.recv.aead_fail_limit
        self.recv_prev = recv_prev

        apply_key_phase(self.recv, next_key_phase(self.recv), trigger=trigger)
        apply_key_phase(self.send, next_key_phase(self.send), trigger=trigger)
        self._update_key_requested = False
        self._update_key_unconfirmed = True
        self._update_key_first_sent = None
