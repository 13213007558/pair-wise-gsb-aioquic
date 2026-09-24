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
INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
INITIAL_SALT_VERSION_2 = binascii.unhexlify("0dede3def700a6db819381be6e269dcbf9bd2ed9")
SAMPLE_SIZE = 16


Callback = Callable[[str], None]


def NoCallback(trigger: str) -> None:
    pass


class KeyUnavailableError(CryptoError):
    pass


class AeadLimitReachedError(CryptoError):
    """
    The number of received packets which failed authentication exceeded the
    integrity limit for the negotiated AEAD algorithm (RFC 9001 section 6.6).
    """

    pass


# AEAD usage limits from RFC 9001 section 6.6, expressed as a number of
# packets: (confidentiality limit, integrity limit).
AEAD_LIMITS = {
    CipherSuite.AES_128_GCM_SHA256: (2**23, 2**52),
    CipherSuite.AES_256_GCM_SHA384: (2**52, 2**52),
    CipherSuite.CHACHA20_POLY1305_SHA256: (2**62, 2**36),
}


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
    return crypto


class CryptoPair:
    def __init__(
        self,
        recv_setup_cb: Callback = NoCallback,
        recv_teardown_cb: Callback = NoCallback,
        send_setup_cb: Callback = NoCallback,
        send_teardown_cb: Callback = NoCallback,
        confidentiality_limit: Optional[int] = None,
        integrity_limit: Optional[int] = None,
    ) -> None:
        self.aead_tag_size = 16
        self.recv = CryptoContext(setup_cb=recv_setup_cb, teardown_cb=recv_teardown_cb)
        self.send = CryptoContext(setup_cb=send_setup_cb, teardown_cb=send_teardown_cb)
        self.key_update_allowed = False
        self._confidentiality_limit = confidentiality_limit
        self._integrity_limit = integrity_limit
        self._previous_recv: Optional[CryptoContext] = None
        self._sent_packet_count = 0
        self._auth_fail_count = 0
        self._key_update_unconfirmed = False
        self._key_update_first_packet_number: Optional[int] = None
        self._update_key_requested = False

    def decrypt_packet(
        self, packet: bytes, encrypted_offset: int, expected_packet_number: int
    ) -> tuple[bytes, bytes, int]:
        try:
            (
                plain_header,
                payload,
                packet_number,
                update_key,
            ) = self.recv.decrypt_packet(
                packet, encrypted_offset, expected_packet_number
            )
        except KeyUnavailableError:
            raise
        except CryptoError:
            # The packet might have been protected with the previous key phase
            # and reordered around a key update, try the retained old keys.
            if self._previous_recv is not None:
                try:
                    (
                        plain_header,
                        payload,
                        packet_number,
                        update_key,
                    ) = self._previous_recv.decrypt_packet(
                        packet, encrypted_offset, expected_packet_number
                    )
                    return plain_header, payload, packet_number
                except CryptoError:
                    pass

            # Count authentication failures, the connection must be closed if
            # the integrity limit for the AEAD algorithm is exceeded.
            self._auth_fail_count += 1
            if self._auth_fail_count > self.integrity_limit:
                raise AeadLimitReachedError(
                    "Number of authentication failures exceeds the AEAD integrity limit"
                )
            raise
        if update_key:
            self._update_key("remote_update")
        return plain_header, payload, packet_number

    def encrypt_packet(
        self, plain_header: bytes, plain_payload: bytes, packet_number: int
    ) -> bytes:
        if self._update_key_requested:
            self._update_key("local_update")
        if (
            self._key_update_unconfirmed
            and self._key_update_first_packet_number is None
        ):
            self._key_update_first_packet_number = packet_number
        packet = self.send.encrypt_packet(plain_header, plain_payload, packet_number)

        # Track the number of packets protected with the current send keys and
        # schedule a key update before the confidentiality limit is reached.
        self._sent_packet_count += 1
        if (
            self.key_update_allowed
            and not self._update_key_requested
            and not self._key_update_unconfirmed
            and self._sent_packet_count >= self.confidentiality_limit
        ):
            self._update_key_requested = True
        return packet

    @property
    def confidentiality_limit(self) -> int:
        if self._confidentiality_limit is not None:
            return self._confidentiality_limit
        return AEAD_LIMITS[self.send.cipher_suite][0]

    @property
    def integrity_limit(self) -> int:
        if self._integrity_limit is not None:
            return self._integrity_limit
        return AEAD_LIMITS[self.recv.cipher_suite][1]

    @property
    def key_update_unconfirmed(self) -> bool:
        """
        Whether a key update was performed for which no packet sent in the
        current key phase has been acknowledged by the peer yet.
        """
        return self._key_update_unconfirmed

    def confirm_key_update(self, packet_number: int) -> None:
        """
        Notify the crypto pair that the peer acknowledged a packet, which
        lifts the restriction on initiating a new key update if the
        acknowledged packet was sent in the current key phase.
        """
        if (
            self._key_update_unconfirmed
            and self._key_update_first_packet_number is not None
            and packet_number >= self._key_update_first_packet_number
        ):
            self._key_update_unconfirmed = False

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
        self._previous_recv = None

    def update_key(self) -> None:
        self._update_key_requested = True

    @property
    def key_phase(self) -> int:
        if self._update_key_requested:
            return int(not self.recv.key_phase)
        else:
            return self.recv.key_phase

    def _update_key(self, trigger: str) -> None:
        # Retain the current receive keys to be able to decrypt legitimate
        # packets sent with the previous key phase which arrive reordered.
        previous_recv = CryptoContext(key_phase=self.recv.key_phase)
        previous_recv.aead = self.recv.aead
        previous_recv.cipher_suite = self.recv.cipher_suite
        previous_recv.hp = self.recv.hp
        previous_recv.secret = self.recv.secret
        previous_recv.version = self.recv.version
        self._previous_recv = previous_recv

        apply_key_phase(self.recv, next_key_phase(self.recv), trigger=trigger)
        apply_key_phase(self.send, next_key_phase(self.send), trigger=trigger)
        self._sent_packet_count = 0
        self._key_update_unconfirmed = True
        self._key_update_first_packet_number = None
        self._update_key_requested = False
