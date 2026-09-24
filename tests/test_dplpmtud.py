from unittest import TestCase

from aioquic.quic.configuration import SMALLEST_MAX_DATAGRAM_SIZE
from aioquic.quic.dplpmtud import MAX_PROBE_FAILURES, QuicMtuProber


class QuicMtuProberTest(TestCase):
    def test_no_probe_when_max_size_is_base_size(self):
        prober = QuicMtuProber(max_size=SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertIsNone(prober.get_probe())

    def test_probe_sequence(self):
        prober = QuicMtuProber(max_size=1452)

        # a single probe is outstanding at any time
        self.assertEqual(prober.get_probe(), 1326)
        self.assertIsNone(prober.get_probe())

        # a successful probe raises the validated size
        self.assertEqual(prober.on_probe_acked(1326), 1326)
        self.assertEqual(prober.validated_size, 1326)
        self.assertEqual(prober.get_probe(), 1389)

        # stale probe results are discarded
        self.assertIsNone(prober.on_probe_acked(1326))
        prober.on_probe_lost(1326)
        self.assertIsNone(prober.get_probe())

        # the outstanding probe is unaffected and completes
        self.assertEqual(prober.on_probe_acked(1389), 1389)
        self.assertEqual(prober.validated_size, 1389)

    def test_probe_failure_requires_repeated_losses(self):
        prober = QuicMtuProber(max_size=1452)

        for i in range(MAX_PROBE_FAILURES - 1):
            self.assertEqual(prober.get_probe(), 1326)
            prober.on_probe_lost(1326)

        # the search ceiling is only lowered after MAX_PROBE_FAILURES
        self.assertEqual(prober.get_probe(), 1326)
        prober.on_probe_lost(1326)
        self.assertEqual(prober.get_probe(), 1263)

        # the validated size is untouched by probe failures
        self.assertEqual(prober.validated_size, SMALLEST_MAX_DATAGRAM_SIZE)

    def test_probe_converges(self):
        prober = QuicMtuProber(max_size=1452)

        # a link which carries datagrams up to 1400 bytes
        while True:
            probe = prober.get_probe()
            if probe is None:
                break
            if probe <= 1400:
                prober.on_probe_acked(probe)
            else:
                for i in range(MAX_PROBE_FAILURES):
                    prober.on_probe_lost(probe)

        self.assertEqual(prober.validated_size, 1400)

    def test_reset(self):
        prober = QuicMtuProber(max_size=1452)
        prober.on_probe_acked(prober.get_probe())
        self.assertEqual(prober.validated_size, 1326)

        prober.reset()
        self.assertEqual(prober.validated_size, SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertEqual(prober.get_probe(), 1326)

    def test_set_max_size(self):
        prober = QuicMtuProber(max_size=1452)
        prober.set_max_size(1280)
        self.assertEqual(prober.max_size, 1280)
        self.assertEqual(prober.get_probe(), 1240)

        # the maximum size cannot go below the base size
        prober.set_max_size(1000)
        self.assertEqual(prober.max_size, SMALLEST_MAX_DATAGRAM_SIZE)
        self.assertIsNone(prober.get_probe())
