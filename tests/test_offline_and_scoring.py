import unittest

from backend.main import _offline_chain_reply
from backend.reporting import readiness_label
from backend.scanner.pqc_engine import classify_key_exchange, label_for_score


CTX = """Source=backend
1. pnbindia.in score=71 assets=10
2. sbi.co.in score=59 assets=12
3. hdfcbank.com score=42 assets=11
4. axisbank.com score=75 assets=9
"""


class RiskModelTests(unittest.TestCase):
    def test_label_thresholds_align_to_srs(self) -> None:
        self.assertEqual(label_for_score(60), "Transitioning")
        self.assertEqual(label_for_score(60.01), "Quantum-Safe")
        self.assertEqual(label_for_score(80), "Quantum-Safe")
        self.assertEqual(label_for_score(80.01), "CRITICAL EXPOSURE")

    def test_reporting_label_matches_engine_label(self) -> None:
        for score in [0, 25, 60, 71, 80, 95]:
            self.assertEqual(readiness_label(score), label_for_score(score))

    def test_key_exchange_tls13_not_auto_critical(self) -> None:
        self.assertEqual(classify_key_exchange("TLS_AES_256_GCM_SHA384", "TLSv1.3"), "WARNING")
        self.assertEqual(classify_key_exchange("TLS_RSA_WITH_AES_128_GCM_SHA256", "TLSv1.2"), "CRITICAL")


class OfflineAssistantIntentTests(unittest.TestCase):
    def test_top3_risky_intent(self) -> None:
        reply, intent = _offline_chain_reply("top 3 risky banks", CTX)
        self.assertEqual(intent, "top_3_risky")
        self.assertIn("1. axisbank.com", reply)

    def test_top3_safest_intent(self) -> None:
        reply, intent = _offline_chain_reply("top 3 safest banks", CTX)
        self.assertEqual(intent, "top_3_safest")
        self.assertIn("1. hdfcbank.com", reply)

    def test_pqc_limits_intent(self) -> None:
        _, intent = _offline_chain_reply("pqc detection limits", CTX)
        self.assertEqual(intent, "pqc_limits")

    def test_chain_clarity_intent(self) -> None:
        reply, intent = _offline_chain_reply("explain chain block meaning", CTX)
        self.assertEqual(intent, "chain_clarity")
        self.assertIn("tamper-evident hash chain", reply)

    def test_certificate_criteria_intent(self) -> None:
        reply, intent = _offline_chain_reply("certificate criteria", CTX)
        self.assertEqual(intent, "certificate_criteria")
        self.assertIn("score <= 80", reply)

    def test_testing_intent(self) -> None:
        _, intent = _offline_chain_reply("testing coverage", CTX)
        self.assertEqual(intent, "testing")

    def test_limitations_intent(self) -> None:
        _, intent = _offline_chain_reply("known limitations", CTX)
        self.assertEqual(intent, "limitations")


if __name__ == "__main__":
    unittest.main()
