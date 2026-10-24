import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from amslab.cases import CASES
from amslab.models import Profile
from amslab.runner import run_all, run_case


class AttackDefenseRegressionTests(unittest.TestCase):
    def test_every_registered_case_has_a_runner(self):
        for case_id in CASES:
            for profile in Profile:
                self.assertEqual(run_case(case_id, profile).case_id, case_id)

    def test_vulnerable_profile_reproduces_each_attack(self):
        results = run_all(Profile.VULNERABLE)
        self.assertTrue(all(result.attack_succeeded for result in results))

    def test_hardened_profile_blocks_each_attack(self):
        results = run_all(Profile.HARDENED)
        self.assertTrue(all(not result.attack_succeeded for result in results))

    def test_no_sensitive_mock_tool_executes(self):
        for profile in Profile:
            for result in run_all(profile):
                self.assertFalse(result.metrics.get("forbidden_executed", False))

    def test_direct_poison_is_observable_but_contained_in_baseline(self):
        result = run_case("direct_override", Profile.VULNERABLE)
        self.assertTrue(result.metrics["tool_attempted"])
        self.assertFalse(result.metrics["forbidden_executed"])


if __name__ == "__main__":
    unittest.main()

