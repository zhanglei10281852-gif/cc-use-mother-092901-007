import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact.versioning import VersionRange, compare_versions


class CompareTests(unittest.TestCase):
    def test_numeric_segments_compare_by_value(self):
        self.assertLess(compare_versions("1.9.0", "1.10.0"), 0)
        self.assertGreater(compare_versions("2.0", "1.10.0"), 0)

    def test_missing_tail_segments_pad_with_zero(self):
        self.assertEqual(compare_versions("1.2", "1.2.0"), 0)

    def test_hardware_style_revisions(self):
        self.assertLess(compare_versions("H2", "H10"), 0)
        self.assertEqual(compare_versions("H3", "H3"), 0)


class RangeTests(unittest.TestCase):
    def test_interval_clauses(self):
        rng = VersionRange.parse(">=2.4,<2.5")
        self.assertTrue(rng.matches("2.4.1"))
        self.assertFalse(rng.matches("2.5.0"))
        self.assertFalse(rng.matches("2.3.9"))

    def test_fork_lines_are_distinguished(self):
        rng = VersionRange.parse(">=1.0,<2.0")
        self.assertTrue(rng.matches("1.6"))
        self.assertFalse(rng.matches("2.1"))

    def test_bare_version_means_exact(self):
        rng = VersionRange.parse("1.2.3")
        self.assertTrue(rng.matches("1.2.3"))
        self.assertFalse(rng.matches("1.2.4"))

    def test_not_equal_and_star(self):
        self.assertFalse(VersionRange.parse("!=1.0").matches("1.0"))
        self.assertTrue(VersionRange.parse("*").matches("9.9.9"))

    def test_empty_range_rejected(self):
        with self.assertRaises(ValueError):
            VersionRange.parse("  ")
        with self.assertRaises(ValueError):
            VersionRange.parse(">=1.0,")


if __name__ == "__main__":
    unittest.main()
