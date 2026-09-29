import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact.contracts import ComponentRef, DependencyEdge, SecurityAdvisory


class SupplyContractTests(unittest.TestCase):
    def test_dependency_direction_is_explicit(self):
        dependent = ComponentRef("firmware", "1.0")
        dependency = ComponentRef("library", "3.2")
        edge = DependencyEdge(dependent, dependency)
        self.assertEqual(edge.dependency.name, "library")

    def test_advisory_requires_range(self):
        with self.assertRaises(ValueError):
            SecurityAdvisory("A-2", "library", " ")


if __name__ == "__main__":
    unittest.main()
