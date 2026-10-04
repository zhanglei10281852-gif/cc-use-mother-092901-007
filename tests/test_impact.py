"""影响引擎：直接命中、传递传播、依赖环、版本分叉、车辆去重、硬件门禁。"""

import unittest

from support import ServiceTestCase, build_standard_service

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact import SupplyChainService, ValidationError


class DirectAndTransitiveTests(ServiceTestCase):
    def test_direct_hits_follow_version_range(self):
        report = self.impact()
        direct = {f"{d['name']}@{d['version']}" for d in report["direct"]}
        self.assertEqual(direct, {"crypto-lib@1.3", "crypto-lib@1.6"})

    def test_transitive_dependents_are_included(self):
        statuses = self.component_status(self.impact())
        # 多跳传递：app-fw 经由 net-stack 间接受影响
        for expected in ["app-fw@9.1", "net-stack@4.2", "diag-core@5.0"]:
            self.assertEqual(statuses.get(expected), "residual", expected)
        # 版本分叉线不受影响
        self.assertNotIn("crypto-lib@2.1", statuses)
        self.assertNotIn("cluster-fw@3.0", statuses)

    def test_impact_maps_to_bundles_configs_batches(self):
        report = self.impact()
        self.assertEqual(report["bundles"], ["B-DIAG", "B-GW"])
        self.assertEqual(report["configs"], ["CFG-A", "CFG-B"])
        self.assertEqual(report["batches"], ["LOT-1", "LOT-2", "LOT-3"])

    def test_evidence_edges_form_affected_subgraph(self):
        report = self.impact()
        edges = {
            (e["dependent"]["name"], e["dependency"]["name"])
            for e in report["evidence_edges"]
        }
        self.assertIn(("app-fw", "net-stack"), edges)
        self.assertIn(("net-stack", "crypto-lib"), edges)
        self.assertNotIn(("cluster-fw", "crypto-lib"), edges)


class VehicleDeduplicationTests(ServiceTestCase):
    def test_vehicle_counted_once_across_batches_and_paths(self):
        report = self.impact()
        vins = [v["vin"] for v in report["vehicles"]]
        self.assertEqual(sorted(vins), ["V001", "V002", "V003", "V004"])
        self.assertEqual(len(vins), len(set(vins)), "同一车辆不得重复计入")
        self.assertEqual(report["counts"]["vehicles_total"], 4)
        # V002 出现在 LOT-1 与 LOT-3 两个批次，只计一次但保留全部来源
        v002 = next(v for v in report["vehicles"] if v["vin"] == "V002")
        self.assertEqual(v002["batches"], ["LOT-1", "LOT-3"])

    def test_vehicle_reachable_via_two_dependency_paths_counted_once(self):
        # 让 B-DIAG 再经一条新路径被命中，车辆仍只计一次
        self.service.register_component_version("voice-fw", "2.0")
        self.service.register_dependency(
            {"name": "voice-fw", "version": "2.0"},
            {"name": "crypto-lib", "version": "1.3"},
        )
        self.service.register_firmware_bundle("B-VOICE", "voice", [
            {"name": "voice-fw", "version": "2.0"},
        ], hw_min="H1", hw_max="H3")
        self.service.register_vehicle_config("CFG-C", "MPV-M", "H2", ["B-VOICE", "B-DIAG"])
        self.service.register_production_batch("LOT-9", "CFG-C", ["V001"])  # V001 复用
        report = self.impact()
        vins = [v["vin"] for v in report["vehicles"]]
        self.assertEqual(len(vins), len(set(vins)))
        self.assertEqual(report["counts"]["vehicles_total"], 4)


class DependencyCycleTests(unittest.TestCase):
    def test_cycle_terminates_and_marks_all_members(self):
        service = SupplyChainService()
        for name in ("a", "b", "c"):
            service.register_component_version(name, "1.0")
        # a -> b -> c -> a 依赖环
        service.register_dependency({"name": "a", "version": "1.0"}, {"name": "b", "version": "1.0"})
        service.register_dependency({"name": "b", "version": "1.0"}, {"name": "c", "version": "1.0"})
        service.register_dependency({"name": "c", "version": "1.0"}, {"name": "a", "version": "1.0"})
        service.register_firmware_bundle("B-CYC", "ecu", [{"name": "a", "version": "1.0"}],
                                         hw_min="H1", hw_max="H1")
        service.register_vehicle_config("CFG-CYC", "M", "H1", ["B-CYC"])
        service.register_production_batch("LOT-CYC", "CFG-CYC", ["V100"])
        service.publish_advisory("ADV-CYC", "b", "1.0")
        report = service.get_impact("ADV-CYC")
        affected = {f"{c['name']}@{c['version']}" for c in report["components"]}
        self.assertEqual(affected, {"a@1.0", "b@1.0", "c@1.0"})
        self.assertEqual(report["counts"]["vehicles_total"], 1)

    def test_self_loop_is_safe(self):
        service = SupplyChainService()
        service.register_component_version("solo", "1.0")
        service.register_dependency({"name": "solo", "version": "1.0"},
                                    {"name": "solo", "version": "1.0"})
        service.publish_advisory("ADV-SOLO", "solo", "*")
        report = service.get_impact("ADV-SOLO")
        self.assertEqual(report["counts"]["affected_components"], 1)


class HardwareGateTests(unittest.TestCase):
    def test_config_rejects_incompatible_hardware_revision(self):
        service = build_standard_service()
        with self.assertRaises(ValidationError):
            # B-DIAG 只兼容 H1..H2，H3 不在范围内
            service.register_vehicle_config("CFG-BAD", "Sedan-S", "H3", ["B-DIAG"])

    def test_bundle_rejects_inverted_hardware_range(self):
        service = SupplyChainService()
        with self.assertRaises(ValidationError):
            service.register_firmware_bundle("B-BAD", "ecu", [{"name": "x", "version": "1"}],
                                             hw_min="H3", hw_max="H1")


if __name__ == "__main__":
    unittest.main()
