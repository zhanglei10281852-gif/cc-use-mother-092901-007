"""供应商操作：声明作废、声明替代、替代版本（含部分替换）。"""

import unittest

from support import ServiceTestCase

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact import ConflictError, NotFoundError, SupplyChainService


class AttestationTests(ServiceTestCase):
    def test_unattested_component_is_unverified_in_impact(self):
        report = self.impact()
        entry = next(c for c in report["components"] if c["name"] == "crypto-lib" and c["version"] == "1.6")
        self.assertFalse(entry["verified"])

    def test_active_attestation_marks_component_verified(self):
        self.service.register_attestation("ATT-1", "chipco", "crypto-lib", "1.6", "sha256:aa")
        report = self.impact()
        entry = next(c for c in report["components"] if c["version"] == "1.6" and c["name"] == "crypto-lib")
        self.assertTrue(entry["verified"])

    def test_void_attestation_flips_verified_and_is_not_idempotent(self):
        self.service.register_attestation("ATT-1", "chipco", "crypto-lib", "1.6", "sha256:aa")
        voided = self.service.void_attestation("ATT-1", "供应商发现签名错误", actor="chipco")
        self.assertEqual(voided["status"], "voided")
        report = self.impact()
        entry = next(c for c in report["components"] if c["version"] == "1.6" and c["name"] == "crypto-lib")
        self.assertFalse(entry["verified"])
        with self.assertRaises(ConflictError):
            self.service.void_attestation("ATT-1", "重复作废")

    def test_supersede_links_old_and_new(self):
        self.service.register_attestation("ATT-1", "chipco", "crypto-lib", "1.6", "sha256:aa")
        created = self.service.supersede_attestation("ATT-1", {
            "attestation_id": "ATT-2",
            "artifact_hash": "sha256:bb",
            "statement": "重新签名",
        })
        self.assertEqual(created["status"], "active")
        old = self.service.store.attestations["ATT-1"]
        self.assertEqual(old.status.value, "superseded")
        self.assertEqual(old.replaced_by, "ATT-2")
        with self.assertRaises(ConflictError):
            self.service.supersede_attestation("ATT-1", {"attestation_id": "ATT-3", "artifact_hash": "x"})

    def test_same_supplier_reregister_auto_supersedes(self):
        self.service.register_attestation("ATT-1", "chipco", "crypto-lib", "1.6", "sha256:aa")
        self.service.register_attestation("ATT-2", "chipco", "crypto-lib", "1.6", "sha256:bb")
        self.assertEqual(self.service.store.attestations["ATT-1"].status.value, "superseded")
        self.assertEqual(self.service.store.attestations["ATT-2"].status.value, "active")

    def test_void_missing_attestation_is_not_found(self):
        with self.assertRaises(NotFoundError):
            self.service.void_attestation("ATT-404", "不存在")


def build_two_track_service() -> SupplyChainService:
    """两条独立装车轨道：V1 装 lib-x 1.3，V2 装 lib-x 1.6。"""
    service = SupplyChainService()
    for name, version in [("lib-x", "1.3"), ("lib-x", "1.6"), ("fw-a", "1.0"), ("fw-b", "1.0")]:
        service.register_component_version(name, version)
    service.register_dependency({"name": "fw-a", "version": "1.0"}, {"name": "lib-x", "version": "1.3"})
    service.register_dependency({"name": "fw-b", "version": "1.0"}, {"name": "lib-x", "version": "1.6"})
    service.register_firmware_bundle("BA", "ecu-a", [
        {"name": "fw-a", "version": "1.0"}, {"name": "lib-x", "version": "1.3"},
    ], hw_min="H1", hw_max="H3")
    service.register_firmware_bundle("BB", "ecu-b", [
        {"name": "fw-b", "version": "1.0"}, {"name": "lib-x", "version": "1.6"},
    ], hw_min="H1", hw_max="H3")
    service.register_vehicle_config("CA", "M1", "H2", ["BA"])
    service.register_vehicle_config("CB", "M2", "H2", ["BB"])
    service.register_production_batch("LA", "CA", ["V1"])
    service.register_production_batch("LB", "CB", ["V2"])
    service.publish_advisory("ADV-X", "lib-x", ">=1.0,<2.0")
    return service


class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.service = build_two_track_service()

    def vehicle_status(self):
        return {v["vin"]: v["status"] for v in self.service.get_impact("ADV-X")["vehicles"]}

    def test_without_replacement_all_vehicles_residual(self):
        self.assertEqual(self.vehicle_status(), {"V1": "residual", "V2": "residual"})

    def test_partial_replacement_splits_vehicle_tiers(self):
        # 供应商只对 >=1.0,<1.5 区间发布替代版本：1.3 可缓解，1.6 仍残留
        self.service.register_replacement("RPL-1", "chipco", "lib-x", ">=1.0,<1.5", "2.0.1")
        self.assertEqual(self.vehicle_status(), {"V1": "mitigated", "V2": "residual"})
        components = {f"{c['name']}@{c['version']}": c["status"]
                      for c in self.service.get_impact("ADV-X")["components"]}
        self.assertEqual(components["lib-x@1.3"], "mitigated")
        self.assertEqual(components["lib-x@1.6"], "residual")
        self.assertEqual(components["fw-a@1.0"], "mitigated")
        self.assertEqual(components["fw-b@1.0"], "residual")

    def test_full_replacement_clears_residual(self):
        self.service.register_replacement("RPL-1", "chipco", "lib-x", ">=1.0,<2.0", "2.0.1")
        self.assertEqual(self.vehicle_status(), {"V1": "mitigated", "V2": "mitigated"})

    def test_replacement_inside_advisory_range_does_not_mitigate(self):
        # 替代版本自身仍落在通告区间内，等于没有有效修复
        self.service.register_replacement("RPL-BAD", "chipco", "lib-x", ">=1.0,<1.5", "1.8.0")
        self.assertEqual(self.vehicle_status(), {"V1": "residual", "V2": "residual"})

    def test_withdraw_replacement_restores_residual(self):
        self.service.register_replacement("RPL-1", "chipco", "lib-x", ">=1.0,<1.5", "2.0.1")
        self.service.withdraw_replacement("RPL-1", "替代版本引入回归")
        self.assertEqual(self.vehicle_status(), {"V1": "residual", "V2": "residual"})
        with self.assertRaises(ConflictError):
            self.service.withdraw_replacement("RPL-1", "重复撤回")


if __name__ == "__main__":
    unittest.main()
