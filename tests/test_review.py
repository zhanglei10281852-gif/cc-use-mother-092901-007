"""经办人审核：缓解措施批准、无法核实链路标记、可追溯清单导出。"""

import unittest

from support import ServiceTestCase

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact import ConflictError, NotFoundError, ValidationError


class MitigationTests(ServiceTestCase):
    def test_propose_then_approve(self):
        self.service.propose_mitigation(
            "MIT-1", "ADV-CRYPTO", "OTA 升级 crypto-lib 至 2.0.1",
            target_component="crypto-lib", fixed_version="2.0.1", actor="operator-li")
        approved = self.service.approve_mitigation("MIT-1", actor="lead-wang")
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approved_by"], "lead-wang")
        with self.assertRaises(ConflictError):
            self.service.approve_mitigation("MIT-1", actor="lead-wang")

    def test_propose_for_missing_advisory_rejected(self):
        with self.assertRaises(NotFoundError):
            self.service.propose_mitigation("MIT-2", "ADV-404", "x")

    def test_approve_missing_mitigation_rejected(self):
        with self.assertRaises(NotFoundError):
            self.service.approve_mitigation("MIT-404")


class UnverifiableMarkTests(ServiceTestCase):
    def test_mark_dependency_edge_surfaces_in_impact(self):
        self.service.mark_unverifiable(
            "MRK-1", "dependency", "net-stack:4.2->crypto-lib:1.6",
            "供应商未提供该边对应的 SBOM 片段", actor="operator-li")
        report = self.impact()
        self.assertEqual([m["mark_id"] for m in report["unverifiable"]], ["MRK-1"])

    def test_mark_on_unrelated_edge_not_in_impact(self):
        self.service.register_dependency(
            {"name": "cluster-fw", "version": "3.0"},
            {"name": "crypto-lib", "version": "2.1"},
        )
        self.service.mark_unverifiable(
            "MRK-9", "dependency", "cluster-fw:3.0->crypto-lib:2.1", "分叉线待核实")
        report = self.impact()
        self.assertEqual(report["unverifiable"], [])

    def test_mark_attestation_and_validation(self):
        self.service.register_attestation("ATT-1", "chipco", "crypto-lib", "1.6", "sha256:aa")
        self.service.mark_unverifiable("MRK-2", "attestation", "ATT-1", "签名链断裂")
        report = self.impact()
        self.assertEqual([m["mark_id"] for m in report["unverifiable"]], ["MRK-2"])
        with self.assertRaises(NotFoundError):
            self.service.mark_unverifiable("MRK-3", "dependency", "a:1->b:1", "边不存在")
        with self.assertRaises(ValidationError):
            self.service.mark_unverifiable("MRK-4", "vin", "V001", "不支持的类型")
        with self.assertRaises(ConflictError):
            self.service.mark_unverifiable("MRK-2", "attestation", "ATT-1", "重复标记")


class ExportManifestTests(ServiceTestCase):
    def test_manifest_is_traceable_and_deduped(self):
        self.service.register_attestation("ATT-1", "chipco", "crypto-lib", "1.6", "sha256:aa")
        self.service.propose_mitigation("MIT-1", "ADV-CRYPTO", "OTA 升级", actor="op")
        self.service.approve_mitigation("MIT-1", actor="lead")
        self.service.confirm_disposition("DISP-1", "ADV-CRYPTO", "召回", actor="op")
        manifest = self.service.export_manifest("ADV-CRYPTO")

        self.assertEqual(manifest["advisory"]["advisory_id"], "ADV-CRYPTO")
        self.assertEqual(manifest["impact"]["counts"]["vehicles_total"], 4)
        vins = [v["vin"] for v in manifest["impact"]["vehicles"]]
        self.assertEqual(len(vins), len(set(vins)))
        self.assertEqual([d["disposition_id"] for d in manifest["dispositions"]], ["DISP-1"])
        self.assertEqual(manifest["mitigations"][0]["status"], "approved")
        self.assertEqual([a["attestation_id"] for a in manifest["attestations"]], ["ATT-1"])

        actions = [e["action"] for e in manifest["audit_trail"]]
        for expected in ["publish_advisory", "register_attestation",
                         "propose_mitigation", "approve_mitigation", "confirm_disposition"]:
            self.assertIn(expected, actions)
        seqs = [e["seq"] for e in manifest["audit_trail"]]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(manifest["manifest_hash"]), 64)

    def test_manifest_hash_is_stable_for_same_state(self):
        first = self.service.export_manifest("ADV-CRYPTO")
        second = self.service.export_manifest("ADV-CRYPTO")
        self.assertEqual(first["manifest_hash"], second["manifest_hash"])

    def test_export_missing_advisory_rejected(self):
        with self.assertRaises(NotFoundError):
            self.service.export_manifest("ADV-404")


if __name__ == "__main__":
    unittest.main()
