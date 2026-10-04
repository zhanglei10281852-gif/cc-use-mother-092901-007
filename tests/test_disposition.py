"""处置批次：确认时冻结范围，后续资料变化只产生差异；通告撤销。"""

import unittest

from support import ServiceTestCase

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact import ConflictError, NotFoundError


class DispositionFreezeTests(ServiceTestCase):
    def setUp(self):
        super().setUp()
        self.disposition = self.service.confirm_disposition(
            "DISP-1", "ADV-CRYPTO", "召回升级 crypto-lib", actor="operator-li")

    def test_snapshot_frozen_at_confirmation(self):
        snapshot = self.disposition["snapshot"]
        self.assertEqual(snapshot["residual_vins"], ["V001", "V002", "V003", "V004"])
        self.assertEqual(snapshot["mitigated_vins"], [])
        self.assertIn("crypto-lib@1.3", snapshot["components"])
        self.assertEqual(self.disposition["status"], "frozen")

    def test_later_data_only_surfaces_as_diff(self):
        baseline_revision = self.disposition["baseline_revision"]
        self.service.register_production_batch("LOT-4", "CFG-A", ["V009"])
        diff = self.service.diff_disposition("DISP-1")
        self.assertEqual(diff["residual_vehicles"]["added"], ["V009"])
        self.assertEqual(diff["residual_vehicles"]["removed"], [])
        self.assertGreater(diff["current_revision"], diff["baseline_revision"])
        # 冻结基线不被后续资料改写
        frozen = self.service.get_disposition("DISP-1")
        self.assertEqual(frozen["baseline_revision"], baseline_revision)
        self.assertEqual(frozen["snapshot"]["residual_vins"], ["V001", "V002", "V003", "V004"])

    def test_partial_replacement_keeps_frozen_sets_but_changes_tiers(self):
        self.service.register_replacement("RPL-1", "chipco", "crypto-lib", ">=1.0,<1.5", "2.0.1")
        # 1.3 获得替代版本：CFG-A 车辆仍经 B-GW（1.6）残留，集合层面无差异
        diff = self.service.diff_disposition("DISP-1")
        self.assertEqual(diff["components"]["added"], [])
        self.assertEqual(diff["components"]["removed"], [])
        self.assertEqual(diff["residual_vehicles"]["removed"], [])
        # 但当前影响的分档已变化：B-DIAG 链路转为可缓解
        statuses = {f"{c['name']}@{c['version']}": c["status"]
                    for c in self.impact()["components"]}
        self.assertEqual(statuses["crypto-lib@1.3"], "mitigated")
        self.assertEqual(statuses["diag-core@5.0"], "mitigated")
        self.assertEqual(statuses["crypto-lib@1.6"], "residual")

    def test_component_diff_reflects_new_dependency_data(self):
        self.service.register_component_version("retrofit-fw", "7.7")
        self.service.register_dependency(
            {"name": "retrofit-fw", "version": "7.7"},
            {"name": "crypto-lib", "version": "1.6"},
        )
        diff = self.service.diff_disposition("DISP-1")
        self.assertEqual(diff["components"]["added"], ["retrofit-fw@7.7"])

    def test_confirm_on_withdrawn_advisory_rejected(self):
        self.service.revoke_advisory("ADV-CRYPTO", "误报")
        with self.assertRaises(ConflictError):
            self.service.confirm_disposition("DISP-2", "ADV-CRYPTO", "x")

    def test_missing_disposition_is_not_found(self):
        with self.assertRaises(NotFoundError):
            self.service.get_disposition("DISP-404")


class AdvisoryRevocationTests(ServiceTestCase):
    def test_revoked_advisory_computes_empty_impact(self):
        self.service.confirm_disposition("DISP-1", "ADV-CRYPTO", "召回", actor="op")
        self.service.revoke_advisory("ADV-CRYPTO", "芯片厂商撤回通告", actor="chipco")
        report = self.impact()
        self.assertEqual(report["advisory_status"], "withdrawn")
        self.assertEqual(report["counts"]["vehicles_total"], 0)
        self.assertEqual(report["components"], [])
        self.assertTrue(report["note"])

    def test_diff_against_frozen_baseline_shows_full_removal(self):
        self.service.confirm_disposition("DISP-1", "ADV-CRYPTO", "召回", actor="op")
        self.service.revoke_advisory("ADV-CRYPTO", "误报")
        diff = self.service.diff_disposition("DISP-1")
        self.assertEqual(diff["residual_vehicles"]["added"], [])
        self.assertEqual(diff["residual_vehicles"]["removed"], ["V001", "V002", "V003", "V004"])
        self.assertEqual(diff["advisory_status"], "withdrawn")

    def test_double_revoke_rejected(self):
        self.service.revoke_advisory("ADV-CRYPTO", "误报")
        with self.assertRaises(ConflictError):
            self.service.revoke_advisory("ADV-CRYPTO", "再次撤销")


if __name__ == "__main__":
    unittest.main()
