"""车规供应链影响追踪后端测试。

覆盖：直接/传递影响、依赖环、版本分叉、部分替换、声明作废/替代、
通告撤销、处置冻结与差异、多路径车辆去重、无法核实链路标记、
缓解措施审批与可追溯清单导出。
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact.service import (
    AdvisoryRevokedError,
    NotFoundError,
    ServiceError,
    SupplyChainService,
)
from supply_chain_impact.versioning import Version, VersionRange


class VersionTests(unittest.TestCase):
    def test_version_ordering_and_normalization(self):
        self.assertEqual(Version("1.2"), Version("1.2.0"))
        self.assertLess(Version("2.4.0"), Version("2.4.1"))
        self.assertLess(Version("9"), Version("10"))

    def test_range_matching(self):
        rng = VersionRange(">=2.4,<2.5")
        self.assertTrue(rng.contains("2.4.0"))
        self.assertTrue(rng.contains("2.4.9"))
        self.assertFalse(rng.contains("2.5"))
        self.assertFalse(rng.contains("2.3.9"))
        self.assertTrue(VersionRange("*").contains("99.99"))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            Version("1.a")
        with self.assertRaises(ValueError):
            VersionRange(">>1.0")


class ImpactScenarioMixin:
    """构造一个典型车规场景：
    chip-lib 2.4.1 <- camera-driver <- perception-fw / gateway-fw
    被两个车型与两个生产批次引用。
    """

    def build_world(self) -> SupplyChainService:
        svc = SupplyChainService()
        # 组件与来源证明
        for name, version, kind in [
            ("chip-lib", "2.4.0", "library"),
            ("chip-lib", "2.4.1", "library"),
            ("chip-lib", "2.5.0", "library"),
            ("camera-driver", "3.0.0", "component"),
            ("camera-driver", "3.1.0", "component"),
            ("perception-fw", "8.0.0", "firmware"),
            ("gateway-fw", "5.2.0", "firmware"),
        ]:
            svc.register_component(name, version, kind, supplier="chipco", attestation="hash:abc")

        self.decl_driver_300 = svc.declare_dependency(
            ("camera-driver", "3.0.0"), ("chip-lib", "2.4.1"), "chipco"
        )
        svc.declare_dependency(("camera-driver", "3.1.0"), ("chip-lib", "2.5.0"), "chipco")

        svc.register_firmware(
            "perception-fw", "8.0.0", [("camera-driver", "3.0.0"), ("chip-lib", "2.4.1")]
        )
        svc.register_firmware(
            "gateway-fw", "5.2.0", [("camera-driver", "3.0.0")]
        )

        svc.register_hardware("HW-A", "域控制器A", [("perception-fw", "8.0.0")])
        svc.configure_model(
            "MODEL-X", "车型X",
            [("perception-fw", "8.0.0"), ("gateway-fw", "5.2.0")],
            hardware=["HW-A"],
        )
        svc.configure_model(
            "MODEL-Y", "车型Y", [("gateway-fw", "5.2.0")]
        )
        svc.register_batch(
            "B-001", "MODEL-X",
            [("perception-fw", "8.0.0"), ("gateway-fw", "5.2.0")],
            ["VIN001", "VIN002"],
        )
        svc.register_batch(
            "B-002", "MODEL-Y",
            [("gateway-fw", "5.2.0")],
            ["VIN003"],
        )
        svc.publish_advisory("ADV-1", "chip-lib", ">=2.4.1,<2.5", title="芯片漏洞")
        return svc


class DirectAndTransitiveImpactTests(ImpactScenarioMixin, unittest.TestCase):
    def test_direct_and_transitive_impact(self):
        svc = self.build_world()
        result = svc.compute_impact("ADV-1")

        self.assertEqual(result.direct_components, [("chip-lib", "2.4.1")])
        # 传递：camera-driver 3.0.0 与两个固件
        impacted = set(result.impacted_components)
        self.assertIn(("camera-driver", "3.0.0"), impacted)
        self.assertIn(("perception-fw", "8.0.0"), impacted)
        self.assertIn(("gateway-fw", "5.2.0"), impacted)
        # 未受影响的分叉版本不计入
        self.assertNotIn(("chip-lib", "2.5.0"), impacted)
        self.assertNotIn(("camera-driver", "3.1.0"), impacted)

        self.assertEqual(set(result.impacted_models), {"MODEL-X", "MODEL-Y"})

    def test_vehicle_counted_once_across_multiple_paths(self):
        """VIN001/VIN002 同时搭载 perception-fw 和 gateway-fw，
        两条依赖路径都通向 chip-lib，但每辆车只能计入一次。"""
        svc = self.build_world()
        result = svc.compute_impact("ADV-1")
        self.assertEqual(result.total_vehicles(), 3)
        all_vins = [
            vin for info in result.impacted_batches.values() for vin in info["vehicles"]
        ]
        self.assertEqual(sorted(all_vins), ["VIN001", "VIN002", "VIN003"])
        self.assertEqual(set(result.impacted_batches["B-001"]["vehicles"]), {"VIN001", "VIN002"})


class DependencyCycleTests(unittest.TestCase):
    def test_cycle_does_not_hang_and_still_propagates(self):
        svc = SupplyChainService()
        for name, version in [("a", "1.0"), ("b", "1.0"), ("c", "1.0")]:
            svc.register_component(name, version)
        svc.declare_dependency(("a", "1.0"), ("b", "1.0"), "s")
        svc.declare_dependency(("b", "1.0"), ("c", "1.0"), "s")
        svc.declare_dependency(("c", "1.0"), ("a", "1.0"), "s")  # 环 a->b->c->a
        svc.publish_advisory("ADV-C", "c", ">=1.0,<2")
        result = svc.compute_impact("ADV-C")
        self.assertEqual(
            set(result.impacted_components),
            {("a", "1.0"), ("b", "1.0"), ("c", "1.0")},
        )

    def test_self_dependency_rejected(self):
        svc = SupplyChainService()
        svc.register_component("a", "1.0")
        with self.assertRaises(ServiceError):
            svc.declare_dependency(("a", "1.0"), ("a", "1.0"), "s")


class VersionForkTests(unittest.TestCase):
    def test_forked_versions_resolved_independently(self):
        """同一组件多个版本分叉，通告只命中区间内的版本。"""
        svc = SupplyChainService()
        for v in ["1.0.0", "1.1.0", "1.2.0", "2.0.0"]:
            svc.register_component("lib", v)
        svc.register_component("app", "1.0")
        svc.declare_dependency(("app", "1.0"), ("lib", "1.1.0"), "s")
        svc.publish_advisory("ADV-F", "lib", ">=1.1,<2")
        result = svc.compute_impact("ADV-F")
        self.assertEqual(
            result.direct_components, [("lib", "1.1.0"), ("lib", "1.2.0")]
        )
        # app 只依赖 1.1.0，仍受影响；未被任何固件/应用使用的 1.2.0 只是直接命中
        self.assertIn(("app", "1.0"), result.impacted_components)


class DeclarationLifecycleTests(ImpactScenarioMixin, unittest.TestCase):
    def test_revoked_declaration_removes_impact(self):
        svc = self.build_world()
        # 供应商作废旧声明并发布指向安全版本的替代声明
        new_decl = svc.supersede_declaration(
            self.decl_driver_300, ("chip-lib", "2.5.0"), reason="升级到安全版本"
        )
        result = svc.compute_impact("ADV-1")
        # camera-driver 不再经旧链路受影响；固件仅因直接打包 chip-lib 2.4.1 而受影响
        impacted = set(result.impacted_components)
        self.assertNotIn(("camera-driver", "3.0.0"), impacted)
        self.assertIn(("chip-lib", "2.4.1"), impacted)
        self.assertTrue(svc.declarations[self.decl_driver_300].revoked)
        self.assertEqual(
            svc.declarations[self.decl_driver_300].superseded_by, new_decl
        )

    def test_supersede_then_revoke_new_declaration(self):
        svc = self.build_world()
        new_decl = svc.supersede_declaration(
            self.decl_driver_300, ("chip-lib", "2.5.0")
        )
        svc.revoke_declaration(new_decl, reason="替代声明撤回")
        # 旧声明仍然作废：不会悄悄恢复
        result = svc.compute_impact("ADV-1")
        self.assertNotIn(("camera-driver", "3.0.0"), set(result.impacted_components))

    def test_supersede_revoked_declaration_rejected(self):
        svc = self.build_world()
        svc.revoke_declaration(self.decl_driver_300)
        with self.assertRaises(ServiceError):
            svc.supersede_declaration(self.decl_driver_300, ("chip-lib", "2.5.0"))


class PartialReplacementTests(ImpactScenarioMixin, unittest.TestCase):
    def test_firmware_scoped_partial_replacement(self):
        """部分替换：chip-lib 2.4.1 仅在 gateway-fw 中被 2.5.0 替换；
        perception-fw 仍含旧版本，车型影响范围相应缩小。"""
        svc = self.build_world()
        svc.apply_replacement(
            ("chip-lib", "2.4.1"),
            ("chip-lib", "2.5.0"),
            supplier="chipco",
            scope="firmware",
            firmware=("gateway-fw", "5.2.0"),
        )
        result = svc.compute_impact("ADV-1")
        self.assertIn(("perception-fw", "8.0.0"), result.impacted_firmware)
        self.assertNotIn(("gateway-fw", "5.2.0"), result.impacted_firmware)
        # MODEL-Y 整车使用 gateway-fw，不再受影响
        self.assertEqual(result.impacted_models, ["MODEL-X"])
        self.assertEqual(result.total_vehicles(), 2)
        self.assertEqual(set(result.impacted_batches), {"B-001"})

    def test_global_replacement(self):
        svc = self.build_world()
        svc.apply_replacement(
            ("chip-lib", "2.4.1"), ("chip-lib", "2.5.0"), supplier="chipco"
        )
        result = svc.compute_impact("ADV-1")
        self.assertEqual(result.impacted_firmware, {})
        self.assertEqual(result.total_vehicles(), 0)


class AdvisoryRevocationTests(ImpactScenarioMixin, unittest.TestCase):
    def test_revoked_advisory_has_no_impact(self):
        svc = self.build_world()
        self.assertEqual(svc.compute_impact("ADV-1").total_vehicles(), 3)
        svc.revoke_advisory("ADV-1", reason="误报")
        with self.assertRaises(AdvisoryRevokedError):
            svc.compute_impact("ADV-1")
        # 冻结批次的差异应反映通告撤销：全部车辆移出范围
        # 先在撤销前冻结（另建同一世界）
        svc2 = self.build_world()
        frozen = svc2.create_disposition("ADV-1")
        svc2.revoke_advisory("ADV-1")
        diff = svc2.diff_disposition(frozen)
        self.assertTrue(diff["advisory_revoked"])
        self.assertEqual(sorted(diff["vehicles_removed"]), ["VIN001", "VIN002", "VIN003"])
        self.assertEqual(diff["vehicles_added"], [])


class DispositionFreezeTests(ImpactScenarioMixin, unittest.TestCase):
    def test_freeze_then_new_batch_only_shows_diff(self):
        svc = self.build_world()
        frozen = svc.create_disposition("ADV-1", note="大会展示车辆处置")
        self.assertEqual(svc.dispositions[frozen].vehicles, frozenset({"VIN001", "VIN002", "VIN003"}))

        # 后续资料：新下线批次 + 一个车型换用安全固件
        svc.register_component("gateway-fw", "5.3.0", "firmware", supplier="tier1", attestation="h")
        svc.register_firmware("gateway-fw", "5.3.0", [("camera-driver", "3.1.0")])
        svc.register_batch(
            "B-003", "MODEL-Y", [("gateway-fw", "5.3.0")], ["VIN009"]
        )
        diff = svc.diff_disposition(frozen)
        self.assertEqual(diff["vehicles_added"], [])  # 新批次用安全固件，不受影响
        self.assertEqual(diff["vehicles_removed"], [])

        # 再下线一个仍使用旧固件的批次 -> 差异只包含新车
        svc.register_batch(
            "B-004", "MODEL-Y", [("gateway-fw", "5.2.0")], ["VIN010"]
        )
        diff = svc.diff_disposition(frozen)
        self.assertEqual(diff["vehicles_added"], ["VIN010"])
        self.assertEqual(diff["batches_added"], ["B-004"])
        # 冻结快照本身不变
        self.assertEqual(
            svc.dispositions[frozen].vehicles,
            frozenset({"VIN001", "VIN002", "VIN003"}),
        )

    def test_diff_after_supersede_removes_vehicles(self):
        svc = self.build_world()
        frozen = svc.create_disposition("ADV-1")
        # 全局修复：camera-driver 升级，且固件不再直接打包旧 chip-lib
        svc.supersede_declaration(self.decl_driver_300, ("chip-lib", "2.5.0"))
        # perception-fw 8.0.0 仍直接包含 chip-lib 2.4.1；为完全修复需替换固件内容
        svc.apply_replacement(
            ("chip-lib", "2.4.1"), ("chip-lib", "2.5.0"), supplier="chipco"
        )
        diff = svc.diff_disposition(frozen)
        self.assertEqual(sorted(diff["vehicles_removed"]), ["VIN001", "VIN002", "VIN003"])
        self.assertEqual(sorted(diff["firmware_removed"]), [
            ["gateway-fw", "5.2.0"], ["perception-fw", "8.0.0"]
        ])


class ReviewAndMitigationTests(ImpactScenarioMixin, unittest.TestCase):
    def test_review_mark_unverifiable_link(self):
        svc = self.build_world()
        # 增加一个无来源证明、未登记组件的声明
        svc.declare_dependency(
            ("mystery-fw", "1.0"), ("chip-lib", "2.4.1"), "unknown-supplier"
        )
        result = svc.compute_impact("ADV-1")
        self.assertTrue(
            any(edge[0] == "mystery-fw" for edge in result.unverified_edges)
        )
        mark_id = svc.review_impact(
            "ADV-1", "component:mystery-fw:1.0", "unverifiable",
            operator="alice", note="供应商无法提供 SBOM 证明",
        )
        self.assertTrue(mark_id.startswith("REV-"))
        marks = svc.marks_for("ADV-1")
        self.assertEqual(marks[0].verdict, "unverifiable")

    def test_confirm_dismiss_and_approve_mitigation(self):
        svc = self.build_world()
        frozen = svc.create_disposition("ADV-1")
        svc.review_impact("ADV-1", "batch:B-001", "confirmed", "alice", "确认召回")
        svc.review_impact("ADV-1", "vin:VIN003", "dismissed", "bob", "该 VIN 实为试制车")

        mit_id = svc.propose_mitigation(
            frozen, "recall", "B-001", "OTA 升级 perception-fw 至 8.1"
        )
        with self.assertRaises(NotFoundError):
            svc.decide_mitigation(frozen, "MIT-9999", True, "alice")
        svc.decide_mitigation(frozen, mit_id, True, "alice", reason="批准召回")
        detail = svc.dispositions[frozen]
        self.assertEqual(detail.mitigations[0].status.value, "approved")
        self.assertEqual(detail.mitigations[0].decided_by, "alice")

        # 拒绝另一条缓解措施
        mit2 = svc.propose_mitigation(frozen, "quarantine", "VIN002", "隔离观察")
        svc.decide_mitigation(frozen, mit2, False, "bob", reason="措施不足")
        self.assertEqual(detail.mitigations[1].status.value, "rejected")

    def test_invalid_verdict_rejected(self):
        svc = self.build_world()
        with self.assertRaises(ServiceError):
            svc.review_impact("ADV-1", "x", "maybe", "alice")


class ExportTests(ImpactScenarioMixin, unittest.TestCase):
    def test_traceability_export_rows(self):
        svc = self.build_world()
        frozen = svc.create_disposition("ADV-1")
        svc.review_impact("ADV-1", "batch:B-001", "confirmed", "alice", "召回")
        mit_id = svc.propose_mitigation(frozen, "recall", "B-001", "OTA")
        svc.decide_mitigation(frozen, mit_id, True, "alice")

        rows = svc.export_traceability(frozen)
        self.assertEqual(len(rows), 3)  # 每辆车一行，不重复
        by_vin = {row["vin"]: row for row in rows}
        row = by_vin["VIN001"]
        self.assertEqual(row["batch_id"], "B-001")
        self.assertEqual(row["direct_component"], "chip-lib@2.4.1")
        self.assertIn("chip-lib@2.4.1", row["dependency_path"])
        # B-001 同时搭载两个固件；VIN 全局去重，由排序在先的固件路径认领
        self.assertIn(row["firmware"], {"perception-fw@8.0.0", "gateway-fw@5.2.0"})
        self.assertIn(row["firmware"], row["dependency_path"])
        self.assertTrue(row["attestation_verified"])
        self.assertEqual(row["review"]["verdict"], "confirmed")
        self.assertIn("recall:B-001", row["mitigation"])
        self.assertEqual(row["advisory_id"], "ADV-1")


class RegistrationValidationTests(unittest.TestCase):
    def test_unknown_references_rejected(self):
        svc = SupplyChainService()
        with self.assertRaises(ServiceError):
            svc.configure_model("M1", "车型", [("fw", "1.0")])
        svc.register_firmware("fw", "1.0", [])
        svc.configure_model("M1", "车型", [("fw", "1.0")])
        with self.assertRaises(ServiceError):
            svc.register_batch("B1", "M1", [("fw", "9.9")], ["V1"])
        with self.assertRaises(ServiceError):
            svc.register_batch("B1", "UNKNOWN", [("fw", "1.0")], ["V1"])

    def test_duplicate_vin_in_batch_rejected(self):
        svc = SupplyChainService()
        svc.register_firmware("fw", "1.0", [])
        svc.configure_model("M1", "车型", [("fw", "1.0")])
        with self.assertRaises(ServiceError):
            svc.register_batch("B1", "M1", [("fw", "1.0")], ["V1", "V1"])

    def test_attestation_requires_value(self):
        svc = SupplyChainService()
        with self.assertRaises(ServiceError):
            svc.add_attestation("lib", "1.0", "sha256", "  ", "s")

    def test_unknown_advisory_and_disposition(self):
        svc = SupplyChainService()
        with self.assertRaises(NotFoundError):
            svc.compute_impact("NOPE")
        with self.assertRaises(NotFoundError):
            svc.diff_disposition("DSP-0001")


if __name__ == "__main__":
    unittest.main()
