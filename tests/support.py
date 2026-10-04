"""测试共享的图构建工具。

标准图覆盖两条版本分叉线（crypto-lib 1.x / 2.x）与多跳依赖：

- app-fw 9.1 -> net-stack 4.2 -> crypto-lib 1.6
- diag-core 5.0 -> crypto-lib 1.3
- cluster-fw 3.0 -> crypto-lib 2.1（分叉线，通告不应波及）

车型配置 CFG-A 装网关+诊断固件，CFG-B 装网关+仪表固件；
V002 同时出现在两个批次中，用于验证车辆去重。
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact import SupplyChainService  # noqa: E402


def build_standard_service() -> SupplyChainService:
    service = SupplyChainService()
    for name, version in [
        ("crypto-lib", "1.3"), ("crypto-lib", "1.6"), ("crypto-lib", "2.1"),
        ("net-stack", "4.2"), ("diag-core", "5.0"),
        ("app-fw", "9.1"), ("cluster-fw", "3.0"),
    ]:
        service.register_component_version(name, version)
    for dependent, dependency in [
        (("net-stack", "4.2"), ("crypto-lib", "1.6")),
        (("diag-core", "5.0"), ("crypto-lib", "1.3")),
        (("app-fw", "9.1"), ("net-stack", "4.2")),
        (("cluster-fw", "3.0"), ("crypto-lib", "2.1")),
    ]:
        service.register_dependency(
            {"name": dependent[0], "version": dependent[1]},
            {"name": dependency[0], "version": dependency[1]},
        )
    service.register_firmware_bundle("B-GW", "gateway", [
        {"name": "app-fw", "version": "9.1"},
        {"name": "net-stack", "version": "4.2"},
        {"name": "crypto-lib", "version": "1.6"},
    ], hw_min="H1", hw_max="H3")
    service.register_firmware_bundle("B-DIAG", "diag", [
        {"name": "diag-core", "version": "5.0"},
        {"name": "crypto-lib", "version": "1.3"},
    ], hw_min="H1", hw_max="H2")
    service.register_firmware_bundle("B-CLUSTER", "cluster", [
        {"name": "cluster-fw", "version": "3.0"},
        {"name": "crypto-lib", "version": "2.1"},
    ], hw_min="H1", hw_max="H4")
    service.register_vehicle_config("CFG-A", "Sedan-S", "H2", ["B-GW", "B-DIAG"])
    service.register_vehicle_config("CFG-B", "SUV-X", "H3", ["B-GW", "B-CLUSTER"])
    service.register_production_batch("LOT-1", "CFG-A", ["V001", "V002"])
    service.register_production_batch("LOT-2", "CFG-B", ["V003"])
    service.register_production_batch("LOT-3", "CFG-A", ["V002", "V004"])
    service.publish_advisory("ADV-CRYPTO", "crypto-lib", ">=1.0,<2.0", title="加密库缺陷")
    return service


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.service = build_standard_service()

    def impact(self, advisory_id="ADV-CRYPTO"):
        return self.service.get_impact(advisory_id)

    def component_status(self, report):
        return {f"{c['name']}@{c['version']}": c["status"] for c in report["components"]}

    def vehicle_status(self, report):
        return {v["vin"]: v["status"] for v in report["vehicles"]}
