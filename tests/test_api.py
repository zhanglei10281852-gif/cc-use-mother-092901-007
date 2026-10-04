"""HTTP API 端到端：真实起服务，走完整审核流程。"""

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact import SupplyChainService
from supply_chain_impact.api import handle, make_server


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = SupplyChainService()
        cls.server = make_server(cls.service, port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def call(self, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class FullFlowTests(ApiTestCase):
    def test_end_to_end_review_flow(self):
        steps = [
            ("POST", "/components/versions", {"name": "camera-stack", "version": "2.4.1"}),
            ("POST", "/components/versions", {"name": "perception-fw", "version": "8.0.0"}),
            ("POST", "/dependencies", {
                "dependent": {"name": "perception-fw", "version": "8.0.0"},
                "dependency": {"name": "camera-stack", "version": "2.4.1"}}),
            ("POST", "/attestations", {
                "attestation_id": "ATT-1", "supplier": "chipco",
                "component_name": "camera-stack", "component_version": "2.4.1",
                "artifact_hash": "sha256:aaa"}),
            ("POST", "/bundles", {
                "bundle_id": "FW-1", "ecu": "adas",
                "components": [{"name": "perception-fw", "version": "8.0.0"},
                               {"name": "camera-stack", "version": "2.4.1"}],
                "hw_min": "H2", "hw_max": "H4"}),
            ("POST", "/configs", {
                "config_id": "CFG-1", "model": "SUV-X",
                "hardware_rev": "H2", "bundle_ids": ["FW-1"]}),
            ("POST", "/batches", {"batch_id": "LOT-1", "config_id": "CFG-1",
                                  "vins": ["VIN001", "VIN002", "VIN002"]}),
            ("POST", "/advisories", {
                "advisory_id": "ADV-1", "component_name": "camera-stack",
                "affected_range": ">=2.4,<2.5", "title": "相机栈缺陷"}),
        ]
        for method, path, body in steps:
            status, payload = self.call(method, path, body)
            self.assertLess(status, 300, f"{path} -> {payload}")

        status, impact = self.call("GET", "/advisories/ADV-1/impact")
        self.assertEqual(status, 200)
        self.assertEqual(impact["counts"]["vehicles_total"], 2, "批次内重复 VIN 也只计一次")
        self.assertEqual(impact["counts"]["affected_components"], 2)

        status, _ = self.call("POST", "/review/unverifiable", {
            "mark_id": "MRK-1", "kind": "dependency",
            "key": "perception-fw:8.0.0->camera-stack:2.4.1",
            "reason": "供应商尚未回传该链路 SBOM", "actor": "operator-li"})
        self.assertEqual(status, 201)

        status, _ = self.call("POST", "/advisories/ADV-1/mitigations", {
            "mitigation_id": "MIT-1", "action": "OTA 升级至 2.5.0",
            "target_component": "camera-stack", "fixed_version": "2.5.0"})
        self.assertEqual(status, 201)
        status, mitigation = self.call("POST", "/mitigations/MIT-1/approve",
                                       {"actor": "lead-wang"})
        self.assertEqual(mitigation["status"], "approved")

        status, disposition = self.call("POST", "/advisories/ADV-1/dispositions", {
            "disposition_id": "DISP-1", "plan": "两辆车进店升级", "actor": "operator-li"})
        self.assertEqual(status, 201)
        self.assertEqual(disposition["snapshot"]["residual_vins"], ["VIN001", "VIN002"])

        status, manifest = self.call("GET", "/advisories/ADV-1/export")
        self.assertEqual(status, 200)
        self.assertEqual(len(manifest["manifest_hash"]), 64)
        self.assertEqual([m["mark_id"] for m in manifest["impact"]["unverifiable"]], ["MRK-1"])
        self.assertTrue(manifest["audit_trail"])


class ErrorMappingTests(ApiTestCase):
    def test_not_found_conflict_and_validation(self):
        status, payload = self.call("GET", "/advisories/NOPE/impact")
        self.assertEqual((status, payload["error"]), (404, "not_found"))

        self.call("POST", "/advisories", {
            "advisory_id": "ADV-DUP", "component_name": "x", "affected_range": "*"})
        status, payload = self.call("POST", "/advisories", {
            "advisory_id": "ADV-DUP", "component_name": "x", "affected_range": "*"})
        self.assertEqual((status, payload["error"]), (409, "conflict"))

        status, payload = self.call("POST", "/components/versions", {"name": " ", "version": "1"})
        self.assertEqual((status, payload["error"]), (400, "validation"))

        status, _ = self.call("GET", "/no/such/route")
        self.assertEqual(status, 404)


class DispatchWithoutNetworkTests(unittest.TestCase):
    def test_handle_health(self):
        service = SupplyChainService()
        status, payload = handle(service, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "ok")


if __name__ == "__main__":
    unittest.main()
