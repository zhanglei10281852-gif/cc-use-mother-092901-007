"""HTTP API 端到端冒烟测试（标准库 http.server，随机端口）。"""

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from supply_chain_impact.api import build_server


class ApiClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def call(self, method: str, path: str, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))


class ApiFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = build_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.api = ApiClient(f"http://127.0.0.1:{cls.port}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def test_full_workflow(self):
        api = self.api
        status, _ = api.call("POST", "/components", {
            "name": "chip-lib", "version": "2.4.1", "supplier": "chipco",
            "attestation": "sha256:aaa",
        })
        self.assertEqual(status, 201)
        for v in ["3.0.0"]:
            self.assertEqual(api.call("POST", "/components", {
                "name": "camera-driver", "version": v, "supplier": "chipco"})[0], 201)

        self.assertEqual(api.call("POST", "/declarations", {
            "dependent": ["camera-driver", "3.0.0"],
            "dependency": "chip-lib@2.4.1",
            "supplier": "chipco",
        })[1]["declaration_id"], "DECL-0001")

        self.assertEqual(api.call("POST", "/firmware", {
            "name": "gateway-fw", "version": "5.2.0",
            "contains": [["camera-driver", "3.0.0"]],
        })[0], 201)
        self.assertEqual(api.call("POST", "/hardware", {
            "hardware_id": "HW-A", "name": "网关硬件",
            "compatible_firmware": [["gateway-fw", "5.2.0"]],
        })[0], 201)
        self.assertEqual(api.call("POST", "/models", {
            "model_code": "MODEL-Y", "name": "车型Y",
            "firmware": [["gateway-fw", "5.2.0"]], "hardware": ["HW-A"],
        })[0], 201)
        self.assertEqual(api.call("POST", "/batches", {
            "batch_id": "B-001", "model_code": "MODEL-Y",
            "firmware_snapshot": [["gateway-fw", "5.2.0"]],
            "vehicle_serials": ["VIN-1", "VIN-2"],
        })[0], 201)
        self.assertEqual(api.call("POST", "/advisories", {
            "advisory_id": "ADV-1", "component_name": "chip-lib",
            "affected_range": ">=2.4,<2.5", "title": "芯片漏洞",
        })[0], 201)

        status, impact = api.call("GET", "/advisories/ADV-1/impact")
        self.assertEqual(status, 200)
        self.assertEqual(impact["total_vehicles"], 2)
        self.assertIn(["gateway-fw", "5.2.0"],
                      [f["firmware"] for f in impact["impacted_firmware"]])

        # 审核 + 冻结
        self.assertEqual(api.call("POST", "/advisories/ADV-1/reviews", {
            "subject": "batch:B-001", "verdict": "confirmed",
            "operator": "alice", "note": "确认",
        })[0], 201)
        status, dsp = api.call("POST", "/advisories/ADV-1/dispositions", {"note": "召回"})
        self.assertEqual(status, 201)
        disposition_id = dsp["disposition_id"]
        self.assertEqual(dsp["frozen_vehicles"], 2)

        # 缓解措施提出与批准
        status, mit = api.call("POST", f"/dispositions/{disposition_id}/mitigations", {
            "kind": "recall", "target": "B-001", "detail": "OTA",
        })
        self.assertEqual(status, 201)
        status, decision = api.call(
            "POST",
            f"/dispositions/{disposition_id}/mitigations/{mit['mitigation_id']}/decision",
            {"approve": True, "operator": "alice"},
        )
        self.assertEqual(decision["decision"], "approved")

        # 导出
        status, exported = api.call("GET", f"/dispositions/{disposition_id}/export")
        self.assertEqual(status, 200)
        self.assertEqual(len(exported["rows"]), 2)

        # 差异：无新资料时为空
        status, diff = api.call("GET", f"/dispositions/{disposition_id}/diff")
        self.assertEqual(status, 200)
        self.assertEqual(diff["vehicles_added"], [])

        # 撤销通告后影响接口返回 409，差异显示车辆全部移出
        self.assertEqual(api.call("POST", "/advisories/ADV-1/revoke", {"reason": "误报"})[0], 201)
        status, err = api.call("GET", "/advisories/ADV-1/impact")
        self.assertEqual(status, 409)
        self.assertEqual(err["code"], "advisory_revoked")
        status, diff = api.call("GET", f"/dispositions/{disposition_id}/diff")
        self.assertTrue(diff["advisory_revoked"])
        self.assertEqual(len(diff["vehicles_removed"]), 2)

    def test_error_cases(self):
        api = self.api
        status, err = api.call("GET", "/advisories/UNKNOWN/impact")
        self.assertEqual(status, 404)
        status, err = api.call("POST", "/components", {"name": "x", "version": "bad!"})
        self.assertEqual(status, 400)
        self.assertEqual(api.call("GET", "/nope")[0], 404)


if __name__ == "__main__":
    unittest.main()
