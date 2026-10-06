"""基于标准库 http.server 的 REST API。

资源路径：
  POST /components                        登记组件版本
  POST /attestations                      登记来源证明
  POST /declarations                      供应商声明依赖
  POST /declarations/{id}/revoke          作废声明
  POST /declarations/{id}/supersede       发布替代声明
  POST /replacements                      组件替换（全局/固件级部分替换）
  POST /firmware                          固件组合
  POST /hardware                          硬件兼容范围
  POST /models                            车型配置
  POST /batches                           生产批次
  POST /advisories                        发布安全通告
  POST /advisories/{id}/revoke            撤销通告
  GET  /advisories/{id}/impact            计算直接/传递影响
  POST /advisories/{id}/reviews           审核影响/标记无法核实链路
  POST /advisories/{id}/dispositions      冻结处置批次
  GET  /dispositions/{id}                 处置批次详情
  GET  /dispositions/{id}/diff            冻结后的差异
  POST /dispositions/{id}/mitigations     提出缓解措施
  POST /dispositions/{id}/mitigations/{mid}/decision  批准/拒绝
  GET  /dispositions/{id}/export          导出可追溯清单
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Tuple
from urllib.parse import urlparse

from .service import (
    AdvisoryRevokedError,
    NotFoundError,
    ServiceError,
    SupplyChainService,
    analysis_to_dict,
)


def as_comp(value: Any) -> Tuple[str, str]:
    """组件版本引用：接受 [name, version] 或 'name@version'。"""
    if isinstance(value, list) and len(value) == 2:
        return str(value[0]), str(value[1])
    if isinstance(value, str) and "@" in value:
        name, _, version = value.partition("@")
        return name, version
    raise ServiceError(f"组件引用必须是 [名称, 版本] 或 '名称@版本': {value!r}")


class SupplyChainAPIHandler(BaseHTTPRequestHandler):
    server_version = "SupplyChainImpact/1.0"

    # 由 server 注入
    service: SupplyChainService = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: Any) -> None:  # 安静输出
        return

    # ------------------------------------------------------------ 框架

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ServiceError(f"请求体不是合法 JSON: {exc}")
        if not isinstance(body, dict):
            raise ServiceError("请求体必须是 JSON 对象")
        return body

    def _send(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self, fn: Callable[..., Any], params: Dict[str, str]) -> None:
        try:
            body = self._read_json() if self.command == "POST" else {}
            result = fn(self, body, params)
        except NotFoundError as exc:
            self._send(404, {"error": str(exc)})
        except AdvisoryRevokedError as exc:
            self._send(409, {"error": str(exc), "code": "advisory_revoked"})
        except ServiceError as exc:
            self._send(400, {"error": str(exc)})
        except (KeyError, TypeError, ValueError) as exc:
            self._send(400, {"error": f"参数缺失或格式错误: {exc}"})
        else:
            self._send(200 if self.command == "GET" else 201, result)

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def _route(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        for pattern, verbs, handler in self.server.routes:  # type: ignore[attr-defined]
            if method not in verbs:
                continue
            match = re.fullmatch(pattern, path)
            if match:
                self._handle(handler, match.groupdict())
                return
        self._send(404, {"error": f"无此接口: {method} {path}"})

    # ------------------------------------------------------------ 端点处理

    # 以下方法签名统一为 (body, params)，由 _handle 调用

    def _components(self, body: dict, _: dict) -> dict:
        comp = self.service.register_component(
            body["name"],
            body["version"],
            kind=body.get("kind", "component"),
            supplier=body.get("supplier", ""),
            attestation=body.get("attestation", ""),
        )
        return {"component": [comp.name, comp.version]}

    def _attestations(self, body: dict, _: dict) -> dict:
        rec = self.service.add_attestation(
            body["component_name"],
            body["component_version"],
            body.get("kind", "sha256"),
            body["value"],
            body.get("supplier", ""),
        )
        return {
            "component": [rec.component_name, rec.component_version],
            "kind": rec.kind,
            "recorded_at": rec.recorded_at,
        }

    def _declarations(self, body: dict, _: dict) -> dict:
        decl_id = self.service.declare_dependency(
            as_comp(body["dependent"]),
            as_comp(body["dependency"]),
            supplier=body.get("supplier", ""),
            declaration_id=body.get("declaration_id"),
        )
        return {"declaration_id": decl_id}

    def _revoke_declaration(self, _: dict, params: dict) -> dict:
        self.service.revoke_declaration(params["id"], reason=_.get("reason", ""))
        return {"declaration_id": params["id"], "revoked": True}

    def _supersede_declaration(self, body: dict, params: dict) -> dict:
        new_id = self.service.supersede_declaration(
            params["id"],
            new_dependency=as_comp(body["dependency"]),
            supplier=body.get("supplier"),
            new_dependent=as_comp(body["dependent"]) if body.get("dependent") else None,
            reason=body.get("reason", ""),
        )
        return {"old_declaration_id": params["id"], "new_declaration_id": new_id}

    def _replacements(self, body: dict, _: dict) -> dict:
        self.service.apply_replacement(
            as_comp(body["old"]),
            as_comp(body["new"]),
            supplier=body.get("supplier", ""),
            scope=body.get("scope", "global"),
            firmware=as_comp(body["firmware"]) if body.get("firmware") else None,
        )
        return {"replaced": True}

    def _firmware(self, body: dict, _: dict) -> dict:
        key = self.service.register_firmware(
            body["name"], body["version"], [as_comp(c) for c in body["contains"]]
        )
        return {"firmware": [key[0], key[1]]}

    def _hardware(self, body: dict, _: dict) -> dict:
        self.service.register_hardware(
            body["hardware_id"],
            body["name"],
            [as_comp(c) for c in body.get("compatible_firmware", [])],
        )
        return {"hardware_id": body["hardware_id"]}

    def _models(self, body: dict, _: dict) -> dict:
        self.service.configure_model(
            body["model_code"],
            body["name"],
            firmware=[as_comp(c) for c in body["firmware"]],
            hardware=body.get("hardware", []),
        )
        return {"model_code": body["model_code"]}

    def _batches(self, body: dict, _: dict) -> dict:
        self.service.register_batch(
            body["batch_id"],
            body["model_code"],
            firmware_snapshot=[as_comp(c) for c in body["firmware_snapshot"]],
            vehicle_serials=list(body["vehicle_serials"]),
        )
        return {"batch_id": body["batch_id"], "vehicles": len(body["vehicle_serials"])}

    def _advisories(self, body: dict, _: dict) -> dict:
        self.service.publish_advisory(
            body["advisory_id"],
            body["component_name"],
            body["affected_range"],
            title=body.get("title", ""),
        )
        return {"advisory_id": body["advisory_id"], "status": "active"}

    def _revoke_advisory(self, body: dict, params: dict) -> dict:
        self.service.revoke_advisory(params["id"], reason=body.get("reason", ""))
        return {"advisory_id": params["id"], "status": "revoked"}

    def _impact(self, _: dict, params: dict) -> dict:
        analysis = self.service.compute_impact(params["id"])
        return analysis_to_dict(analysis)

    def _reviews(self, body: dict, params: dict) -> dict:
        mark_id = self.service.review_impact(
            params["id"],
            body["subject"],
            body["verdict"],
            operator=body.get("operator", ""),
            note=body.get("note", ""),
        )
        return {"mark_id": mark_id}

    def _create_disposition(self, body: dict, params: dict) -> dict:
        disposition_id = self.service.create_disposition(params["id"], note=body.get("note", ""))
        dsp = self.service.dispositions[disposition_id]
        return {
            "disposition_id": disposition_id,
            "advisory_id": dsp.advisory_id,
            "frozen_vehicles": len(dsp.vehicles),
            "frozen_batches": sorted(dsp.batches),
        }

    def _disposition_detail(self, _: dict, params: dict) -> dict:
        dsp = self.service._require_disposition(params["id"])
        return {
            "disposition_id": dsp.disposition_id,
            "advisory_id": dsp.advisory_id,
            "note": dsp.note,
            "vehicles": sorted(dsp.vehicles),
            "batches": sorted(dsp.batches),
            "models": sorted(dsp.models),
            "mitigations": [
                {
                    "mitigation_id": m.mitigation_id,
                    "kind": m.kind,
                    "target": m.target,
                    "detail": m.detail,
                    "status": m.status.value,
                }
                for m in dsp.mitigations
            ],
        }

    def _disposition_diff(self, _: dict, params: dict) -> dict:
        return self.service.diff_disposition(params["id"])

    def _mitigations(self, body: dict, params: dict) -> dict:
        mitigation_id = self.service.propose_mitigation(
            params["id"], body["kind"], body["target"], body.get("detail", "")
        )
        return {"mitigation_id": mitigation_id, "status": "proposed"}

    def _mitigation_decision(self, body: dict, params: dict) -> dict:
        self.service.decide_mitigation(
            params["id"],
            params["mid"],
            approve=bool(body["approve"]),
            operator=body.get("operator", ""),
            reason=body.get("reason", ""),
        )
        return {"mitigation_id": params["mid"], "decision": "approved" if body["approve"] else "rejected"}

    def _export(self, _: dict, params: dict) -> dict:
        return {
            "disposition_id": params["id"],
            "rows": self.service.export_traceability(params["id"]),
        }


def build_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    service = SupplyChainService()
    h = SupplyChainAPIHandler
    h.service = service

    routes = [
        (r"/components", {"POST"}, h._components),
        (r"/attestations", {"POST"}, h._attestations),
        (r"/declarations", {"POST"}, h._declarations),
        (r"/declarations/(?P<id>[^/]+)/revoke", {"POST"}, h._revoke_declaration),
        (r"/declarations/(?P<id>[^/]+)/supersede", {"POST"}, h._supersede_declaration),
        (r"/replacements", {"POST"}, h._replacements),
        (r"/firmware", {"POST"}, h._firmware),
        (r"/hardware", {"POST"}, h._hardware),
        (r"/models", {"POST"}, h._models),
        (r"/batches", {"POST"}, h._batches),
        (r"/advisories", {"POST"}, h._advisories),
        (r"/advisories/(?P<id>[^/]+)/revoke", {"POST"}, h._revoke_advisory),
        (r"/advisories/(?P<id>[^/]+)/impact", {"GET"}, h._impact),
        (r"/advisories/(?P<id>[^/]+)/reviews", {"POST"}, h._reviews),
        (r"/advisories/(?P<id>[^/]+)/dispositions", {"POST"}, h._create_disposition),
        (r"/dispositions/(?P<id>[^/]+)", {"GET"}, h._disposition_detail),
        (r"/dispositions/(?P<id>[^/]+)/diff", {"GET"}, h._disposition_diff),
        (r"/dispositions/(?P<id>[^/]+)/mitigations", {"POST"}, h._mitigations),
        (r"/dispositions/(?P<id>[^/]+)/mitigations/(?P<mid>[^/]+)/decision", {"POST"}, h._mitigation_decision),
        (r"/dispositions/(?P<id>[^/]+)/export", {"GET"}, h._export),
    ]

    server = ThreadingHTTPServer((host, port), h)
    server.service = service  # type: ignore[attr-defined]
    server.routes = routes  # type: ignore[attr-defined]
    return server


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="车规软件供应链影响追踪后端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = build_server(args.host, args.port)
    print(f"供应链影响追踪服务监听 http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
