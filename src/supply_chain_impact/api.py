"""JSON HTTP API（仅标准库实现）。

路由分发与传输分离：:func:`handle` 接收方法、路径与已解析的 JSON
请求体，返回 ``(状态码, 响应体)``，可以不起网络直接测试；
:func:`make_server` 把它包装成 ``http.server`` 服务。
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .service import ConflictError, NotFoundError, SupplyChainService, ValidationError

_ERROR_STATUS = {
    "not_found": 404,
    "conflict": 409,
    "validation": 400,
}


def _actor(body: dict) -> str:
    return body.get("actor") or "api-user"


def handle(service: SupplyChainService, method: str, path: str, body: dict | None = None):
    """按路由调用服务方法，返回 (HTTP 状态码, JSON 可序列化响应)。"""
    body = body or {}
    routes = _routes(service)
    for route_method, pattern, handler in routes:
        if route_method != method:
            continue
        match = pattern.fullmatch(path)
        if match:
            try:
                result = handler(body, **match.groupdict())
                return (200 if method == "GET" else 201), result
            except (NotFoundError, ConflictError, ValidationError) as exc:
                return _ERROR_STATUS[exc.code], {"error": exc.code, "message": str(exc)}
            except ValueError as exc:
                return 400, {"error": "validation", "message": str(exc)}
    return 404, {"error": "not_found", "message": f"路由不存在: {method} {path}"}


def _routes(service: SupplyChainService):
    def post(pattern):
        return ("POST", re.compile(pattern))

    def get(pattern):
        return ("GET", re.compile(pattern))

    return [
        get(r"/health") + (lambda body: {"status": "ok", "revision": service.store.revision},),
        post(r"/components/versions") + (
            lambda body: service.register_component_version(
                body.get("name", ""), body.get("version", ""),
                attributes=body.get("attributes"), actor=_actor(body)),),
        post(r"/dependencies") + (
            lambda body: service.register_dependency(
                body.get("dependent") or {}, body.get("dependency") or {}, actor=_actor(body)),),
        post(r"/attestations") + (
            lambda body: service.register_attestation(
                body.get("attestation_id", ""), body.get("supplier", ""),
                body.get("component_name", ""), body.get("component_version", ""),
                body.get("artifact_hash", ""), statement=body.get("statement", ""),
                actor=_actor(body)),),
        post(r"/attestations/(?P<attestation_id>[^/]+)/void") + (
            lambda body, attestation_id: service.void_attestation(
                attestation_id, body.get("reason", ""), actor=_actor(body)),),
        post(r"/attestations/(?P<attestation_id>[^/]+)/supersede") + (
            lambda body, attestation_id: service.supersede_attestation(
                attestation_id, body.get("attestation") or {}, actor=_actor(body)),),
        post(r"/replacements") + (
            lambda body: service.register_replacement(
                body.get("replacement_id", ""), body.get("supplier", ""),
                body.get("component_name", ""), body.get("replaced_range", ""),
                body.get("replacement_version", ""), note=body.get("note", ""),
                actor=_actor(body)),),
        post(r"/replacements/(?P<replacement_id>[^/]+)/withdraw") + (
            lambda body, replacement_id: service.withdraw_replacement(
                replacement_id, body.get("reason", ""), actor=_actor(body)),),
        post(r"/bundles") + (
            lambda body: service.register_firmware_bundle(
                body.get("bundle_id", ""), body.get("ecu", ""),
                body.get("components") or [], body.get("hw_min", ""),
                body.get("hw_max", ""), actor=_actor(body)),),
        get(r"/bundles/(?P<bundle_id>[^/]+)") + (
            lambda body, bundle_id: service.get_firmware_bundle(bundle_id),),
        post(r"/configs") + (
            lambda body: service.register_vehicle_config(
                body.get("config_id", ""), body.get("model", ""),
                body.get("hardware_rev", ""), body.get("bundle_ids") or [],
                actor=_actor(body)),),
        get(r"/configs/(?P<config_id>[^/]+)") + (
            lambda body, config_id: service.get_vehicle_config(config_id),),
        post(r"/batches") + (
            lambda body: service.register_production_batch(
                body.get("batch_id", ""), body.get("config_id", ""),
                body.get("vins") or [], plant=body.get("plant", ""),
                note=body.get("note", ""), actor=_actor(body)),),
        get(r"/batches/(?P<batch_id>[^/]+)") + (
            lambda body, batch_id: service.get_production_batch(batch_id),),
        post(r"/advisories") + (
            lambda body: service.publish_advisory(
                body.get("advisory_id", ""), body.get("component_name", ""),
                body.get("affected_range", ""), title=body.get("title", ""),
                detail=body.get("detail", ""), actor=_actor(body)),),
        post(r"/advisories/(?P<advisory_id>[^/]+)/revoke") + (
            lambda body, advisory_id: service.revoke_advisory(
                advisory_id, body.get("reason", ""), actor=_actor(body)),),
        get(r"/advisories/(?P<advisory_id>[^/]+)/impact") + (
            lambda body, advisory_id: service.get_impact(advisory_id),),
        get(r"/advisories/(?P<advisory_id>[^/]+)/export") + (
            lambda body, advisory_id: service.export_manifest(advisory_id),),
        post(r"/advisories/(?P<advisory_id>[^/]+)/dispositions") + (
            lambda body, advisory_id: service.confirm_disposition(
                body.get("disposition_id", ""), advisory_id,
                body.get("plan", ""), actor=_actor(body)),),
        post(r"/advisories/(?P<advisory_id>[^/]+)/mitigations") + (
            lambda body, advisory_id: service.propose_mitigation(
                body.get("mitigation_id", ""), advisory_id, body.get("action", ""),
                target_component=body.get("target_component", ""),
                fixed_version=body.get("fixed_version", ""), actor=_actor(body)),),
        get(r"/dispositions/(?P<disposition_id>[^/]+)") + (
            lambda body, disposition_id: service.get_disposition(disposition_id),),
        get(r"/dispositions/(?P<disposition_id>[^/]+)/diff") + (
            lambda body, disposition_id: service.diff_disposition(disposition_id),),
        post(r"/mitigations/(?P<mitigation_id>[^/]+)/approve") + (
            lambda body, mitigation_id: service.approve_mitigation(
                mitigation_id, actor=_actor(body)),),
        post(r"/review/unverifiable") + (
            lambda body: service.mark_unverifiable(
                body.get("mark_id", ""), body.get("kind", ""),
                body.get("key", ""), body.get("reason", ""), actor=_actor(body)),),
    ]


def make_server(service: SupplyChainService, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                self._respond(400, {"error": "validation", "message": "请求体不是合法 JSON"})
                return
            if not isinstance(body, dict):
                self._respond(400, {"error": "validation", "message": "请求体必须是 JSON 对象"})
                return
            status, payload = handle(service, method, self.path.split("?", 1)[0], body)
            self._respond(status, payload)

        def _respond(self, status: int, payload) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def log_message(self, format, *args) -> None:  # noqa: A002
            pass

    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    service = SupplyChainService()
    server = make_server(service, port=8080)
    print("供应链影响追踪 API 监听于 http://127.0.0.1:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
