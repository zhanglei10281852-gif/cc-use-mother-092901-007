"""应用服务：登记、供应商操作、通告影响、处置冻结与审核导出。

所有读写都经过 :class:`SupplyChainService`，HTTP 层只是它的薄包装。
每次变更写入审计事件并推进修订号；处置批次在确认时冻结快照，
之后资料变化只能通过差异接口观察。
"""

from __future__ import annotations

import hashlib
import json
import time

from .contracts import ComponentRef, DependencyEdge
from .impact import compute_impact, edge_key
from .models import (
    Advisory,
    AdvisoryStatus,
    Attestation,
    AttestationStatus,
    ComponentVersion,
    Disposition,
    FirmwareBundle,
    Mitigation,
    MitigationStatus,
    ProductionBatch,
    Replacement,
    ReplacementStatus,
    UnverifiableMark,
    VehicleConfig,
)
from .store import Store
from .versioning import VersionRange, compare_versions


class ServiceError(Exception):
    """业务错误基类，``code`` 供 API 层映射状态码。"""

    code = "error"


class NotFoundError(ServiceError):
    code = "not_found"


class ConflictError(ServiceError):
    code = "conflict"


class ValidationError(ServiceError):
    code = "validation"


def _require_text(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} 不能为空")
    return value.strip()


class SupplyChainService:
    def __init__(self, store: Store | None = None, clock=time.time):
        self.store = store or Store(clock=clock)
        self._clock = clock

    # ------------------------------------------------------------------
    # 序列化
    # ------------------------------------------------------------------

    @staticmethod
    def _ref_payload(ref: ComponentRef) -> dict:
        return {"name": ref.name, "version": ref.version}

    def _attestation_dict(self, att: Attestation) -> dict:
        return {
            "attestation_id": att.attestation_id,
            "supplier": att.supplier,
            "component_name": att.component_name,
            "component_version": att.component_version,
            "artifact_hash": att.artifact_hash,
            "statement": att.statement,
            "status": att.status.value,
            "reason": att.reason,
            "replaced_by": att.replaced_by,
            "created_at": att.created_at,
        }

    def _replacement_dict(self, repl: Replacement) -> dict:
        return {
            "replacement_id": repl.replacement_id,
            "supplier": repl.supplier,
            "component_name": repl.component_name,
            "replaced_range": repl.replaced_range.raw,
            "replacement_version": repl.replacement_version,
            "note": repl.note,
            "status": repl.status.value,
            "created_at": repl.created_at,
        }

    def _advisory_dict(self, advisory: Advisory) -> dict:
        return {
            "advisory_id": advisory.advisory_id,
            "component_name": advisory.component_name,
            "affected_range": advisory.affected_range.raw,
            "title": advisory.title,
            "detail": advisory.detail,
            "status": advisory.status.value,
            "revoked_reason": advisory.revoked_reason,
            "created_at": advisory.created_at,
        }

    def _disposition_dict(self, disposition: Disposition) -> dict:
        return {
            "disposition_id": disposition.disposition_id,
            "advisory_id": disposition.advisory_id,
            "plan": disposition.plan,
            "actor": disposition.actor,
            "status": disposition.status.value,
            "baseline_revision": disposition.baseline_revision,
            "created_at": disposition.created_at,
            "snapshot": disposition.snapshot,
        }

    def _mitigation_dict(self, mitigation: Mitigation) -> dict:
        return {
            "mitigation_id": mitigation.mitigation_id,
            "advisory_id": mitigation.advisory_id,
            "action": mitigation.action,
            "target_component": mitigation.target_component,
            "fixed_version": mitigation.fixed_version,
            "status": mitigation.status.value,
            "proposed_by": mitigation.proposed_by,
            "approved_by": mitigation.approved_by,
            "created_at": mitigation.created_at,
            "approved_at": mitigation.approved_at,
        }

    # ------------------------------------------------------------------
    # 登记：组件版本与依赖
    # ------------------------------------------------------------------

    def register_component_version(self, name: str, version: str, attributes: dict | None = None,
                                   actor: str = "system") -> dict:
        name = _require_text(name, "组件名称")
        version = _require_text(version, "组件版本")
        key = (name, version)
        existing = self.store.component_versions.get(key)
        if existing is not None:
            return {"name": name, "version": version, "attributes": dict(existing.attributes)}
        self.store.component_versions[key] = ComponentVersion(name, version, dict(attributes or {}))
        self.store.record(actor, "register_component_version", "component_version", f"{name}@{version}")
        return {"name": name, "version": version, "attributes": dict(attributes or {})}

    def register_dependency(self, dependent: dict, dependency: dict, actor: str = "system") -> dict:
        edge = DependencyEdge(
            ComponentRef(_require_text(dependent.get("name"), "依赖方名称"),
                         _require_text(dependent.get("version"), "依赖方版本")),
            ComponentRef(_require_text(dependency.get("name"), "被依赖方名称"),
                         _require_text(dependency.get("version"), "被依赖方版本")),
        )
        if edge in self.store.edges:
            return {"edge": edge_key(edge), "created": False}
        self.store.edges.add(edge)
        self.store.record(actor, "register_dependency", "dependency", edge_key(edge))
        return {"edge": edge_key(edge), "created": True}

    # ------------------------------------------------------------------
    # 供应商：来源证明与替代版本
    # ------------------------------------------------------------------

    def register_attestation(self, attestation_id: str, supplier: str, component_name: str,
                             component_version: str, artifact_hash: str, statement: str = "",
                             actor: str = "system") -> dict:
        attestation_id = _require_text(attestation_id, "证明编号")
        if attestation_id in self.store.attestations:
            raise ConflictError(f"来源证明已存在: {attestation_id}")
        supplier = _require_text(supplier, "供应商")
        component_name = _require_text(component_name, "组件名称")
        component_version = _require_text(component_version, "组件版本")
        attestation = Attestation(
            attestation_id=attestation_id,
            supplier=supplier,
            component_name=component_name,
            component_version=component_version,
            artifact_hash=_require_text(artifact_hash, "制品哈希"),
            statement=statement,
            status=AttestationStatus.ACTIVE,
            created_at=self._clock(),
        )
        # 同一供应商对同一组件版本只保留一份生效声明，旧声明自动替代
        for existing in self.store.attestations.values():
            if (
                existing.status == AttestationStatus.ACTIVE
                and existing.supplier == supplier
                and existing.component_name == component_name
                and existing.component_version == component_version
            ):
                existing.status = AttestationStatus.SUPERSEDED
                existing.replaced_by = attestation_id
                self.store.record(actor, "auto_supersede_attestation", "attestation",
                                  existing.attestation_id, {"replaced_by": attestation_id})
        self.store.attestations[attestation_id] = attestation
        self.store.record(actor, "register_attestation", "attestation", attestation_id,
                          {"supplier": supplier, "component": f"{component_name}@{component_version}"})
        return self._attestation_dict(attestation)

    def _get_attestation(self, attestation_id: str) -> Attestation:
        attestation = self.store.attestations.get(attestation_id)
        if attestation is None:
            raise NotFoundError(f"来源证明不存在: {attestation_id}")
        return attestation

    def void_attestation(self, attestation_id: str, reason: str, actor: str = "system") -> dict:
        attestation = self._get_attestation(attestation_id)
        if attestation.status != AttestationStatus.ACTIVE:
            raise ConflictError(f"只有生效中的声明可以作废，当前状态: {attestation.status.value}")
        attestation.status = AttestationStatus.VOIDED
        attestation.reason = _require_text(reason, "作废原因")
        self.store.record(actor, "void_attestation", "attestation", attestation_id,
                          {"reason": attestation.reason})
        return self._attestation_dict(attestation)

    def supersede_attestation(self, attestation_id: str, new_attestation: dict,
                              actor: str = "system") -> dict:
        old = self._get_attestation(attestation_id)
        if old.status != AttestationStatus.ACTIVE:
            raise ConflictError(f"只有生效中的声明可以被替代，当前状态: {old.status.value}")
        created = self.register_attestation(
            attestation_id=new_attestation.get("attestation_id", ""),
            supplier=new_attestation.get("supplier", old.supplier),
            component_name=new_attestation.get("component_name", old.component_name),
            component_version=new_attestation.get("component_version", old.component_version),
            artifact_hash=new_attestation.get("artifact_hash", ""),
            statement=new_attestation.get("statement", old.statement),
            actor=actor,
        )
        if old.status == AttestationStatus.ACTIVE:
            # 新声明没有触发自动替代（供应商或组件不同），显式收尾
            old.status = AttestationStatus.SUPERSEDED
            old.replaced_by = created["attestation_id"]
            self.store.record(actor, "supersede_attestation", "attestation",
                              old.attestation_id, {"replaced_by": created["attestation_id"]})
        return created

    def register_replacement(self, replacement_id: str, supplier: str, component_name: str,
                             replaced_range: str, replacement_version: str, note: str = "",
                             actor: str = "system") -> dict:
        replacement_id = _require_text(replacement_id, "替代记录编号")
        if replacement_id in self.store.replacements:
            raise ConflictError(f"替代记录已存在: {replacement_id}")
        replacement = Replacement(
            replacement_id=replacement_id,
            supplier=_require_text(supplier, "供应商"),
            component_name=_require_text(component_name, "组件名称"),
            replaced_range=VersionRange.parse(_require_text(replaced_range, "被替代区间")),
            replacement_version=_require_text(replacement_version, "替代版本"),
            note=note,
            status=ReplacementStatus.ACTIVE,
            created_at=self._clock(),
        )
        self.store.replacements[replacement_id] = replacement
        self.store.record(actor, "register_replacement", "replacement", replacement_id,
                          {"component": replacement.component_name,
                           "range": replacement.replaced_range.raw,
                           "replacement_version": replacement.replacement_version})
        return self._replacement_dict(replacement)

    def withdraw_replacement(self, replacement_id: str, reason: str, actor: str = "system") -> dict:
        replacement = self.store.replacements.get(replacement_id)
        if replacement is None:
            raise NotFoundError(f"替代记录不存在: {replacement_id}")
        if replacement.status != ReplacementStatus.ACTIVE:
            raise ConflictError(f"替代记录已撤回: {replacement_id}")
        replacement.status = ReplacementStatus.WITHDRAWN
        self.store.record(actor, "withdraw_replacement", "replacement", replacement_id,
                          {"reason": _require_text(reason, "撤回原因")})
        return self._replacement_dict(replacement)

    # ------------------------------------------------------------------
    # 登记：固件组合、车型配置、生产批次
    # ------------------------------------------------------------------

    def register_firmware_bundle(self, bundle_id: str, ecu: str, components: list,
                                 hw_min: str, hw_max: str, actor: str = "system") -> dict:
        bundle_id = _require_text(bundle_id, "固件组合编号")
        if bundle_id in self.store.bundles:
            raise ConflictError(f"固件组合已存在: {bundle_id}")
        hw_min = _require_text(hw_min, "硬件兼容下限")
        hw_max = _require_text(hw_max, "硬件兼容上限")
        if compare_versions(hw_min, hw_max) > 0:
            raise ValidationError(f"硬件兼容范围颠倒: {hw_min} > {hw_max}")
        refs = frozenset(
            ComponentRef(_require_text(item.get("name"), "组件名称"),
                         _require_text(item.get("version"), "组件版本"))
            for item in components
        )
        if not refs:
            raise ValidationError("固件组合至少包含一个组件")
        self.store.bundles[bundle_id] = FirmwareBundle(
            bundle_id=bundle_id, ecu=_require_text(ecu, "控制器型号"),
            components=refs, hw_min=hw_min, hw_max=hw_max,
        )
        self.store.record(actor, "register_firmware_bundle", "firmware_bundle", bundle_id,
                          {"components": sorted(f"{r.name}@{r.version}" for r in refs)})
        return self.get_firmware_bundle(bundle_id)

    def get_firmware_bundle(self, bundle_id: str) -> dict:
        bundle = self.store.bundles.get(bundle_id)
        if bundle is None:
            raise NotFoundError(f"固件组合不存在: {bundle_id}")
        return {
            "bundle_id": bundle.bundle_id,
            "ecu": bundle.ecu,
            "components": [self._ref_payload(ref) for ref in
                           sorted(bundle.components, key=lambda r: (r.name, r.version))],
            "hw_min": bundle.hw_min,
            "hw_max": bundle.hw_max,
        }

    def register_vehicle_config(self, config_id: str, model: str, hardware_rev: str,
                                bundle_ids: list, actor: str = "system") -> dict:
        config_id = _require_text(config_id, "车型配置编号")
        if config_id in self.store.configs:
            raise ConflictError(f"车型配置已存在: {config_id}")
        hardware_rev = _require_text(hardware_rev, "硬件修订")
        if not bundle_ids:
            raise ValidationError("车型配置至少引用一个固件组合")
        for bundle_id in bundle_ids:
            bundle = self.store.bundles.get(bundle_id)
            if bundle is None:
                raise NotFoundError(f"固件组合不存在: {bundle_id}")
            if not bundle.supports_hardware(hardware_rev):
                raise ValidationError(
                    f"固件组合 {bundle_id} 的硬件兼容范围 "
                    f"[{bundle.hw_min}, {bundle.hw_max}] 不含硬件修订 {hardware_rev}"
                )
        self.store.configs[config_id] = VehicleConfig(
            config_id=config_id, model=_require_text(model, "车型"),
            hardware_rev=hardware_rev, bundle_ids=tuple(bundle_ids),
        )
        self.store.record(actor, "register_vehicle_config", "vehicle_config", config_id,
                          {"model": model, "hardware_rev": hardware_rev})
        return self.get_vehicle_config(config_id)

    def get_vehicle_config(self, config_id: str) -> dict:
        config = self.store.configs.get(config_id)
        if config is None:
            raise NotFoundError(f"车型配置不存在: {config_id}")
        return {
            "config_id": config.config_id,
            "model": config.model,
            "hardware_rev": config.hardware_rev,
            "bundle_ids": list(config.bundle_ids),
        }

    def register_production_batch(self, batch_id: str, config_id: str, vins: list,
                                  plant: str = "", note: str = "", actor: str = "system") -> dict:
        batch_id = _require_text(batch_id, "生产批次编号")
        if batch_id in self.store.batches:
            raise ConflictError(f"生产批次已存在: {batch_id}")
        if config_id not in self.store.configs:
            raise NotFoundError(f"车型配置不存在: {config_id}")
        cleaned = tuple(dict.fromkeys(_require_text(vin, "车辆 VIN") for vin in (vins or [])))
        if not cleaned:
            raise ValidationError("生产批次至少包含一辆车")
        self.store.batches[batch_id] = ProductionBatch(
            batch_id=batch_id, config_id=config_id, vins=cleaned, plant=plant, note=note,
        )
        self.store.record(actor, "register_production_batch", "production_batch", batch_id,
                          {"config_id": config_id, "vehicle_count": len(cleaned)})
        return self.get_production_batch(batch_id)

    def get_production_batch(self, batch_id: str) -> dict:
        batch = self.store.batches.get(batch_id)
        if batch is None:
            raise NotFoundError(f"生产批次不存在: {batch_id}")
        return {
            "batch_id": batch.batch_id,
            "config_id": batch.config_id,
            "vins": list(batch.vins),
            "plant": batch.plant,
            "note": batch.note,
        }

    # ------------------------------------------------------------------
    # 安全通告与影响计算
    # ------------------------------------------------------------------

    def publish_advisory(self, advisory_id: str, component_name: str, affected_range: str,
                         title: str = "", detail: str = "", actor: str = "system") -> dict:
        advisory_id = _require_text(advisory_id, "通告编号")
        if advisory_id in self.store.advisories:
            raise ConflictError(f"安全通告已存在: {advisory_id}")
        advisory = Advisory(
            advisory_id=advisory_id,
            component_name=_require_text(component_name, "组件名称"),
            affected_range=VersionRange.parse(_require_text(affected_range, "受影响版本范围")),
            title=title,
            detail=detail,
            status=AdvisoryStatus.ACTIVE,
            created_at=self._clock(),
        )
        self.store.advisories[advisory_id] = advisory
        self.store.record(actor, "publish_advisory", "advisory", advisory_id,
                          {"component": advisory.component_name,
                           "range": advisory.affected_range.raw})
        return self._advisory_dict(advisory)

    def _get_advisory(self, advisory_id: str) -> Advisory:
        advisory = self.store.advisories.get(advisory_id)
        if advisory is None:
            raise NotFoundError(f"安全通告不存在: {advisory_id}")
        return advisory

    def revoke_advisory(self, advisory_id: str, reason: str, actor: str = "system") -> dict:
        advisory = self._get_advisory(advisory_id)
        if advisory.status == AdvisoryStatus.WITHDRAWN:
            raise ConflictError(f"安全通告已撤销: {advisory_id}")
        advisory.status = AdvisoryStatus.WITHDRAWN
        advisory.revoked_reason = _require_text(reason, "撤销原因")
        self.store.record(actor, "revoke_advisory", "advisory", advisory_id,
                          {"reason": advisory.revoked_reason})
        return self._advisory_dict(advisory)

    def get_impact(self, advisory_id: str) -> dict:
        advisory = self._get_advisory(advisory_id)
        report = compute_impact(self.store, advisory)
        report["generated_at"] = self._clock()
        return report

    # ------------------------------------------------------------------
    # 处置批次：确认冻结 + 差异
    # ------------------------------------------------------------------

    def confirm_disposition(self, disposition_id: str, advisory_id: str, plan: str,
                            actor: str = "system") -> dict:
        disposition_id = _require_text(disposition_id, "处置批次编号")
        if disposition_id in self.store.dispositions:
            raise ConflictError(f"处置批次已存在: {disposition_id}")
        advisory = self._get_advisory(advisory_id)
        if advisory.status == AdvisoryStatus.WITHDRAWN:
            raise ConflictError(f"通告已撤销，不能确认处置: {advisory_id}")
        report = compute_impact(self.store, advisory)
        snapshot = {
            "residual_vins": sorted(v["vin"] for v in report["vehicles"] if v["status"] == "residual"),
            "mitigated_vins": sorted(v["vin"] for v in report["vehicles"] if v["status"] == "mitigated"),
            "components": [f"{c['name']}@{c['version']}" for c in report["components"]],
            "bundles": list(report["bundles"]),
            "configs": list(report["configs"]),
            "batches": list(report["batches"]),
        }
        disposition = Disposition(
            disposition_id=disposition_id,
            advisory_id=advisory_id,
            plan=_require_text(plan, "处置方案"),
            actor=actor,
            created_at=self._clock(),
            baseline_revision=self.store.revision,
            snapshot=snapshot,
        )
        self.store.dispositions[disposition_id] = disposition
        self.store.record(actor, "confirm_disposition", "disposition", disposition_id,
                          {"advisory_id": advisory_id,
                           "residual_vehicles": len(snapshot["residual_vins"]),
                           "mitigated_vehicles": len(snapshot["mitigated_vins"])})
        return self._disposition_dict(disposition)

    def _get_disposition(self, disposition_id: str) -> Disposition:
        disposition = self.store.dispositions.get(disposition_id)
        if disposition is None:
            raise NotFoundError(f"处置批次不存在: {disposition_id}")
        return disposition

    def get_disposition(self, disposition_id: str) -> dict:
        return self._disposition_dict(self._get_disposition(disposition_id))

    def diff_disposition(self, disposition_id: str) -> dict:
        """冻结基线与当前资料的差异；基线本身永不变更。"""
        disposition = self._get_disposition(disposition_id)
        advisory = self._get_advisory(disposition.advisory_id)
        report = compute_impact(self.store, advisory)
        current_residual = {v["vin"] for v in report["vehicles"] if v["status"] == "residual"}
        current_mitigated = {v["vin"] for v in report["vehicles"] if v["status"] == "mitigated"}
        current_components = {f"{c['name']}@{c['version']}" for c in report["components"]}
        base_residual = set(disposition.snapshot["residual_vins"])
        base_mitigated = set(disposition.snapshot["mitigated_vins"])
        base_components = set(disposition.snapshot["components"])

        def delta(base: set, current: set) -> dict:
            return {"added": sorted(current - base), "removed": sorted(base - current)}

        return {
            "disposition_id": disposition_id,
            "advisory_id": disposition.advisory_id,
            "advisory_status": advisory.status.value,
            "baseline_revision": disposition.baseline_revision,
            "current_revision": self.store.revision,
            "residual_vehicles": delta(base_residual, current_residual),
            "mitigated_vehicles": delta(base_mitigated, current_mitigated),
            "components": delta(base_components, current_components),
        }

    # ------------------------------------------------------------------
    # 缓解措施
    # ------------------------------------------------------------------

    def propose_mitigation(self, mitigation_id: str, advisory_id: str, action: str,
                           target_component: str = "", fixed_version: str = "",
                           actor: str = "system") -> dict:
        mitigation_id = _require_text(mitigation_id, "缓解措施编号")
        if mitigation_id in self.store.mitigations:
            raise ConflictError(f"缓解措施已存在: {mitigation_id}")
        self._get_advisory(advisory_id)
        mitigation = Mitigation(
            mitigation_id=mitigation_id,
            advisory_id=advisory_id,
            action=_require_text(action, "缓解措施内容"),
            target_component=target_component,
            fixed_version=fixed_version,
            status=MitigationStatus.PROPOSED,
            proposed_by=actor,
            created_at=self._clock(),
        )
        self.store.mitigations[mitigation_id] = mitigation
        self.store.record(actor, "propose_mitigation", "mitigation", mitigation_id,
                          {"advisory_id": advisory_id, "action": mitigation.action})
        return self._mitigation_dict(mitigation)

    def approve_mitigation(self, mitigation_id: str, actor: str = "system") -> dict:
        mitigation = self.store.mitigations.get(mitigation_id)
        if mitigation is None:
            raise NotFoundError(f"缓解措施不存在: {mitigation_id}")
        if mitigation.status != MitigationStatus.PROPOSED:
            raise ConflictError(f"只有待批准的缓解措施可以批准，当前状态: {mitigation.status.value}")
        mitigation.status = MitigationStatus.APPROVED
        mitigation.approved_by = actor
        mitigation.approved_at = self._clock()
        self.store.record(actor, "approve_mitigation", "mitigation", mitigation_id,
                          {"advisory_id": mitigation.advisory_id})
        return self._mitigation_dict(mitigation)

    # ------------------------------------------------------------------
    # 审核：无法核实标记与可追溯导出
    # ------------------------------------------------------------------

    def mark_unverifiable(self, mark_id: str, kind: str, key: str, reason: str,
                          actor: str = "system") -> dict:
        mark_id = _require_text(mark_id, "标记编号")
        if any(mark.mark_id == mark_id for mark in self.store.unverifiable_marks):
            raise ConflictError(f"标记已存在: {mark_id}")
        kind = _require_text(kind, "链路类型")
        key = _require_text(key, "链路标识")
        if kind == "dependency":
            if not any(edge_key(edge) == key for edge in self.store.edges):
                raise NotFoundError(f"依赖边不存在: {key}")
        elif kind == "attestation":
            if key not in self.store.attestations:
                raise NotFoundError(f"来源证明不存在: {key}")
        else:
            raise ValidationError(f"不支持的链路类型: {kind}（应为 dependency 或 attestation）")
        mark = UnverifiableMark(
            mark_id=mark_id, kind=kind, key=key,
            reason=_require_text(reason, "无法核实原因"),
            actor=actor, created_at=self._clock(),
        )
        self.store.unverifiable_marks.append(mark)
        self.store.record(actor, "mark_unverifiable", "unverifiable_mark", mark_id,
                          {"kind": kind, "key": key})
        return {
            "mark_id": mark.mark_id,
            "kind": mark.kind,
            "key": mark.key,
            "reason": mark.reason,
            "actor": mark.actor,
            "created_at": mark.created_at,
        }

    def export_manifest(self, advisory_id: str) -> dict:
        """导出可追溯清单：影响范围、处置、缓解、证明与审计轨迹，附内容哈希。"""
        advisory = self._get_advisory(advisory_id)
        impact = self.get_impact(advisory_id)
        dispositions = [
            self._disposition_dict(d)
            for d in self.store.dispositions.values()
            if d.advisory_id == advisory_id
        ]
        mitigations = [
            self._mitigation_dict(m)
            for m in self.store.mitigations.values()
            if m.advisory_id == advisory_id
        ]
        affected_keys = {(c["name"], c["version"]) for c in impact["components"]}
        attestations = [
            self._attestation_dict(a)
            for a in self.store.attestations.values()
            if (a.component_name, a.component_version) in affected_keys
        ]
        replacements = [
            self._replacement_dict(r)
            for r in self.store.replacements.values()
            if r.component_name == advisory.component_name
        ]
        related_ids = (
            {("advisory", advisory_id)}
            | {("disposition", d["disposition_id"]) for d in dispositions}
            | {("mitigation", m["mitigation_id"]) for m in mitigations}
            | {("attestation", a["attestation_id"]) for a in attestations}
            | {("replacement", r["replacement_id"]) for r in replacements}
            | {("unverifiable_mark", m["mark_id"]) for m in impact["unverifiable"]}
        )
        audit_trail = [
            {
                "seq": event.seq,
                "ts": event.ts,
                "actor": event.actor,
                "action": event.action,
                "entity_kind": event.entity_kind,
                "entity_id": event.entity_id,
                "payload": event.payload,
            }
            for event in self.store.events
            if (event.entity_kind, event.entity_id) in related_ids
        ]
        manifest = {
            "manifest_version": 1,
            "advisory": self._advisory_dict(advisory),
            "generated_at": self._clock(),
            "revision": self.store.revision,
            "impact": impact,
            "dispositions": dispositions,
            "mitigations": mitigations,
            "attestations": attestations,
            "replacements": replacements,
            "audit_trail": audit_trail,
        }
        # 哈希只覆盖可追溯内容，剔除导出时刻等易变字段，
        # 保证同一资料状态下导出的清单哈希稳定。
        hashable = json.loads(json.dumps(manifest, ensure_ascii=False, default=str))
        hashable.pop("generated_at", None)
        hashable.get("impact", {}).pop("generated_at", None)
        canonical = json.dumps(hashable, sort_keys=True, ensure_ascii=False, default=str)
        manifest["manifest_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return manifest
