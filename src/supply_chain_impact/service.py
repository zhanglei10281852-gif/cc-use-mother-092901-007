"""供应链影响追踪核心服务。

负责：
- 组件、来源证明、供应商声明（作废/替代）、组件替换的登记；
- 固件组合、硬件兼容范围、车型配置、生产批次的登记；
- 安全通告按版本区间与依赖关系计算直接/传递影响（环安全、去重）；
- 处置批次冻结与差异计算；
- 影响审核、缓解措施审批、无法核实链路标记、可追溯清单导出。
"""

from __future__ import annotations

import itertools
import time
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import (
    AdvisoryStatus,
    Attestation,
    Component,
    DispositionBatch,
    FirmwareBuild,
    HardwarePlatform,
    ImpactAnalysis,
    ImpactStatus,
    Mitigation,
    MitigationStatus,
    ProductionBatch,
    Replacement,
    ReviewMark,
    SecurityAdvisoryRecord,
    SupplierDeclaration,
    VehicleModel,
    new_id,
)
from .versioning import Version, VersionRange

Comp = Tuple[str, str]


class ServiceError(Exception):
    """业务校验错误。"""


class NotFoundError(ServiceError):
    """引用的资源不存在。"""


class AdvisoryRevokedError(ServiceError):
    """通告已撤销，不再产生影响。"""


class SupplyChainService:
    def __init__(self) -> None:
        self.components: Dict[Comp, Component] = {}
        self.attestations: List[Attestation] = []
        self.declarations: Dict[str, SupplierDeclaration] = {}
        self.replacements: List[Replacement] = []
        self.firmware: Dict[Comp, FirmwareBuild] = {}
        self.hardware: Dict[str, HardwarePlatform] = {}
        self.models: Dict[str, VehicleModel] = {}
        self.batches: Dict[str, ProductionBatch] = {}
        self.advisories: Dict[str, SecurityAdvisoryRecord] = {}
        self.dispositions: Dict[str, DispositionBatch] = {}
        self.marks: List[ReviewMark] = []
        self._counter = itertools.count()

    # ------------------------------------------------------------ 登记

    def register_component(
        self,
        name: str,
        version: str,
        kind: str = "component",
        supplier: str = "",
        attestation: str = "",
    ) -> Component:
        Version(version)  # 校验
        key = (name, version)
        comp = self.components.get(key)
        if comp is None:
            comp = Component(name, version, kind, supplier, attestation)
            self.components[key] = comp
        return comp

    def add_attestation(
        self, component_name: str, component_version: str, kind: str, value: str, supplier: str
    ) -> Attestation:
        if not value.strip():
            raise ServiceError("来源证明内容不能为空")
        record = Attestation(component_name, component_version, kind, value, supplier)
        self.attestations.append(record)
        return record

    def declare_dependency(
        self,
        dependent: Comp,
        dependency: Comp,
        supplier: str,
        declaration_id: Optional[str] = None,
    ) -> str:
        if dependent == dependency:
            raise ServiceError("组件不能依赖自身")
        decl_id = declaration_id or new_id("DECL", self._counter)
        if decl_id in self.declarations:
            raise ServiceError(f"声明编号已存在: {decl_id}")
        self.declarations[decl_id] = SupplierDeclaration(
            declaration_id=decl_id,
            dependent=dependent,
            dependency=dependency,
            supplier=supplier,
        )
        return decl_id

    def revoke_declaration(self, declaration_id: str, reason: str = "") -> None:
        """供应商作废旧声明。作废声明不参与影响计算。"""
        decl = self._require_declaration(declaration_id)
        if decl.revoked:
            return
        self.declarations[declaration_id] = SupplierDeclaration(
            declaration_id=decl.declaration_id,
            dependent=decl.dependent,
            dependency=decl.dependency,
            supplier=decl.supplier,
            declared_at=decl.declared_at,
            revoked=True,
            revoked_at=time.time(),
            revocation_reason=reason,
            superseded_by=decl.superseded_by,
        )

    def supersede_declaration(
        self,
        old_declaration_id: str,
        new_dependency: Comp,
        supplier: Optional[str] = None,
        new_dependent: Optional[Comp] = None,
        reason: str = "",
    ) -> str:
        """发布替代声明：旧声明作废，新声明生效（典型为依赖版本升级）。"""
        old = self._require_declaration(old_declaration_id)
        if old.revoked and not old.superseded_by:
            # 已单独作废的声明不应被替代
            raise ServiceError(f"声明 {old_declaration_id} 已作废，不能再被替代")
        new_id_ = new_id("DECL", self._counter)
        self.declarations[new_id_] = SupplierDeclaration(
            declaration_id=new_id_,
            dependent=new_dependent or old.dependent,
            dependency=new_dependency,
            supplier=supplier if supplier is not None else old.supplier,
        )
        self.revoke_declaration(old_declaration_id, reason=reason or f"被 {new_id_} 替代")
        self.declarations[old_declaration_id] = SupplierDeclaration(
            declaration_id=old.declaration_id,
            dependent=old.dependent,
            dependency=old.dependency,
            supplier=old.supplier,
            declared_at=old.declared_at,
            revoked=True,
            revoked_at=time.time(),
            revocation_reason=reason or f"被 {new_id_} 替代",
            superseded_by=new_id_,
        )
        return new_id_

    def apply_replacement(
        self,
        old: Comp,
        new: Comp,
        supplier: str,
        scope: str = "global",
        firmware: Optional[Comp] = None,
    ) -> None:
        """登记组件替换关系。scope=global 全局生效；scope=firmware 仅在指定固件组合中替换（部分替换）。"""
        if scope not in ("global", "firmware"):
            raise ServiceError("替换范围必须是 global 或 firmware")
        if scope == "firmware" and firmware is None:
            raise ServiceError("固件级替换必须指定固件组合")
        self.replacements.append(Replacement(old, new, supplier, scope, firmware))

    def register_firmware(self, name: str, version: str, contains: Iterable[Comp]) -> Comp:
        Version(version)
        contents = frozenset(contains)
        key = (name, version)
        self.firmware[key] = FirmwareBuild(key, name, version, contents)
        # 固件本身也登记为组件，便于依赖穿越固件层
        self.register_component(name, version, kind="firmware")
        for comp in contents:
            # 声明固件包含组件，复用依赖图；缺登记的组件在计算时标为无法核实
            if not any(
                d.dependent == key and d.dependency == comp and not d.revoked
                for d in self.declarations.values()
            ):
                self.declare_dependency(key, comp, supplier="firmware-bill")
        return key

    def register_hardware(
        self, hardware_id: str, name: str, compatible_firmware: Iterable[Comp]
    ) -> None:
        self.hardware[hardware_id] = HardwarePlatform(
            hardware_id, name, frozenset(compatible_firmware)
        )

    def configure_model(
        self,
        model_code: str,
        name: str,
        firmware: Iterable[Comp],
        hardware: Iterable[str] = (),
    ) -> None:
        fw = frozenset(firmware)
        unknown = [f"{n}@{v}" for n, v in fw if (n, v) not in self.firmware]
        if unknown:
            raise ServiceError(f"车型引用了未登记的固件组合: {unknown}")
        self.models[model_code] = VehicleModel(
            model_code, name, fw, frozenset(hardware)
        )

    def register_batch(
        self,
        batch_id: str,
        model_code: str,
        firmware_snapshot: Iterable[Comp],
        vehicle_serials: Sequence[str],
    ) -> None:
        if model_code not in self.models:
            raise ServiceError(f"未知车型: {model_code}")
        fw = frozenset(firmware_snapshot)
        unknown = [f"{n}@{v}" for n, v in fw if (n, v) not in self.firmware]
        if unknown:
            raise ServiceError(f"批次引用了未登记的固件组合: {unknown}")
        serials = tuple(vehicle_serials)
        if len(set(serials)) != len(serials):
            raise ServiceError("批次内 VIN 不得重复")
        self.batches[batch_id] = ProductionBatch(
            batch_id, model_code, fw, serials
        )

    # ------------------------------------------------------------ 通告

    def publish_advisory(
        self, advisory_id: str, component_name: str, affected_range: str, title: str = ""
    ) -> None:
        VersionRange(affected_range)  # 校验
        if advisory_id in self.advisories:
            raise ServiceError(f"通告编号已存在: {advisory_id}")
        self.advisories[advisory_id] = SecurityAdvisoryRecord(
            advisory_id, component_name, affected_range, title
        )

    def revoke_advisory(self, advisory_id: str, reason: str = "") -> None:
        """撤销通告：撤销后重新计算不再产生任何影响。"""
        record = self._require_advisory(advisory_id)
        if record.status is AdvisoryStatus.REVOKED:
            return
        self.advisories[advisory_id] = SecurityAdvisoryRecord(
            advisory_id=record.advisory_id,
            component_name=record.component_name,
            affected_range=record.affected_range,
            title=record.title,
            published_at=record.published_at,
            status=AdvisoryStatus.REVOKED,
            revoked_at=time.time(),
            revocation_reason=reason,
        )

    # ------------------------------------------------------------ 影响计算

    def _active_edges(self) -> List[Tuple[Comp, Comp, str]]:
        return [
            (d.dependent, d.dependency, d.declaration_id)
            for d in self.declarations.values()
            if not d.revoked
        ]

    def _replacement_target(self, comp: Comp, firmware_key: Comp) -> Optional[Comp]:
        """按替换关系解析组件在指定固件中的实际版本。固件级替换优先于全局替换。"""
        scoped = global_match = None
        for rep in self.replacements:
            if rep.old != comp:
                continue
            if rep.scope == "firmware" and rep.firmware == firmware_key:
                scoped = rep.new
            elif rep.scope == "global":
                global_match = rep.new
        return scoped or global_match

    def _resolve(self, comp: Comp, firmware_key: Comp) -> Comp:
        """按替换链解析组件在指定固件上下文中的实际版本。"""
        cur = comp
        seen: Set[Comp] = set()
        while cur not in seen:
            seen.add(cur)
            nxt = self._replacement_target(cur, firmware_key)
            if nxt is None:
                break
            cur = nxt
        return cur

    def effective_firmware_contents(self, firmware_key: Comp) -> FrozenSet[Comp]:
        """应用替换链后的固件实际内容（不展开依赖）。"""
        build = self.firmware[firmware_key]
        return frozenset(self._resolve(comp, firmware_key) for comp in build.contains)

    def _firmware_closure(
        self, firmware_key: Comp, forward: Dict[Comp, List[Comp]]
    ) -> Dict[Comp, List[Comp]]:
        """固件上下文内的有效依赖闭包（已应用替换、环安全）。

        返回 node -> 从固件内容根到该节点的前向路径。
        """
        build = self.firmware[firmware_key]
        roots = {self._resolve(comp, firmware_key) for comp in build.contains}
        closure: Dict[Comp, List[Comp]] = {}
        visited: Set[Comp] = set()
        stack: List[Tuple[Comp, List[Comp]]] = [(r, [r]) for r in roots]
        while stack:
            node, path = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            closure[node] = path
            for dep in forward.get(node, []):
                effective = self._resolve(dep, firmware_key)
                if effective not in visited:
                    stack.append((effective, path + [effective]))
        return closure

    def compute_impact(self, advisory_id: str) -> ImpactAnalysis:
        record = self._require_advisory(advisory_id)
        if record.status is AdvisoryStatus.REVOKED:
            raise AdvisoryRevokedError(f"通告 {advisory_id} 已撤销")

        affected_range = VersionRange(record.affected_range)

        # 1) 直接命中：已登记且版本落在区间内的组件
        direct: Set[Comp] = set()
        for name, version in self.components:
            if name == record.component_name and affected_range.contains(version):
                direct.add((name, version))

        # 2) 沿反向依赖边做传递闭包（visited 去环；共享 visited 保证多路径只展开一次）
        edges = self._active_edges()
        reverse: Dict[Comp, List[Tuple[Comp, str]]] = defaultdict(list)
        forward: Dict[Comp, List[Comp]] = defaultdict(list)
        unverified: Set[Tuple[str, str, str, str]] = set()
        for dependent, dependency, decl_id in edges:
            reverse[dependency].append((dependent, decl_id))
            forward[dependent].append(dependency)
            if dependent not in self.components or dependency not in self.components:
                unverified.add(
                    (
                        dependent[0],
                        dependent[1],
                        dependency[0],
                        dependency[1],
                    )
                )

        paths: Dict[Comp, List[Comp]] = {}
        visited: Set[Comp] = set()
        for root in sorted(direct):
            if root in visited:
                continue
            stack: List[Tuple[Comp, List[Comp]]] = [(root, [root])]
            while stack:
                node, path = stack.pop()
                if node in visited:
                    continue
                visited.add(node)
                paths[node] = path
                for dependent, _ in reverse.get(node, []):
                    if dependent not in visited:
                        stack.append((dependent, path + [dependent]))

        impacted_components: Dict[Comp, List[List[Comp]]] = {
            node: [path] for node, path in sorted(paths.items())
        }

        # 3) 固件组合：在各自固件上下文中展开依赖闭包并应用（部分）替换
        impacted_firmware: Dict[Comp, List[Comp]] = {}
        firmware_closures: Dict[Comp, Dict[Comp, List[Comp]]] = {}
        for fw_key in sorted(self.firmware):
            closure = self._firmware_closure(fw_key, forward)
            firmware_closures[fw_key] = closure
            hits = sorted(set(closure) & direct)
            if hits:
                impacted_firmware[fw_key] = hits

        # 4) 车型配置
        impacted_models = sorted(
            model_code
            for model_code, cfg in self.models.items()
            if set(cfg.firmware) & set(impacted_firmware)
        )

        # 5) 生产批次与车辆：VIN 全局去重，多条依赖路径只计一次
        impacted_batches: Dict[str, dict] = {}
        claimed_serials: Set[str] = set()
        for batch_id in sorted(self.batches):
            batch = self.batches[batch_id]
            batch_fw = sorted(set(batch.firmware_snapshot) & set(impacted_firmware))
            if not batch_fw:
                continue
            vehicles: Set[str] = set()
            vehicle_paths: Dict[str, Tuple[Comp, List[Comp]]] = {}
            for fw_key in batch_fw:
                for hit in impacted_firmware[fw_key]:
                    for vin in batch.vehicle_serials:
                        if vin in claimed_serials:
                            continue  # 同一车辆已由其他固件/路径计入
                        claimed_serials.add(vin)
                        vehicles.add(vin)
                        # 直接命中组件 -> 中间依赖 -> 固件根
                        vehicle_paths[vin] = (
                            fw_key,
                            list(reversed(firmware_closures[fw_key][hit])) + [fw_key],
                        )
            if vehicles:
                impacted_batches[batch_id] = {
                    "model_code": batch.model_code,
                    "vehicles": vehicles,
                    "paths": vehicle_paths,
                }

        return ImpactAnalysis(
            advisory_id=advisory_id,
            generated_at=time.time(),
            direct_components=sorted(direct),
            impacted_components=impacted_components,
            impacted_firmware=impacted_firmware,
            impacted_models=impacted_models,
            impacted_batches=impacted_batches,
            unverified_edges=sorted(unverified),
        )

    # ------------------------------------------------------------ 审核与处置

    def review_impact(
        self,
        advisory_id: str,
        subject: str,
        verdict: str,
        operator: str,
        note: str = "",
    ) -> str:
        """审核影响：confirmed / dismissed / unverifiable。"""
        self._require_advisory(advisory_id)
        if verdict not in (v.value for v in ImpactStatus):
            raise ServiceError("审核结论必须是 confirmed / dismissed / unverifiable")
        mark_id = new_id("REV", self._counter)
        self.marks.append(
            ReviewMark(mark_id, advisory_id, subject, verdict, operator, note)
        )
        return mark_id

    def marks_for(self, advisory_id: str) -> List[ReviewMark]:
        return [m for m in self.marks if m.advisory_id == advisory_id]

    def create_disposition(self, advisory_id: str, note: str = "") -> str:
        """冻结当前影响范围，建立处置批次。"""
        analysis = self.compute_impact(advisory_id)
        vehicles = frozenset(
            vin for info in analysis.impacted_batches.values() for vin in info["vehicles"]
        )
        disposition_id = new_id("DSP", self._counter)
        self.dispositions[disposition_id] = DispositionBatch(
            disposition_id=disposition_id,
            advisory_id=advisory_id,
            created_at=time.time(),
            note=note,
            vehicles=vehicles,
            batches=frozenset(analysis.impacted_batches),
            firmware=frozenset(analysis.impacted_firmware),
            models=frozenset(analysis.impacted_models),
            impact_snapshot=analysis_to_dict(analysis),
        )
        return disposition_id

    def diff_disposition(self, disposition_id: str) -> dict:
        """对比冻结快照与当前资料，只返回差异。"""
        dsp = self._require_disposition(disposition_id)
        try:
            current = self.compute_impact(dsp.advisory_id)
        except AdvisoryRevokedError:
            current = None
        current_vehicles = (
            frozenset()
            if current is None
            else frozenset(
                vin for info in current.impacted_batches.values() for vin in info["vehicles"]
            )
        )
        current_batches = frozenset() if current is None else frozenset(current.impacted_batches)
        current_firmware = (
            frozenset() if current is None else frozenset(current.impacted_firmware)
        )
        return {
            "disposition_id": disposition_id,
            "advisory_revoked": current is None,
            "frozen_vehicle_count": len(dsp.vehicles),
            "current_vehicle_count": len(current_vehicles),
            "vehicles_added": sorted(current_vehicles - dsp.vehicles),
            "vehicles_removed": sorted(dsp.vehicles - current_vehicles),
            "batches_added": sorted(current_batches - dsp.batches),
            "batches_removed": sorted(dsp.batches - current_batches),
            "firmware_added": _comp_sort(current_firmware - dsp.firmware),
            "firmware_removed": _comp_sort(dsp.firmware - current_firmware),
        }

    def propose_mitigation(
        self, disposition_id: str, kind: str, target: str, detail: str
    ) -> str:
        dsp = self._require_disposition(disposition_id)
        if kind not in ("upgrade", "replace", "quarantine", "recall"):
            raise ServiceError("缓解措施类型非法")
        mitigation_id = new_id("MIT", self._counter)
        dsp.mitigations.append(
            Mitigation(mitigation_id, kind, target, detail)
        )
        return mitigation_id

    def decide_mitigation(
        self,
        disposition_id: str,
        mitigation_id: str,
        approve: bool,
        operator: str,
        reason: str = "",
    ) -> None:
        dsp = self._require_disposition(disposition_id)
        for m in dsp.mitigations:
            if m.mitigation_id == mitigation_id:
                m.status = MitigationStatus.APPROVED if approve else MitigationStatus.REJECTED
                m.decided_by = operator
                m.decided_at = time.time()
                m.reason = reason
                return
        raise NotFoundError(f"缓解措施不存在: {mitigation_id}")

    # ------------------------------------------------------------ 导出

    def export_traceability(self, disposition_id: str) -> List[dict]:
        """导出可追溯清单：每辆车一行，含车型、批次、固件、命中链路、证明与审核状态。"""
        dsp = self._require_disposition(disposition_id)
        snap = dsp.impact_snapshot
        marks = {m.subject: m for m in self.marks_for(dsp.advisory_id)}
        rows: List[dict] = []
        for batch_id in snap["impacted_batches"]:
            info = snap["impacted_batches"][batch_id]
            for vin in sorted(info["vehicles"]):
                fw_ref, path_refs = info["paths"][vin]
                fw_name, fw_version = fw_ref
                path = [tuple(node) for node in path_refs]
                chain = [f"{n}@{v}" for n, v in path]
                rows.append(
                    {
                        "vin": vin,
                        "advisory_id": dsp.advisory_id,
                        "model_code": info["model_code"],
                        "batch_id": batch_id,
                        "firmware": f"{fw_name}@{fw_version}",
                        "impacted_component": chain[-1] if chain else "",
                        "direct_component": chain[0] if chain else "",
                        "dependency_path": " -> ".join(chain),
                        "attestation_verified": all(
                            (n, v) in self.components
                            and bool(self.components[(n, v)].attestation)
                            for n, v in path
                        ),
                        "unverified_links": [
                            f"{a}@{b}->{c}@{d}"
                            for a, b, c, d in snap["unverified_edges"]
                        ],
                        "review": _mark_dict(marks.get(f"vin:{vin}"))
                        or _mark_dict(marks.get(f"batch:{batch_id}"))
                        or "",
                        "mitigation": _mitigation_summary(dsp, vin),
                        "frozen_at": dsp.created_at,
                    }
                )
        return rows

    # ------------------------------------------------------------ 内部

    def _require_declaration(self, decl_id: str) -> SupplierDeclaration:
        if decl_id not in self.declarations:
            raise NotFoundError(f"声明不存在: {decl_id}")
        return self.declarations[decl_id]

    def _require_advisory(self, advisory_id: str) -> SecurityAdvisoryRecord:
        if advisory_id not in self.advisories:
            raise NotFoundError(f"通告不存在: {advisory_id}")
        return self.advisories[advisory_id]

    def _require_disposition(self, disposition_id: str) -> DispositionBatch:
        if disposition_id not in self.dispositions:
            raise NotFoundError(f"处置批次不存在: {disposition_id}")
        return self.dispositions[disposition_id]


# ---------------------------------------------------------------- 序列化


def _comp_sort(items: Iterable[Comp]) -> List[List[str]]:
    return [[n, v] for n, v in sorted(items)]


def _mark_dict(mark: Optional[ReviewMark]) -> dict:
    if mark is None:
        return {}
    return {
        "verdict": mark.verdict,
        "operator": mark.operator,
        "note": mark.note,
        "marked_at": mark.marked_at,
    }


def _mitigation_summary(dsp: DispositionBatch, vin: str) -> str:
    approved = [m for m in dsp.mitigations if m.status is MitigationStatus.APPROVED]
    if approved:
        return ";".join(f"{m.kind}:{m.target}" for m in approved)
    batch_scope = [m for m in dsp.mitigations if vin in m.target or m.kind == "recall"]
    if batch_scope:
        return "proposed"
    return ""


def analysis_to_dict(analysis: ImpactAnalysis) -> dict:
    return {
        "advisory_id": analysis.advisory_id,
        "generated_at": analysis.generated_at,
        "direct_components": [[n, v] for n, v in analysis.direct_components],
        "impacted_components": [
            {"component": [n, v], "path": [[a, b] for a, b in path]}
            for (n, v), [path] in analysis.impacted_components.items()
        ],
        "impacted_firmware": [
            {"firmware": [n, v], "via": [[a, b] for a, b in via]}
            for (n, v), via in analysis.impacted_firmware.items()
        ],
        "impacted_models": analysis.impacted_models,
        "impacted_batches": {
            batch_id: {
                "model_code": info["model_code"],
                "vehicles": sorted(info["vehicles"]),
                "paths": {
                    vin: [[fw[0], fw[1]], [[n, v] for n, v in path]]
                    for vin, (fw, path) in info["paths"].items()
                },
            }
            for batch_id, info in analysis.impacted_batches.items()
        },
        "unverified_edges": [list(e) for e in analysis.unverified_edges],
        "total_vehicles": analysis.total_vehicles(),
    }
