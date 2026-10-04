"""影响计算引擎。

给定一条安全通告，按版本区间命中直接受影响组件，再沿依赖图反向
（被依赖方 -> 依赖方）做传递闭包，随后映射到固件组合、车型配置、
生产批次与车辆。设计要点：

- 传递闭包用带访问集合的广度优先遍历，依赖环不会导致死循环；
- 供应商发布的替代版本把直接命中分为「可缓解」与「残留」两档，
  替代版本自身仍落在通告区间内的，不视为有效替代；
- 车辆按 VIN 去重，多条依赖路径命中同一辆车只计一次，
  只要存在一条残留路径，该车即按残留计；
- 输出全部排序，保证同一修订号下结果可复现。
"""

from __future__ import annotations

from collections import deque

from .contracts import ComponentRef
from .models import AdvisoryStatus, ReplacementStatus
from .store import Store


def edge_key(edge) -> str:
    """依赖边的稳定标识，用于无法核实标记与导出清单。"""
    return (
        f"{edge.dependent.name}:{edge.dependent.version}"
        f"->{edge.dependency.name}:{edge.dependency.version}"
    )


def _ref_dict(ref: ComponentRef) -> dict:
    return {"name": ref.name, "version": ref.version}


def _reach(seeds, reverse_adj) -> set:
    seen = set(seeds)
    queue = deque(seeds)
    while queue:
        node = queue.popleft()
        for dependent in reverse_adj.get(node, ()):
            if dependent not in seen:
                seen.add(dependent)
                queue.append(dependent)
    return seen


def _empty_report(advisory, revision: int, note: str) -> dict:
    return {
        "advisory_id": advisory.advisory_id,
        "advisory_status": advisory.status.value,
        "revision": revision,
        "note": note,
        "direct": [],
        "components": [],
        "evidence_edges": [],
        "bundles": [],
        "configs": [],
        "batches": [],
        "vehicles": [],
        "unverifiable": [],
        "counts": {
            "direct_components": 0,
            "affected_components": 0,
            "residual_vehicles": 0,
            "mitigated_vehicles": 0,
            "vehicles_total": 0,
        },
    }


def compute_impact(store: Store, advisory) -> dict:
    """计算通告的当前影响范围（直接 + 传递，含缓解分档）。"""
    if advisory.status == AdvisoryStatus.WITHDRAWN:
        return _empty_report(advisory, store.revision, "通告已撤销，影响范围按空集计算")

    # 1. 版本区间直接命中
    direct = sorted(
        (
            ref
            for ref in store.known_refs()
            if ref.name == advisory.component_name and advisory.affected_range.matches(ref.version)
        ),
        key=lambda r: (r.name, r.version),
    )

    # 2. 替代版本分档：命中版本被生效中的替代记录覆盖，且替代版本自身
    #    不在通告区间内，才算可缓解。
    active_replacements = [
        r
        for r in store.replacements.values()
        if r.status == ReplacementStatus.ACTIVE and r.component_name == advisory.component_name
    ]
    direct_entries = []
    residual_direct, mitigated_direct = [], []
    for ref in direct:
        replacement = next(
            (
                r
                for r in active_replacements
                if r.replaced_range.matches(ref.version)
                and not advisory.affected_range.matches(r.replacement_version)
            ),
            None,
        )
        if replacement is None:
            residual_direct.append(ref)
            mitigation = None
        else:
            mitigated_direct.append(ref)
            mitigation = {
                "replacement_id": replacement.replacement_id,
                "replacement_version": replacement.replacement_version,
                "supplier": replacement.supplier,
            }
        direct_entries.append({**_ref_dict(ref), "mitigation": mitigation})

    # 3. 传递闭包（环安全）：残留与可缓解分别传播，残留优先
    reverse_adj = store.dependents_of()
    residual_set = _reach(residual_direct, reverse_adj)
    mitigated_set = _reach(mitigated_direct, reverse_adj) - residual_set
    affected = residual_set | mitigated_set

    # 4. 证据子图：两端都受影响的依赖边，完整保留传播路径
    evidence = sorted(
        (edge for edge in store.edges if edge.dependent in affected and edge.dependency in affected),
        key=edge_key,
    )

    # 5. 组件清单：登记状态 + 来源证明核验状态
    attestation_index = store.active_attestation_index()
    components = []
    for ref in sorted(affected, key=lambda r: (r.name, r.version)):
        registered = (ref.name, ref.version) in store.component_versions
        verified = bool(attestation_index.get((ref.name, ref.version)))
        components.append(
            {
                **_ref_dict(ref),
                "registered": registered,
                "verified": verified,
                "status": "residual" if ref in residual_set else "mitigated",
            }
        )

    # 6. 固件组合 -> 车型配置 -> 生产批次 -> 车辆（按 VIN 去重）
    bundle_status = {}
    for bundle in store.bundles.values():
        if any(ref in residual_set for ref in bundle.components):
            bundle_status[bundle.bundle_id] = "residual"
        elif any(ref in mitigated_set for ref in bundle.components):
            bundle_status[bundle.bundle_id] = "mitigated"

    config_status = {}
    for config in store.configs.values():
        statuses = [bundle_status[b] for b in config.bundle_ids if b in bundle_status]
        if not statuses:
            continue
        config_status[config.config_id] = "residual" if "residual" in statuses else "mitigated"

    batch_status = {}
    for batch in store.batches.values():
        status = config_status.get(batch.config_id)
        if status:
            batch_status[batch.batch_id] = status

    vehicles: dict = {}
    for batch in store.batches.values():
        status = batch_status.get(batch.batch_id)
        if status is None:
            continue
        for vin in batch.vins:
            entry = vehicles.setdefault(
                vin,
                {"vin": vin, "status": status, "batches": set(), "configs": set()},
            )
            entry["batches"].add(batch.batch_id)
            entry["configs"].add(batch.config_id)
            if status == "residual":
                entry["status"] = "residual"

    vehicle_list = [
        {
            "vin": vin,
            "status": entry["status"],
            "batches": sorted(entry["batches"]),
            "configs": sorted(entry["configs"]),
        }
        for vin, entry in sorted(vehicles.items())
    ]

    # 7. 与本次影响相关的无法核实标记
    evidence_keys = {edge_key(edge) for edge in evidence}
    affected_attestation_ids = {
        att.attestation_id
        for att in store.attestations.values()
        if (att.component_name, att.component_version)
        in {(ref.name, ref.version) for ref in affected}
    }
    unverifiable = [
        {
            "mark_id": mark.mark_id,
            "kind": mark.kind,
            "key": mark.key,
            "reason": mark.reason,
            "actor": mark.actor,
        }
        for mark in store.unverifiable_marks
        if (mark.kind == "dependency" and mark.key in evidence_keys)
        or (mark.kind == "attestation" and mark.key in affected_attestation_ids)
    ]

    residual_count = sum(1 for v in vehicle_list if v["status"] == "residual")
    return {
        "advisory_id": advisory.advisory_id,
        "advisory_status": advisory.status.value,
        "revision": store.revision,
        "note": "",
        "direct": direct_entries,
        "components": components,
        "evidence_edges": [
            {"dependent": _ref_dict(edge.dependent), "dependency": _ref_dict(edge.dependency)}
            for edge in evidence
        ],
        "bundles": sorted(bundle_status),
        "configs": sorted(config_status),
        "batches": sorted(batch_status),
        "vehicles": vehicle_list,
        "unverifiable": unverifiable,
        "counts": {
            "direct_components": len(direct),
            "affected_components": len(components),
            "residual_vehicles": residual_count,
            "mitigated_vehicles": len(vehicle_list) - residual_count,
            "vehicles_total": len(vehicle_list),
        },
    }
