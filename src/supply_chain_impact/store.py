"""内存仓储与审计日志。

所有实体保存在进程内字典中；每次变更把 ``revision`` 加一并追加一条
:class:`~supply_chain_impact.models.Event`，处置批次冻结时记录当时的
revision，后续差异都以它为基线计算。
"""

from __future__ import annotations

import time

from .models import (
    Advisory,
    Attestation,
    AttestationStatus,
    ComponentVersion,
    Disposition,
    Event,
    FirmwareBundle,
    Mitigation,
    ProductionBatch,
    Replacement,
    UnverifiableMark,
    VehicleConfig,
)


class Store:
    def __init__(self, clock=time.time):
        self._clock = clock
        self.revision = 0
        self.component_versions: dict = {}  # (name, version) -> ComponentVersion
        self.edges: set = set()  # DependencyEdge
        self.attestations: dict = {}  # id -> Attestation
        self.replacements: dict = {}  # id -> Replacement
        self.bundles: dict = {}  # id -> FirmwareBundle
        self.configs: dict = {}  # id -> VehicleConfig
        self.batches: dict = {}  # id -> ProductionBatch
        self.advisories: dict = {}  # id -> Advisory
        self.dispositions: dict = {}  # id -> Disposition
        self.mitigations: dict = {}  # id -> Mitigation
        self.unverifiable_marks: list = []  # list[UnverifiableMark]
        self.events: list = []  # list[Event]

    def record(self, actor: str, action: str, entity_kind: str, entity_id: str, payload: dict | None = None) -> Event:
        """推进修订号并追加审计事件，所有变更入口都必须经过这里。"""
        self.revision += 1
        event = Event(
            seq=len(self.events) + 1,
            ts=self._clock(),
            actor=actor,
            action=action,
            entity_kind=entity_kind,
            entity_id=entity_id,
            payload=payload or {},
        )
        self.events.append(event)
        return event

    # -- 查询辅助 ---------------------------------------------------------

    def known_refs(self) -> set:
        """已登记组件版本与依赖边端点的并集（图中可能出现未登记节点）。"""
        refs = {cv.ref for cv in self.component_versions.values()}
        for edge in self.edges:
            refs.add(edge.dependent)
            refs.add(edge.dependency)
        return refs

    def active_attestation_index(self) -> dict:
        """(组件名, 版本) -> 生效中的来源证明列表。"""
        index: dict = {}
        for att in self.attestations.values():
            if att.status == AttestationStatus.ACTIVE:
                index.setdefault((att.component_name, att.component_version), []).append(att)
        return index

    def dependents_of(self) -> dict:
        """反向邻接表：被依赖方 -> 依赖它的组件集合。"""
        reverse: dict = {}
        for edge in self.edges:
            reverse.setdefault(edge.dependency, set()).add(edge.dependent)
        return reverse
