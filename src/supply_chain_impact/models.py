"""供应链追踪的领域模型。

所有记录带状态与时间戳；供应商声明（SBOM 依赖关系）支持作废与替代版本，
作废的声明不参与影响计算，替代关系保证旧组件被新组件替换。
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Tuple


def _now() -> float:
    return time.time()


# ---------------------------------------------------------------- 组件与声明


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    kind: str = "component"  # component / library / firmware / bsp / os
    supplier: str = ""
    attestation: str = ""  # 来源证明（哈希、签名编号或审计说明）
    registered_at: float = field(default_factory=_now)


@dataclass(frozen=True)
class Attestation:
    """组件来源证明登记记录。"""

    component_name: str
    component_version: str
    kind: str  # sha256 / signature / audit-note
    value: str
    supplier: str
    recorded_at: float = field(default_factory=_now)


@dataclass(frozen=True)
class SupplierDeclaration:
    """供应商声明：某组件版本依赖另一组件版本（SBOM 边）。

    - revoked=True 表示声明被供应商作废，不再参与计算；
    - superseded_by 指向替代声明（供应商发布的替代版本）；
    - replaced_by 指向组件替代关系（旧组件被新组件替换）。
    """

    declaration_id: str
    dependent: Tuple[str, str]
    dependency: Tuple[str, str]
    supplier: str
    declared_at: float = field(default_factory=_now)
    revoked: bool = False
    revoked_at: Optional[float] = None
    revocation_reason: str = ""
    superseded_by: Optional[str] = None


@dataclass(frozen=True)
class Replacement:
    """组件替代关系：old 在固件中被 new 替换（部分或全部）。"""

    old: Tuple[str, str]
    new: Tuple[str, str]
    supplier: str
    # scope=firmware 表示仅在特定固件组合中替换；global 表示全局替换
    scope: str = "global"
    firmware: Optional[Tuple[str, str]] = None
    declared_at: float = field(default_factory=_now)


# ---------------------------------------------------------------- 固件/硬件/车型/批次


@dataclass(frozen=True)
class HardwarePlatform:
    hardware_id: str
    name: str
    compatible_firmware: FrozenSet[Tuple[str, str]]  # 硬件兼容范围


@dataclass(frozen=True)
class FirmwareBuild:
    """固件组合：把若干组件版本打包为一个可烧录固件。"""

    firmware_id: str  # (name, version) 同时也是组件表中的 firmware 组件
    name: str
    version: str
    contains: FrozenSet[Tuple[str, str]]
    created_at: float = field(default_factory=_now)


@dataclass(frozen=True)
class VehicleModel:
    """车型配置：某车型在配置上搭载的固件集合。"""

    model_code: str
    name: str
    firmware: FrozenSet[Tuple[str, str]]
    hardware: FrozenSet[str]
    configured_at: float = field(default_factory=_now)


@dataclass(frozen=True)
class ProductionBatch:
    """生产批次：已下线车辆的固件烧录快照。"""

    batch_id: str
    model_code: str
    firmware_snapshot: FrozenSet[Tuple[str, str]]  # 冻结的固件组合
    vehicle_serials: Tuple[str, ...]  # VIN 列表
    produced_at: float = field(default_factory=_now)


# ---------------------------------------------------------------- 通告


class AdvisoryStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"  # 通告撤销


@dataclass(frozen=True)
class SecurityAdvisoryRecord:
    advisory_id: str
    component_name: str
    affected_range: str
    title: str
    published_at: float = field(default_factory=_now)
    status: AdvisoryStatus = AdvisoryStatus.ACTIVE
    revoked_at: Optional[float] = None
    revocation_reason: str = ""


# ---------------------------------------------------------------- 影响评估


class ImpactStatus(str, Enum):
    OPEN = "open"                      # 待审核
    CONFIRMED = "confirmed"            # 经办人确认影响
    DISMISSED = "dismissed"            # 审核后排除
    UNVERIFIABLE = "unverifiable"      # 链路无法核实


class MitigationStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ImpactNode:
    """影响图上的一个组件版本命中点。"""

    component: Tuple[str, str]
    direct: bool  # 是否被通告直接命中


@dataclass
class ImpactAnalysis:
    """一次通告影响计算的完整结果。"""

    advisory_id: str
    generated_at: float
    direct_components: List[Tuple[str, str]]
    impacted_components: Dict[Tuple[str, str], List[List[Tuple[str, str]]]]
    impacted_firmware: Dict[Tuple[str, str], List[Tuple[str, str]]]
    impacted_models: List[str]
    # batch_id -> {"vehicles": set[vin], "paths": vin -> [(firmware, path)]}
    impacted_batches: Dict[str, dict]
    unverified_edges: List[Tuple[str, str, str, str]] = field(default_factory=list)

    def total_vehicles(self) -> int:
        total = 0
        for info in self.impacted_batches.values():
            total += len(info["vehicles"])
        return total


@dataclass
class DispositionBatch:
    """已确认的处置批次：创建时冻结范围，后续只产生差异。"""

    disposition_id: str
    advisory_id: str
    created_at: float
    note: str
    # 冻结快照
    vehicles: FrozenSet[str]
    batches: FrozenSet[str]
    firmware: FrozenSet[Tuple[str, str]]
    models: FrozenSet[str]
    impact_snapshot: dict  # 序列化的 ImpactAnalysis
    # 缓解措施
    mitigations: List["Mitigation"] = field(default_factory=list)


@dataclass
class Mitigation:
    mitigation_id: str
    kind: str  # upgrade / replace / quarantine / recall
    target: str  # 组件、固件或批次标识
    detail: str
    status: MitigationStatus = MitigationStatus.PROPOSED
    decided_by: str = ""
    decided_at: Optional[float] = None
    reason: str = ""


@dataclass
class ReviewMark:
    """审核标记：确认/排除影响，或标记无法核实的链路。"""

    mark_id: str
    advisory_id: str
    subject: str  # component:name:version / batch:id / vin
    verdict: str  # confirmed / dismissed / unverifiable
    operator: str
    note: str
    marked_at: float = field(default_factory=_now)


def new_id(prefix: str, counter: itertools.count) -> str:
    return f"{prefix}-{next(counter) + 1:04d}"
