"""供应链影响追踪的领域实体。

实体分为几组：

- 登记资料：组件版本、来源证明、替代版本、依赖边、固件组合、
  车型配置、生产批次；
- 安全通告与影响处置：通告、处置批次（冻结快照）、缓解措施；
- 审核痕迹：无法核实标记、审计事件。

轻量的共享词汇（``ComponentRef``、``DependencyEdge``）沿用
:mod:`supply_chain_impact.contracts` 中的契约，本模块只补充带状态
与生命周期的完整实体。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .contracts import ComponentRef
from .versioning import VersionRange


class AttestationStatus(str, Enum):
    ACTIVE = "active"
    VOIDED = "voided"
    SUPERSEDED = "superseded"


class AdvisoryStatus(str, Enum):
    ACTIVE = "active"
    WITHDRAWN = "withdrawn"


class ReplacementStatus(str, Enum):
    ACTIVE = "active"
    WITHDRAWN = "withdrawn"


class MitigationStatus(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"


class DispositionStatus(str, Enum):
    FROZEN = "frozen"


@dataclass
class ComponentVersion:
    name: str
    version: str
    attributes: dict = field(default_factory=dict)

    @property
    def ref(self) -> ComponentRef:
        return ComponentRef(self.name, self.version)


@dataclass
class Attestation:
    """供应商对某个组件版本来源的声明。"""

    attestation_id: str
    supplier: str
    component_name: str
    component_version: str
    artifact_hash: str
    statement: str
    status: AttestationStatus
    created_at: float
    reason: str = ""
    replaced_by: str = ""


@dataclass
class Replacement:
    """供应商发布的替代版本：某区间内的旧版本应由新版本替代。"""

    replacement_id: str
    supplier: str
    component_name: str
    replaced_range: VersionRange
    replacement_version: str
    note: str
    status: ReplacementStatus
    created_at: float


@dataclass
class FirmwareBundle:
    """固件组合：一张钉死版本的车规 SBOM，附带硬件兼容范围。"""

    bundle_id: str
    ecu: str
    components: frozenset  # frozenset[ComponentRef]
    hw_min: str
    hw_max: str

    def supports_hardware(self, revision: str) -> bool:
        return VersionRange.parse(f">={self.hw_min},<={self.hw_max}").matches(revision)


@dataclass
class VehicleConfig:
    """车型配置：某车型在某个硬件修订上装配的一组固件组合。"""

    config_id: str
    model: str
    hardware_rev: str
    bundle_ids: tuple


@dataclass
class ProductionBatch:
    """生产批次：同一车型配置下下线的一组车辆（按 VIN 登记）。"""

    batch_id: str
    config_id: str
    vins: tuple
    plant: str = ""
    note: str = ""


@dataclass
class Advisory:
    advisory_id: str
    component_name: str
    affected_range: VersionRange
    title: str
    detail: str
    status: AdvisoryStatus
    created_at: float
    revoked_reason: str = ""


@dataclass
class Disposition:
    """处置批次：经办人确认时冻结的影响范围快照。"""

    disposition_id: str
    advisory_id: str
    plan: str
    actor: str
    created_at: float
    baseline_revision: int
    snapshot: dict
    status: DispositionStatus = DispositionStatus.FROZEN


@dataclass
class Mitigation:
    mitigation_id: str
    advisory_id: str
    action: str
    target_component: str
    fixed_version: str
    status: MitigationStatus
    proposed_by: str
    created_at: float
    approved_by: str = ""
    approved_at: float = 0.0


@dataclass
class UnverifiableMark:
    """经办人对某条链路（依赖边或来源证明）标注的无法核实记录。"""

    mark_id: str
    kind: str  # "dependency" 或 "attestation"
    key: str
    reason: str
    actor: str
    created_at: float


@dataclass
class Event:
    """审计事件：每一次状态变更追加一条，保证可追溯。"""

    seq: int
    ts: float
    actor: str
    action: str
    entity_kind: str
    entity_id: str
    payload: dict = field(default_factory=dict)
