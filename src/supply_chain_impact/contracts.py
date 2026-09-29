"""组件依赖与安全通告的数据契约。"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ComponentRef:
    name: str
    version: str

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.version.strip():
            raise ValueError("组件名称和版本不能为空")


@dataclass(frozen=True)
class DependencyEdge:
    dependent: ComponentRef
    dependency: ComponentRef


@dataclass(frozen=True)
class SecurityAdvisory:
    advisory_id: str
    component_name: str
    affected_range: str

    def __post_init__(self) -> None:
        if not self.affected_range.strip():
            raise ValueError("受影响版本范围不能为空")
