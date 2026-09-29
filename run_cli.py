import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from supply_chain_impact.contracts import ComponentRef, DependencyEdge, SecurityAdvisory


source = ComponentRef("camera-stack", "2.4.1")
target = ComponentRef("perception-fw", "8.0.0")
edge = DependencyEdge(target, source)
advisory = SecurityAdvisory("ADV-1", "camera-stack", ">=2.4,<2.5")
print(json.dumps({"dependent": edge.dependent.name, "dependency": edge.dependency.name, "advisory": advisory.advisory_id}, ensure_ascii=False))
