"""端到端冒烟：登记资料 -> 发布通告 -> 计算影响 -> 冻结处置 -> 新增资料出差异 -> 导出清单。"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from supply_chain_impact import SupplyChainService

service = SupplyChainService()

# 芯片厂商与固件资料
service.register_component_version("camera-stack", "2.4.1")
service.register_component_version("perception-fw", "8.0.0")
service.register_attestation("ATT-1", "chipco", "camera-stack", "2.4.1", "sha256:aaa")
service.register_dependency(
    {"name": "perception-fw", "version": "8.0.0"},
    {"name": "camera-stack", "version": "2.4.1"},
)
service.register_firmware_bundle(
    "FW-ADAS-1", "adas-ecu",
    [{"name": "perception-fw", "version": "8.0.0"}, {"name": "camera-stack", "version": "2.4.1"}],
    hw_min="H2", hw_max="H4",
)
service.register_vehicle_config("CFG-SUV-H2", "SUV-X", "H2", ["FW-ADAS-1"])
service.register_production_batch("LOT-0901", "CFG-SUV-H2", ["VIN001", "VIN002"])

# 安全通告与影响
service.publish_advisory("ADV-1", "camera-stack", ">=2.4,<2.5", title="相机栈缓冲区溢出")
impact = service.get_impact("ADV-1")

# 经办人确认处置，冻结范围
service.confirm_disposition("DISP-1", "ADV-1", "OTA 升级 camera-stack 至 2.5.0", actor="operator-li")

# 新下线一批车辆，只能以差异形式呈现
service.register_production_batch("LOT-0902", "CFG-SUV-H2", ["VIN003"])
diff = service.diff_disposition("DISP-1")

manifest = service.export_manifest("ADV-1")
print(json.dumps({
    "受影响车辆": impact["counts"],
    "冻结基线车辆": impact["vehicles"] and manifest["dispositions"][0]["snapshot"]["residual_vins"],
    "新增差异": diff["residual_vehicles"],
    "清单哈希": manifest["manifest_hash"][:16],
}, ensure_ascii=False, indent=2))
