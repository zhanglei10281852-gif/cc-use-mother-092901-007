"""命令行冒烟：构造芯片通告场景，打印影响、冻结差异与追溯清单。

用法：
  python run_cli.py            # 内存场景演示
  python run_cli.py --serve    # 启动 HTTP 服务（默认 127.0.0.1:8080）
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from supply_chain_impact.api import main as serve_main
from supply_chain_impact.service import SupplyChainService


def build_demo() -> SupplyChainService:
    svc = SupplyChainService()
    for name, version, kind in [
        ("chip-lib", "2.4.1", "library"),
        ("chip-lib", "2.5.0", "library"),
        ("camera-driver", "3.0.0", "component"),
        ("perception-fw", "8.0.0", "firmware"),
        ("gateway-fw", "5.2.0", "firmware"),
    ]:
        svc.register_component(name, version, kind, supplier="chipco", attestation="sha256:abc")

    svc.declare_dependency(("camera-driver", "3.0.0"), ("chip-lib", "2.4.1"), "chipco")
    svc.register_firmware("perception-fw", "8.0.0", [("camera-driver", "3.0.0")])
    svc.register_firmware("gateway-fw", "5.2.0", [("camera-driver", "3.0.0")])
    svc.configure_model(
        "MODEL-X", "展示车型X",
        [("perception-fw", "8.0.0"), ("gateway-fw", "5.2.0")],
    )
    svc.register_batch(
        "B-001", "MODEL-X",
        [("perception-fw", "8.0.0"), ("gateway-fw", "5.2.0")],
        ["VIN001", "VIN002"],
    )
    svc.publish_advisory("ADV-1", "chip-lib", ">=2.4.1,<2.5", title="芯片安全通告")
    return svc


def main() -> None:
    if "--serve" in sys.argv:
        sys.argv.remove("--serve")
        serve_main()
        return

    from supply_chain_impact.service import analysis_to_dict

    svc = build_demo()
    impact = svc.compute_impact("ADV-1")
    print("== 通告影响 ==")
    print(json.dumps(analysis_to_dict(impact), ensure_ascii=False, indent=2))

    frozen = svc.create_disposition("ADV-1", note="大会展示车辆处置")
    print(f"\n== 已冻结处置批次 {frozen}，车辆 {sorted(svc.dispositions[frozen].vehicles)} ==")

    # 供应商发布替代版本后，差异只反映移出的车辆
    decls = [d for d in svc.declarations.values() if not d.revoked]
    svc.supersede_declaration(decls[0].declaration_id, ("chip-lib", "2.5.0"))
    svc.apply_replacement(("chip-lib", "2.4.1"), ("chip-lib", "2.5.0"), "chipco")
    print("\n== 修复后的冻结差异 ==")
    print(json.dumps(svc.diff_disposition(frozen), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
