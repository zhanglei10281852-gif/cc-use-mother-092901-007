# 车规软件供应链影响追踪

面向整车企业供应链团队的后端：登记组件版本、来源证明、固件组合、硬件兼容
范围、车型配置与生产批次；安全通告按版本区间与依赖关系计算直接与传递影响；
处置批次确认时冻结范围，后续资料变化只生成差异；同一车辆按 VIN 去重，不因
多条依赖路径被重复计入召回。

## 架构

```
src/supply_chain_impact/
├── contracts.py   # 共享词汇：ComponentRef / DependencyEdge / SecurityAdvisory
├── versioning.py  # 版本比较与区间匹配（>=1.0,<2.0 等逗号子句）
├── models.py      # 带生命周期的领域实体与状态枚举
├── store.py       # 内存仓储 + 审计事件日志 + 全局修订号
├── impact.py      # 影响引擎：区间命中 -> 依赖传递 -> 装车映射（环安全）
├── service.py     # 应用服务：登记/供应商操作/通告/处置/缓解/审核/导出
└── api.py         # JSON HTTP API（仅标准库，路由与传输分离）
```

关键语义：

- **传递影响**：通告命中组件版本后，沿「被依赖方 → 依赖方」反向传播，
  带访问集合，依赖环不会死循环；证据子图完整保留传播路径。
- **替代版本分档**：供应商发布的替代记录把直接命中分为「可缓解」与
  「残留」；替代版本自身仍落在通告区间内的不视为有效修复；只覆盖部分
  区间即为部分替换，车辆按残留优先分档。
- **来源证明**：同一供应商对同一组件版本只保留一份生效声明，重新登记
  自动替代旧声明；作废或替代后，影响报告中的 `verified` 标志即时变化。
- **处置冻结**：`confirm_disposition` 把当时的车辆/组件集合与修订号存为
  不可变快照；之后只能通过 `diff` 接口观察新增/移除。
- **通告撤销**：撤销后影响按空集计算，已冻结处置的差异显示为整体移除。
- **可追溯**：每次变更追加审计事件；导出清单含影响、处置、缓解、证明与
  审计轨迹，并附剔除易变字段后的内容哈希（同状态同哈希）。

## 运行

```bash
python3 -m unittest discover -s tests -v      # 测试
python3 -m compileall -q src tests run_cli.py # 编译检查
python3 run_cli.py                            # 端到端冒烟
python3 -m supply_chain_impact.api            # 启动 API（8080 端口，需 PYTHONPATH=src）
```

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/components/versions` | 登记组件版本 |
| POST | `/dependencies` | 登记依赖边（dependent → dependency） |
| POST | `/attestations` | 登记来源证明（同供应商同版本自动替代旧声明） |
| POST | `/attestations/{id}/void` · `/supersede` | 作废 / 替代声明 |
| POST | `/replacements` · `/replacements/{id}/withdraw` | 发布 / 撤回替代版本 |
| POST | `/bundles` · `/configs` · `/batches` | 固件组合 / 车型配置 / 生产批次 |
| POST | `/advisories` · `/advisories/{id}/revoke` | 发布 / 撤销安全通告 |
| GET | `/advisories/{id}/impact` | 直接 + 传递影响（车辆按 VIN 去重） |
| POST | `/advisories/{id}/dispositions` | 确认处置并冻结范围 |
| GET | `/dispositions/{id}` · `/diff` | 冻结快照 / 与当前资料的差异 |
| POST | `/advisories/{id}/mitigations` · `/mitigations/{id}/approve` | 提出 / 批准缓解措施 |
| POST | `/review/unverifiable` | 标记无法核实的依赖边或声明 |
| GET | `/advisories/{id}/export` | 导出可追溯清单（含内容哈希与审计轨迹） |

错误映射：`404 not_found`、`409 conflict`、`400 validation`。

## 测试覆盖

- `test_impact.py`：直接/传递影响、依赖环与自环、版本分叉、车辆多路径去重、硬件兼容门禁
- `test_supply_ops.py`：声明作废/替代/自动替代、部分替换、区间内替代无效、替代撤回
- `test_disposition.py`：处置冻结、差异计算、通告撤销后的整体移除
- `test_review.py`：缓解措施批准、无法核实标记、清单导出与哈希稳定性
- `test_versioning.py` / `test_api.py`：版本区间语义、HTTP 端到端与错误映射
