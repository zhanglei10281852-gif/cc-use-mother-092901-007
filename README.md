# 车规软件供应链影响追踪后端

登记组件版本、来源证明、供应商声明、固件组合、硬件兼容范围、车型配置与生产批次；
安全通告按版本区间和依赖关系计算直接与传递影响，支持声明作废/替代、组件（部分）替换、
通告撤销、处置批次冻结与差异、影响审核与缓解措施审批，并导出可追溯清单。

## 设计要点

- **版本与区间**（`versioning.py`）：点分数字版本（`2.4.1`），区间支持 `>=、<=、>、<、==、!=`
  与通配符，如 `>=2.4.1,<2.5`。
- **声明生命周期**（`models.py`/`service.py`）：SBOM 依赖边由供应商声明产生，可**作废**（revoke）
  或被**替代声明**取代（supersede）；作废声明不参与计算，且替代声明再被作废时旧声明不会悄悄恢复。
- **替换关系**：全局替换与**固件级部分替换**（仅某个固件组合内生效）；替换在固件上下文中沿替换链解析。
- **影响计算**（`compute_impact`）：
  1. 版本区间匹配得到直接命中组件；
  2. 反向依赖闭包得到传递影响（`visited` 集合保证**依赖环不死循环**、多路径不重复展开）；
  3. 固件组合在各自上下文中展开依赖闭包并应用替换；
  4. 映射到车型配置与生产批次，**VIN 全局去重**——同一车辆经多条依赖路径只计入召回一次；
  5. 引用未登记组件的声明列入 `unverified_edges`，供经办人标记“无法核实”。
- **冻结与差异**：处置批次（disposition）创建时冻结车辆/批次/固件/车型与完整影响快照；
  后续资料变化只能通过 `diff` 看到 `added/removed`，快照不可变。通告撤销后差异显示全部移出。
- **审核与审批**：影响可标记 confirmed/dismissed/unverifiable；缓解措施（upgrade/replace/
  quarantine/recall）可提出、批准、拒绝；导出清单每辆车一行，含完整依赖路径、来源证明核实状态、
  审核结论与已批准措施。

## 运行

```bash
python -m unittest discover -s tests -v     # 28 个测试
python -m compileall -q src tests run_cli.py
python run_cli.py                            # 内存场景演示（影响→冻结→修复差异）
python run_cli.py --serve --port 8080        # HTTP API（仅标准库，无第三方依赖）
```

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/components` | 登记组件版本（含供应商、来源证明） |
| POST | `/attestations` | 补充来源证明（sha256/签名/审计说明） |
| POST | `/declarations` | 供应商声明依赖（`[名称,版本]` 或 `名称@版本`） |
| POST | `/declarations/{id}/revoke` | 作废声明 |
| POST | `/declarations/{id}/supersede` | 发布替代声明（旧声明作废并留痕） |
| POST | `/replacements` | 组件替换，`scope=global` 或 `firmware`（部分替换） |
| POST | `/firmware` | 固件组合（打包的组件版本集合） |
| POST | `/hardware` | 硬件兼容范围（可搭载的固件） |
| POST | `/models` | 车型配置 |
| POST | `/batches` | 生产批次（固件烧录快照 + VIN） |
| POST | `/advisories` | 发布安全通告（组件 + 版本区间） |
| POST | `/advisories/{id}/revoke` | 撤销通告（再查影响返回 409） |
| GET | `/advisories/{id}/impact` | 直接/传递影响、固件、车型、批次、VIN、链路 |
| POST | `/advisories/{id}/reviews` | 审核影响 / 标记无法核实链路 |
| POST | `/advisories/{id}/dispositions` | 冻结处置批次 |
| GET | `/dispositions/{id}` | 处置批次详情 |
| GET | `/dispositions/{id}/diff` | 冻结后资料差异 |
| POST | `/dispositions/{id}/mitigations` | 提出缓解措施 |
| POST | `/dispositions/{id}/mitigations/{mid}/decision` | 批准/拒绝 |
| GET | `/dispositions/{id}/export` | 导出可追溯清单（每车一行） |

## 测试覆盖

依赖环、版本分叉（同组件多版本独立匹配）、固件级部分替换与全局替换、
声明作废/替代/替代再撤回、通告撤销、处置冻结后只出差异、多依赖路径 VIN 去重、
无法核实链路标记、缓解措施审批、追溯清单导出，以及 HTTP API 端到端流程与错误码。
