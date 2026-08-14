# KineGrant 协议

**面向物理 AI 的授权基础设施。**

[![CI](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/ci.yml)
[![ESP32-C3 Firmware](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/firmware.yml/badge.svg)](https://github.com/zoahdev/kinegrant-protocol/actions/workflows/firmware.yml)
[![Release](https://img.shields.io/github/v/release/zoahdev/kinegrant-protocol)](https://github.com/zoahdev/kinegrant-protocol/releases)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![License](https://img.shields.io/github/license/zoahdev/kinegrant-protocol)](LICENSE.txt)

[官方网站](https://kinegrant.com) · [公开验证器](https://kinegrant.com/verify) · [技术白皮书](docs/whitepaper/KineGrant-KGP-001-Whitepaper-v0.1.pdf) · [KGP-001](spec/KGP-001.md) · [可复现指南](REPRODUCING.md) · [在 Codespaces 中打开](https://codespaces.new/zoahdev/kinegrant-protocol?ref=main&quickstart=1) · [威胁模型](spec/THREAT-MODEL.md) · [路线图](ROADMAP.md) · [English](README.md)

> **KGP-001 实验性开放草案 0.1 · 稳定线格式 1.0**
>
> **参考实现 v1.0.0 · Apache-2.0**
>
> 请勿将本实现作为真实机械设备的唯一安全控制。

KineGrant 是面向机器人与其他“物理 AI”系统的窄授权与问责层。在执行器执行动作之前，KineGrant 会验证一份短时、一次性的能力（capability），该能力精确绑定到主体、目标、动作、目的与策略决策。执行完成后，执行方可以生成一份签名、隐私最小化的收据。

KineGrant 不是代币、区块链、机器人中间件、运动规划器或功能安全系统。它补充——而不是取代——W3C ODRL、W3C Web of Things、IEEE 7012、ROS 2/SROS2、OPC UA、Matter 以及原生安全逻辑。

```text
外部策略/设备描述
            │
            ▼
   KineGrant 边界适配器
            │
            ▼
ActionRequest → PolicyEngine → Capability → ActionGate → Actuator
                                                    │
                                                    ▼
                                           签名收据日志
```

## 参考实现 v1.0.0 中已实现的安全属性

- 默认拒绝、deny-overrides 策略评估；
- 明确的策略签发者信任边界：不可信来源只能拒绝、永远不能放行；
- 可信时钟的请求新鲜度与策略窗口评估；
- Ed25519 签名能力，生命周期 1–300 秒；
- 绑定到主体、目标、动作、目的、请求摘要与策略摘要；
- 原子一次性消费，内存与崩溃持久化 SQLite 防重放存储；
- 明确的受信签发者白名单；
- 签名、哈希链动作收据；
- 严格适配器：拒绝未知授权限制；
- 每个核心对象的严格 JSON Schema；
- 覆盖策略来源、拒绝、篡改、过期、并发/持久化重放、收据信任、Schema 与适配器的测试。

默认重放缓存位于内存中，因此仅用于演示。内置的 `SQLiteReplayStore` 可以在进程重启后保留消费状态，但生产部署仍需要部署特定的原子存储、撤销、硬件密钥、安全时间、独立评审，以及位于受信执行器路径内的门禁。

## 快速开始

需要 Python 3.11 或更高版本。

```bash
git clone https://github.com/zoahdev/kinegrant-protocol.git
cd kinegrant-protocol
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -e '.[test]'
kinegrant-demo
kinegrant-mpt --output machine-permission-test.evidence.json
python -m unittest discover -s tests -v
```

演示会授权一台送货机器人为一次送货打开一扇特定的门：签发 60 秒能力、在动作门禁处一次性消费、输出签名收据。同一份策略会拒绝录像与训练数据采集。

## Machine Permission Test（机器权限测试）

可复现的 [Machine Permission Test](challenge/README.md) 输出严格的 JSON 证据，并带显式的 `PASS` 或 `FAIL`。它覆盖十四个可执行用例：无授权拒绝、一次性授权、重放、请求绑定、签发者与过期检查、并发消费、持久化重放状态、收据信任、物理约束、能力衰减、委派、审批分级、禁止组合。验证结果可以用
[`machine-permission-test-evidence.schema.json`](spec/schemas/machine-permission-test-evidence.schema.json) 校验。

从 [`mpt-v0.2` 发布](https://github.com/zoahdev/kinegrant-protocol/releases/tag/mpt-v0.2) 下载校验和寻址的数据包与参考证据。基于浏览器的[公开验证器](https://kinegrant.com/verify)在本地检查 MPT 证据，并可以验证发布的 [`sample-receipt-v0.1.json`](examples/sample-receipt-v0.1.json) 的 Ed25519 签名、内容寻址 ID 与调用者提供的执行方信任锚。仅凭签名有效并不等于执行方可信，也不等于物理动作真实发生。

独立实现者可以用一条跨平台命令生成带来源绑定的数据包，并且无需信任托管输出即可验证。详见 [REPRODUCING.md](REPRODUCING.md)。

## 低风险 ESP32-C3 硬件证明

非规范性的 [ESP32-C3 证明方案](proof/esp32-c3/README.md) 现已包含默认锁定的 ESP-IDF 固件、密钥安全烧录、严格串口桥、持久化设备重放状态、设备签名确认、无动作预检，以及 GitHub Actions 中的可复现固件构建。

其物理证据状态仍为 **NOT_RUN（未执行）**。本仓库不声称任何 GPIO、舵机或真实机器已经动作，本实验也不是功能安全控制或认证。硬件组装与已发布的验收运行在 [issue #7](https://github.com/zoahdev/kinegrant-protocol/issues/7) 中跟踪。

## 当前 main 分支的功能面

- RFC 8785 JCS 规范化 JSON 是所有摘要与签名背后的确定性编码，符合 ECMAScript 数字语义与 UTF-16 成员排序，独立实现可以产生字节级一致的决策。
- 机器可读的 [`kg.action.*` 动作词表](spec/ACTION-VOCABULARY.md) 覆盖 `observe`、`record`、`touch`、`grasp`、`move`、`open`、`enter`、`retain` 与 `train_on_data`，带风险分级与数据敏感性元数据。`PolicyEngine(require_known_actions=True)` 会对未知动作词 fail-closed（拒绝放行）。
- 策略规则强制执行物理约束：`max_force_newtons`、`max_velocity_mps` 与 `allowed_zones`。声明了物理上限的规则会拒绝省略或超出对应上下文值的请求。
- 作用域 v0.2 能力支持能力衰减（attenuation）：受信签发者可以派生严格更窄的子能力（目标、动作、目的、生命周期、物理上限），动作门禁可以对照父能力验证子能力。参见 [spec/ATTENUATION.md](spec/ATTENUATION.md)。
- 审批分级：策略决策携带 `required_approval_tier`（自动 / 操作员确认 / 人工在场），作用域能力绑定该分级。
- 收据携带 v0.2 能力的授权上下文：审批分级、物理约束、父能力 ID 都记入签名收据，审计时可以看到当时究竟授权了什么。
- 收据可以按附加方式扩展为版本 `1.0`：可选的 `obligation_results` 记录每项义务（例如“必须发出签名回执”）是已完成、待处理还是失败及失败原因；可选的 `failure_reason` 记录动作尝试失败的原因。普通收据保持字节级一致的 `0.1`；Python、JavaScript 与 Go 三个验证器都接受两个版本（参见 `spec/schemas/receipt-1.0.schema.json`）。
- 义务在事后强制执行：`ObligationCompliance` 检查每项能力义务都有可验证的履行证据（`emitActionReceipt` 必须有签名收据，`logAuditEvent` 必须有审计日志承诺），红队套件新增“隐瞒收据”探针；家庭机器人与摄像头同意两个部署案例都输出合规结论。
- 三个可运行演示（`kinegrant-robot-demo`、`kinegrant-bridge-demo`、`kinegrant-ros2-demo`）都会在放行后执行义务合规检查并输出 `obligation_compliance_ok`；性能基准也包含合规检查吞吐。
- 一致性认证套件 L1-L4 新增“义务履行”考核项（共 18/18 项）；已知义务词表可扩展：`emitActionReceipt`（发签名收据）与 `logAuditEvent`（写审计日志）当前均受支持。
- 跨主体委派是 opt-in 且有界：一份能力最多授权一个特定被委托人并在收窄范围内使用，被委托人永远不能再次转委。根能力可以用 fleet 级 `delegate_allowlist` 限制被委托人。
- 离线撤销：`RevocationList` 加 `root_capability_id` 让门禁拒绝已撤销的能力，撤销根即撤销整条委派链。签名、版本化的 `RevocationBundle` 提供可认证的分发。参见 [spec/REVOCATION.md](spec/REVOCATION.md)。
- WoT 风格发现：带认证的 `ThingRegistry` 将 Thing Description 映射到动作与策略指针；未认证发现永远不能携带授权指针。参见 [spec/DISCOVERY.md](spec/DISCOVERY.md)。
- 模拟双栈机器人演示：`kinegrant-robot-demo` 让 ROS 2 风格与 Matter 风格两个技术栈服从同一份策略，并注入重放、不可信签发者、提示注入、物理超限与禁止组合故障。参见 [spec/ROBOT-DEMO.md](spec/ROBOT-DEMO.md)。
- 参考桥接：面向 ROS 2 形态集成的 `Ros2GoalGate` + `Sros2PolicyMapping`，以及覆盖 Matter、OPC UA、ROS 2 适配器并带适配器保真检查的 `kinegrant-bridge-demo`。参见 [spec/ROS2-BRIDGE.md](spec/ROS2-BRIDGE.md)。
- 跨系统动作门禁演示：`kinegrant-ros2-demo` 让 ROS 2 风格技术栈与 MCP 风格智能体工具调用栈（`kinegrant.adapters.mcp`）服从同一份策略、门禁、签名收据日志与序列策略，并注入重放、不可信签发者、目的、物理超限与禁止组合故障（参见 [spec/ROS2-BRIDGE.md](spec/ROS2-BRIDGE.md)）。
- 硬件信任基础：`TrustedClock`、绑定进收据的签名传感器证据承诺、公证收据检查点、硬件密钥签名后端与带测量启动声明的设备证明。参见 [spec/HARDWARE-TRUST.md](spec/HARDWARE-TRUST.md)。
- 隐私基础：轮换临时标识符与带 Merkle 包含证明的选择性披露信封（参见 [spec/PRIVACY.md](spec/PRIVACY.md)、[spec/MERKLE-DISCLOSURE.md](spec/MERKLE-DISCLOSURE.md)），外加可执行的红队套件 `kinegrant-red-team`，覆盖重放、篡改、混淆代理、冲突、降级、时钟、撤销、委派、适配器与序列攻击（参见 [spec/RED-TEAM.md](spec/RED-TEAM.md)）。
- 静态策略分析（`PolicyInvariants`、`explain_decision`）与确定性适配器模糊器（`AdapterFuzzHarness`），外加[治理章程](GOVERNANCE.md)与 [RFC 流程](docs/RFC-PROCESS.md)。
- 一致性等级 L1-L4（`kinegrant-conformance`）与线格式兼容性政策（参见 [CONFORMANCE.md](CONFORMANCE.md) 与 [COMPATIBILITY.md](COMPATIBILITY.md)）。
- 独立 JavaScript 验证器（`kinegrant-js`）：验证 JCS、Ed25519 信封、v0.1 能力与 Python 参考实现签发的收据链（参见 [implementations/README.md](implementations/README.md)）。
- 独立 Go 验证器（`kinegrant-go`，仅标准库）在 CI 中与 Python 参考实现交叉测试，外加首份稳定线格式 RFC 草案（[docs/rfcs/0001-stable-wire-format.md](docs/rfcs/0001-stable-wire-format.md)）与[认证程序草案](CERTIFICATION.md)。
- 可运行的部署示例：家庭机器人送货与摄像头同意场景，包含完整策略 → 能力 → 门禁 → 收据流程（参见 [docs/DEPLOYMENT-CASES.md](docs/DEPLOYMENT-CASES.md)）。
- 稳定线格式：参考实现现在签发并验证 `1.0` 能力（冻结的作用域形状），`capability-1.0` Schema 已发布，KGP-RFC-0001 已 Accepted；JavaScript 与 Go 验证器接受 `0.2`/`1.0` 作用域能力。参考实现版本为 `1.0.0`。标准组织外联材料在 [docs/STANDARDS-OUTREACH.md](docs/STANDARDS-OUTREACH.md)。
- 发布包可以离线验证：`python scripts/verify_release.py <数据包目录>`（校验和、一致性报告与 MPT 证据），`python benchmarks/bench.py` 输出机器可读的策略、签发、门禁、收据与 JCS 吞吐基准。
- 后量子签名：作为 Ed25519 的实验性并行方案，支持 FIPS 204 ML-DSA-65 信封（`alg: "ML-DSA-65"`）。
- 禁止组合：`ActionJournal` + `SequencePolicy` 在危险动作集合全部出现后拒绝后续请求（例如先录像再训练数据），支持可选时间窗与触发模式。
- 规范标识符：主体、目标与策略使用 `urn:kinegrant:<kind>:<namespace>:<local-id>` 语法。参见 [spec/IDENTITY.md](spec/IDENTITY.md)。
- 版本化外部 profile：ODRL 适配器支持 KineGrant 物理动作 profile（`kgp-v0.2`），映射力/速度/区域/审批约束与 `emitActionReceipt` 义务，并提供 `kg:prohibitedCombination` 扩展表达跨动作禁止组合；`rules_to_odrl()` 可以把规则反序列化回 profile 文档形成忠实往返。IEEE 7012 桥接受 profile/version 元数据。未知约束与未知义务仍然 fail-closed。

## 仓库地图

| 路径 | 用途 |
| --- | --- |
| `spec/KGP-001.md` | 规范性核心协议草案 |
| `spec/THREAT-MODEL.md` | 假设、对手与未解决风险 |
| `spec/STANDARD-MAPPING.md` | 与现有标准的边界 |
| `spec/schemas/` | 所有核心对象的严格 Draft 2020-12 Schema |
| `challenge/` | 可复现 Machine Permission Test 说明 |
| `REPRODUCING.md` | 外部复现与证据提交指南 |
| `examples/` | 公开、Schema 有效的签名示例对象 |
| `proof/esp32-c3/` | 非规范性低风险设备边界实验 |
| `src/kinegrant/` | Python 参考实现 |
| `tests/` | 可执行的安全与互操作检查 |
| `CITATION.cff` | 精确到 release/commit 的引用元数据 |
| `codemeta.json` | 机器可读的软件与主题元数据 |
| `SECURITY.md` | 漏洞报告政策 |
| `CONTRIBUTING.md` | 开放贡献与 RFC 流程 |
| `GOVERNANCE.md` | 供应商中立治理章程 |

## 非目标

- 没有加密货币、代币或金融机制；
- 实时动作路径不依赖区块链；
- 不宣称与外部标准正式符合；
- 不宣称签名能证明物理世界的真实情况；
- 不为危险机械实现远程控制。

## 参与贡献

早期最高价值的贡献是对抗性的：指出歧义语义、绕过、重放/撤销失效、隐私泄露与适配器失配。参见 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [SECURITY.md](SECURITY.md)。

Apache-2.0 许可。KineGrant 协议目前是一个独立的实验性开放项目，不是被采纳的行业标准。
