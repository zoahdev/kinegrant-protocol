# KGP-RFC-0004: Independent Implementation Recognition

> Status: draft (2026-08-18)
> Editor: zoahdev
> Related: KGP-RFC-0001, CONFORMANCE.md, implementations/README.md, docs/community/CONTRIBUTION-CREDENTIALS.md

## Motivation

KineGrant 的价值在于“多个互不信任的实现能就同一授权语义达成一致”。目前 Python
参考实现、JavaScript 与 Go 验证器在 CI 中交叉验证，但没有一套正式机制承认第三方的
独立实现。没有承认机制，生态就无法回答一个关键问题：“除了参考实现，还有谁实现了
这个协议，并证明自己与稳定线格式兼容？”

## Scope

本 RFC 定义：

1. 什么构成“独立实现”（independent implementation）；
2. 独立实现如何获得社区承认（recognition）；
3. “Founding Implementer” 贡献凭证的授予条件；
4. 承认后的公开记录形式。

本 RFC 不涉及：任何经济奖励、代币、NFT、股权或可交易凭证；任何对实现的安全性
认证；任何对“生产就绪”的声明。

## Proposal

### 1. 独立实现的定义

满足以下全部条件的实现视为独立：

- 不是参考实现（Python `kinegrant-protocol`）的拷贝或分叉；
- 由不同作者/组织独立编写，核心逻辑不与参考实现共享同一代码库；
- 至少实现稳定线格式 1.0 的核心对象：ActionRequest、Capability、Receipt；
- 通过 Machine Permission Test 证据校验（schema 0.5）或等价的一致性用例。

### 2. 承认流程

1. 实现方提交 PR：在 `implementations/<name>/` 下添加实现清单与互操作证据；
2. 证据要求：能独立生成或验证 Capability/Receipt，并提供与参考实现交叉验证的运行
   记录（可复现命令 + 输出摘要）；
3. 维护者评审后，指导委员会按公开记录确认；
4. 承认结果写入 `implementations/README.md` 的官方清单，并记录在社区决策日志。

### 3. Founding Implementer 凭证

- 授予条件：在承认流程中成为首批（前 12 个）被正式承认的独立实现作者；
- 属性：仅声誉记录，无经济价值，不可转让、不可买卖、不可质押；
- 记录格式遵循 `docs/community/CONTRIBUTION-CREDENTIALS.md`。

### 4. 公开记录

- 每个被承认实现列出：名称、作者/组织、语言/平台、证据链接、承认日期；
- 记录公开在仓库 `implementations/README.md`，任何变更走普通 PR + 维护者评审。

## Security properties

- 承认不等于安全性背书；被承认实现仍须在各自文档中声明未经过独立安全审计（如适用）。
- 证据必须是可复现的（提供命令与固定版本），防止“截图式”虚假承认。
- 交叉验证失败或证据撤回时，承认可被撤销（普通 PR + 委员会确认）。

## Compatibility

- 本 RFC 不改变任何线格式、Schema 或协议语义；
- 只新增过程性文档与公开记录，向后兼容。

## Open questions

- 是否要求被承认实现提供独立安全审计（现草案：不要求，但必须明示无审计）？
- 前 12 个名额是否按承认顺序锁定（现草案：是，只认流程时间，不认购买/预留）？

## Test plan

- 新增一个 CI 检查：`implementations/` 下每个被承认条目必须有对应证据链接且可访问；
- 提供一个示例互操作运行记录模板，要求新实现按模板提交。