# 贡献凭证（中文版）

> 英文原文：`docs/community/CONTRIBUTION-CREDENTIALS.md`。

## 目的

贡献凭证是公开、不可转让的记录，用于认可被合并进 KineGrant 的工作。它们表达社区内的声誉与流程权利，**没有任何经济价值**。

## 硬性规则

- 凭证不可购买、出售、交易、质押、委托，也不可作为投资工具。
- 凭证不可预留、预售或在账户间转让。
- Founding Implementer 编号仅在出现可复现的外部实现、被接受的适配器、已确认的 issue 或被采纳的技术提案后授予。它不是股权、股份或财务权利。

## 凭证等级

| 等级 | 授予条件 | 授予方 |
| --- | --- | --- |
| 贡献者 | 在 Apache-2.0 下被合并的任何工作 | 维护者合并 |
| 维护者 | 持续承担评审与 CI 责任 | 指导委员会 |
| 编辑 | RFC 文档所有权 | 指导委员会 |
| 创始实现者 | 早期外部实现或被接受的贡献 | 指导委员会 |

## 记录格式

注册表是公开的 JSON 列表；每条记录：

```json
{
  "id": "kg-cred-0001",
  "level": "contributor",
  "handle": "github-handle",
  "awarded_at": "2026-08-18",
  "reference": "PR-123",
  "transferable": false,
  "economic_value": 0
}
```