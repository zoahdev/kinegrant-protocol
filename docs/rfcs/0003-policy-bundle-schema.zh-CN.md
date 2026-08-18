# KGP-RFC-0003：策略包 Schema 稳定性（中文版）

> 状态：草案（2026-08-15）——接受投票进行中，窗口至 2026-08-29（issue #127）；临时主席已投 APPROVE。
> 英文原文：`docs/rfcs/0003-policy-bundle-schema.md`。

## 摘要

将 `kinegrant:PolicyBundle` Schema 版本 `0.1` 冻结为稳定的策略分发格式，使车队与独立实现可以依赖字节稳定的策略包、当前版本选择与按注册表确认的车队回执。

## 动机

策略包（v2.0+）已经过 fail-closed 验证、在 JavaScript 与 Go 中交叉实现、带确认地车队级分发，并映射到 ODRL。采用方需要稳定性承诺，才能把策略包当作长期集成面。

## 提案

1. 保持信封格式（`alg` + `kid` + `payload` + `signature`）、payload 字段（`type`、`schema_version`、`bundle_id`、`policy_id`、`issuer`、`version`、`previous_version_digest`、`issued_at`、`not_before`、`not_after`、`policy_digest`、`rules`）与摘要语义不变。
2. 新增 payload 字段为附加式；验证器必须继续拒绝未知义务、约束与权限集（fail-closed）。
3. `PolicyRule` 序列化与 ODRL `kgp-v0.2` 映射为规范性；变更需要新 RFC。
4. 弃用遵循 `docs/STABILITY.md`（公告、保留至少一个小版本、仅通过 RFC 移除）。

## 待决问题

- 接受时 `schema_version` 应升至 `1.0`，还是保持 `0.1` 并提供冻结保证？（编辑建议：升至 `1.0`，并在一个版本内保留 `0.1` 验证。）
- 车队分发报告是否应在同一 RFC 内冻结 Schema？

## 影响

- 参考实现：在 `verify_policy_bundle` 中验证冻结 Schema。
- 独立验证器：JS/Go 保持冻结检查。
- 发布流程：conformance 23/23 与 MPT 22/22 继续作为门槛。