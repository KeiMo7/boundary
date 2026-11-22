# 验收测试矩阵与回收时延

本文件说明授权加固的验收口径。所有纯逻辑用例均可离线运行（无需 PostgreSQL）：

```bash
# 作用域合成三维矩阵 + 回归
go test ./internal/perms/ -run TestAllowedWithPolicy -count=1 -v

# 快照回收比对（五类撤销信号 + 用户隔离）
go test ./internal/session/ -run 'TestDiffRevocation|TestSelectAffectedSessions' -count=1 -v

# 回收时延蒙特卡洛仿真（P50/P99，固定种子）
go test ./internal/session/ -run TestRevocationLatency -count=1 -v

# 配置 fail-closed
go test ./internal/cmd/config/ -run 'TestParse_AuthorizationBlock|TestNormalizeAuthorization' -count=1 -v

# 目标侧身份派生
go test ./internal/util/template/ -run TestBoundaryPrincipal -count=1 -v
```

## 1. 越权判定三维矩阵

矩阵在 `internal/perms/composition_test.go` 的 `compositionMatrix()` 中固化，三个维度交叉：

| 维度 | 取值 |
|---|---|
| 作用域层级 | global / org / project / org+project 双层 / global+org+project 三层 |
| 角色组合 | 单角色直接绑定、同用户多角色分层、经组成员继承、组+直接混合、u_anon/u_auth 内置主体 |
| 目标归属 × grant scope | global 资源（this）、org 资源（this/children）、project target（this/children/descendants） |

每格对 `union` 与 `intersection` 两种策略分别断言 `Authorized`，并由 `TestAllowedWithPolicy_UnionMatchesLegacy` 保证默认 union 与历史 `ACL.Allowed` 输出逐格一致（"默认保持现有判定"约束的回归锁）。

### 关键判定口径（被测试固定）

- 交集模式：只有"参与了本次授权的角色作用域层"需要全部命中；对资源无适用 grant 的层不参与、不否决。
- 空 grant 集合在两种策略下都拒绝（交集不会因零层而放行）。
- 匿名用户即使有 wildcard grant 也不能 authorize-session（沿用内置限制，与策略无关）。
- descendants grant 不覆盖 global 本身；children 不跨代；父作用域授权不自动覆盖子作用域，除非显式 children/descendants。

## 2. 回收比对验收

`internal/session/authz_snapshot_test.go` 覆盖：

| 用例 | 预期 |
|---|---|
| 无变更 | 不撤销 |
| 删除单条 grant | 命中缺失 entry，撤销 |
| 移出组成员（membership path 改变） | 即使 grant 仍在，路径键不同，撤销 |
| 快照 `GrantsComplete=false` | 保守拒绝，直接撤销 |
| 交集策略下某层不再贡献 grant | 撤销 |
| 信号只涉及 alice | bob 的会话绝不入选（用户隔离） |
| 组信号 | 仅 membership path 经过该组的会话入选 |
| 仅 role 维度信号 | 按 role 匹配，仍需后续 Diff 确认 |

比对键为 `(role_id, grant_scope_id, grant, membership_path)` 四元组；membership path 排序后比较，顺序无关。

## 3. 回收时延分布

`internal/session/revocation_latency_test.go` 用固定种子（20261122）各采 10 万样本：

| 路径 | P50 | P99 | 硬上限 |
|---|---|---|---|
| 快路径（同步 hook + 下次心跳） | ≈ 1.0s | ≈ 2.3s | 2.5s（一个心跳周期） |
| 兜底路径（对账 sweep + 心跳） | ≈ 16.0s | ≈ 30.9s | ≤ 32.5s，且不超过 `max_revocation_signal_lag`=60s |

时序常量在测试中被 pin 住（`heartbeatBase=2s`、`reconcileInterval=30s`、`maxSignalLag=60s`），与 `worker/common.SessionInfoInterval` 和配置默认值一致；任一处改动都会使测试失败，迫使显式重新评估时延预算。

## 4. 待 PG 的集成验收（本环境未运行）

下列用例需 Postgres，建议在仓库标准 controller 集成测试框架中补：

1. 建会话 → 删 grant → 断言会话在 lag 窗口内进入 `canceling`，终止原因为 `authorization revoked`，无关用户会话保持 `active`。
2. 五类 IAM 变更（删角色、删 grant、删 principal-role、set principal、组成员变更）各一条端到端用例。
3. 注入 live grant 查询失败 → 会话被保守撤销且产生 sys event。
4. migration 113 的快照行与 session 行同事务、级联删除验证。
5. 审计链路：以 session_id 查快照取回 role/grant/scope_path，以 correlation_id 在审计事件取回时间与用户身份。
