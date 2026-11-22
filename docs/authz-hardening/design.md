# 授权判定与权限回收加固设计

## 1. 背景与问题

基线版本 `970c5acca`（HashiCorp Boundary）存在三类授权缺陷，均已在代码中核实：

1. **多层作用域判定口径隐式取并集**。`perms.ACL.Allowed`（`internal/perms/acl.go:219`）把 direct / children / descendants 三类来源的 grant 合并成一个切片，任一 grant 命中即放行。当角色绑定在项目级而目标归属全局（或反向跨级）时，判定口径无法由运维显式选择，"任一满足"由代码隐含决定。
2. **授权是一次性的，回收不传导**。`authorize-session` 时 `auth.Verify`（`internal/daemon/controller/auth/auth.go:176`）实时查 grant 做一次判定；会话行（`internal/session/session.go:74`）只固化 `UserId/AuthTokenId/CorrelationId`，不保存任何角色/grant 快照。此后 `AuthorizeConnection`（`internal/session/service_authorize_connection.go:18`）只校验会话状态、过期时间、连接数，不再做用户级授权。删除角色/grant/principal-role 不触碰任何会话外键，现有 `cancel_session_with_null_fk` trigger 不会触发（只有删用户/target/auth token 才触发）。
3. **目标侧身份不可追溯**。worker 收到的注入凭据 proto 只有 username/password/key/cert，不含 Boundary 用户身份；`LookupSessionResponse` 虽带 `UserId`，worker 从不读取。默认情况下目标主机看到的是凭据库派发的通用账号。

### 约束（来自需求，不可违反）

- 授权模型与代理转发复用现有实现，不另起一套。
- 权限收紧只影响权限被收回的用户，不影响其他用户的正常会话。
- 不新增第三方依赖（仅用标准库与仓库已有依赖）。
- 默认行为与现有判定一致（默认并集语义、默认开快照但不改放行结果）。
- 授权信息缺失时保守拒绝；回收信号传递失败时，会话在短时间内失效并记录。

## 2. 作用域合成语义（显式配置，写死规则）

### 2.1 语义定义

授权引擎支持两种**作用域合成策略**，由配置显式声明，代码不隐含选择：

| 策略 | 含义 | 判定规则 |
|---|---|---|
| `union`（默认） | 并集，等价现行行为 | 资源作用域路径上任一适用 grant 命中即放行 |
| `intersection` | 交集 | 对该资源**实际存在适用 grant 的每一个角色作用域层**，都必须至少有一个 grant 命中才放行 |

交集模式的精确口径（在 `perms` 包内可纯函数判定，无需查库）：

1. 先按现行规则收集适用 grant 集合 `G`（direct + children + descendants，`acl.go:222-228` 的收集逻辑不变）。
2. 按 `RoleScopeId` 把 `G` 分组，得到出现过的角色作用域层集合 `L`。
3. 并集：`∃ g ∈ G, g 命中资源与动作`。
4. 交集：`L` 非空，且 `∀ layer ∈ L, ∃ g ∈ G[layer], g 命中资源与动作`。任一层没有命中 grant 即拒绝。

这样定义的理由：交集的意图是"多层授权必须每层都认可"。对资源完全没有 grant 的层不构成约束（否则任何全局角色存在都会让项目级授权失效，等于拒绝一切）；只有"参与了本次授权的层"才需要全部满足。两种语义的输出在测试矩阵中逐格固定。

### 2.2 作用域继承边界（明确写死）

沿用并文档化引擎既有规则，不改变继承方向：

- grant scope = `this`：仅在 grant 显式指定的作用域内生效。
- grant scope = `children`：仅对角色所在作用域的**直接子**作用域生效，不跨代。
- grant scope = `descendants`：对 global 之下所有后代生效，但**不覆盖 global 本身**（`acl.go:225-227`）。
- **父作用域授权不自动覆盖子作用域**，除非 grant 显式使用 `children`/`descendants`。这条是默认且唯一的继承规则，不提供反向开关，避免多层结构下的判定争议。
- 层级固定为 global → org → project 三级（`internal/types/scope/scope.go:18`），target 只能存在于 project（`scope.AllowedIn`）。

### 2.3 配置形态

在 `controller` HCL 块下新增 `authorization` 子块（解析模式对齐现有 `scheduler`/events 块）：

```hcl
controller {
  authorization {
    scope_composition              = "union"   # union(默认) | intersection，非法值启动报错
    revocation_reconcile_interval = "30s"     # 回收兜底对账周期，默认 30s
    max_revocation_signal_lag      = "60s"     # 信号失败时会话必须失效的上限，默认 60s
  }
}
```

- 缺省/空块：全部取默认值，行为与基线完全一致。
- `scope_composition` 非法值：`config.Parse` 直接返回错误，拒绝启动（fail-closed，不静默回退）。
- 两个 duration 必须 > 0，否则启动报错。

## 3. 会话授权快照

### 3.1 快照内容（逐项可比对，缺一项即可能漏撤销）

新表 `session_authz_snapshot`，在 `CreateSession` 的同一事务内写入（`repository_session.go:75` 的 `DoTx` 内，保证会话与快照原子可见）：

| 字段 | 内容 | 来源 |
|---|---|---|
| `session_id` | 会话 ID（主键，FK→session 级联删除） | 新建会话 |
| `user_id` | 授权用户 | `VerifyResults.UserId` |
| `auth_token_id` | 当时的 token | `VerifyResults.AuthTokenId` |
| `scope_path` | 资源作用域全路径，global→org→project 的 ID 有序数组（JSONB） | `scopes.ScopeInfo` 向上遍历 |
| `composition_policy` | 本次判定使用的合成策略快照 | 配置值 |
| `grants_hash` | 全部 grant tuple 的稳定哈希 | 复用 `perms.GrantTuples.GrantHash`（`grants.go:55`） |
| `entries`（JSONB） | 逐项授权条目数组，见下 | `VerifyResults.grants`（`GrantTuple` 已含 RoleId/RoleScopeId/GrantScopeId/Grant） |
| `grants_complete` | grant 是否完整加载（布尔） | 加载过程出错置 false |
| `last_verified_at` | 最近一次实时对账时间 | 对账 job 维护 |

每个 entry 包含：`role_id`、`role_scope_id`、`role_parent_scope_id`、`grant_scope_id`、`grant`（canonical grant 原文）、`principal_id`、`principal_type`（user/group/managed-group）、`membership_path`（该角色经哪个组到达用户；直接绑定为 user 自身）。

`membership_path` 是回收比对的关键：只存 role+grant 无法区分"用户直接被授予角色"与"经组继承角色"。组被收回成员时，只有快照里 membership_path 经过该组、且无其他路径仍保留该角色的会话才失效。

### 3.2 回收时逐项比对规则（纯逻辑，可单测）

回收信号携带变更的 `(principal_id, role_id, grant_canonical)` 中任意维度。比对函数 `snapshots.DiffRevocation` 对每个在线会话：

1. 重新加载该用户当前的实时 grant 集合 `live`（复用 `iam.GrantsForUser`，不新写 SQL 语义）。
2. 把快照 entries 与 `live` 做规范化集合差：
   - 快照中存在、`live` 中不存在的 entry → **撤销命中**。
   - 比对键为 `(role_id, grant_scope_id, grant, membership_path)` 四元组，任一不同即视为不同 entry。
3. 出现 ≥1 个撤销命中，或 `grants_complete=false`（授权信息缺失/不完整）→ 判定会话应失效。
4. 交集策略下额外校验：实时 grant 按 `RoleScopeId` 分层后，若任一层不再命中 → 失效（与 2.1 的判定口径一致）。
5. 只返回受影响用户的会话 ID；其他用户的会话不进入比对集合，保证不误伤。

### 3.3 降级

- 会话建立时 grant 加载失败：沿用 `performAuthCheck` 的错误返回，拒绝建立（保守拒绝，`auth.go:657-660`）。
- 快照写入失败：与会话同一事务，整体回滚，不会出现"有会话无快照"。
- 回收时实时 grant 查询失败：不放宽。把该用户名下所有 `active/pending` 会话标记 `canceling`，终止原因记为新枚举 `authorization-revoked`，并写 sys event 记录失败原因；依赖 `max_revocation_signal_lag` 兜底。
- 会话无快照行（理论上不应发生）：对账 job 发现后直接置 `canceling` 并告警。

### 3.4 已知边界：组维度回收依赖兜底对账保证正确性

`perms.GrantTuple`（`grants.go:43`）只携带 role 与 grant 字段，**不携带 principal/group 信息**。因此会话建立时写入的快照 entry，其 `membership_path` 只能记录用户直连路径 `[userId]`，无法在快照内还原"该角色具体经哪个组到达用户"。

这带来一条明确的覆盖边界：

- **删角色 / 删 grant / 用户直连角色解除**：同步 hook 的 `SelectAffectedSessions` 能精确命中，走快路径（P99 ≈ 2.3s）。
- **组成员移除 / managed-group 失效**：快路径按 membership path 匹配可能漏选（快照里没有组 id）。这类回收的**正确性由 4.2 的周期对账 job 兜底**——它对每个会话重载该用户的完整实时 grant（`GrantsForUser` 内部已展开组与 managed-group 成员关系），再做四元组集合差，因此组回收最迟在 `max_revocation_signal_lag` 内必然生效。

即：快路径优化延迟，对账 job 保证正确性，两者职责分离。若未来要让组回收也走快路径，需要扩展 `GrantTuple` 携带 principal 维度（改动面更大，列为后续增强，不在本次范围）。纯逻辑测试 `TestSelectAffectedSessions_GroupSignalFollowsMembershipPath` 固定了"当快照含组路径时选择器正确"的行为；当前生产快照仅填用户路径，故该测试刻画的是目标能力而非现行数据。

## 4. 回收传导

### 4.1 复用现有取消通道，不新增推送链路

现有机制已经具备完整的"controller 置位 → worker 拆除"通道，直接复用：

- controller 把会话置 `canceling`：`Repository.CancelSession`（`repository_session.go:498`）。
- worker 每 `2s ± 0.5s` 心跳（`common.SessionInfoInterval=2s`，`routing_info.go:326` jitter），`SessionInfo` 响应的 `NonActiveSessions` 回推（`session_info.go:118-139`），worker `ApplyLocalStatus` 后断开本地连接。
- 之后由 `TerminateCompletedSessions`（1 分钟 ticker）落 `terminated`。

### 4.2 两条触发路径

1. **同步 hook（快路径）**：在 iam 仓储的 `DeleteRole` / `DeleteRoleGrants` / `SetPrincipalRoles` / `DeletePrincipalRoles` / `DeleteGroupMembers` / `SetGroupMembers` 成功提交后，调用一个通过 option 注入的 `RevocationHook` 接口。iam 包不 import session 包（现状 iam 不依赖 session，仅测试反向依赖），接口定义在 iam 包、实现在 controller 装配，避免循环依赖。hook 失败只记日志不阻断 IAM 写操作（回收不能让角色管理 API 失败）。
2. **周期对账 job（兜底路径）**：新 scheduler job，间隔 `revocation_reconcile_interval`（默认 30s）。扫描所有未结束会话，按 3.2 重新比对。hook 丢失（controller 重启、信号失败）时，会话最迟在 `max_revocation_signal_lag`（默认 60s）内被兜底 job 失效。

### 4.3 回收时延预算与 P50/P99

下列数值由固定种子的蒙特卡洛仿真测试（`internal/session/revocation_latency_test.go`，10 万样本）复算并断言，时序常量被改动时测试会失败，防止口径漂移：

- 快路径时延 = hook 处理时间（DB 单次更新，毫秒级）+ 等待下一次心跳。心跳基础间隔 2s、抖动 ±0.5s，相位均匀随机；周期本身在 1.5s–2.5s 随机，把尾部抬高。实测：**P50 ≈ 1.0s，P99 ≈ 2.3s**，硬上限 2.5s。
- 兜底路径时延 = 对账周期内相位（0–30s）+ 心跳等待：实测 **P50 ≈ 16.0s，P99 ≈ 30.9s**，最差样本 ≤ 32.5s，硬上限不超过 `max_revocation_signal_lag`=60s。

## 5. 目标侧身份透传

### 5.1 方案选择：短期目标侧凭据为主，审计关联为兜底

二选一的结论：**默认且推荐 ephemeral-credential（短期凭据）模式**，因为它让目标侧看到的身份天然可追溯且随会话结束失效；审计关联模式作为无法签发动态凭据时的兜底保留。

- **ephemeral 模式（首选）**：复用现有 Vault 动态凭据链路（不新增依赖）。现状 `credential.WithTemplateData(authResults.UserData)`（`target_service.go:1041`）已把用户属性传入 Vault 模板，但不含会话标识。扩展模板数据，追加 `Session.Id` 与一个派生身份 `BoundaryPrincipal = "bnd_" + userId + "_" + sessionId 短哈希`。运维在 credential library 的 username 模板引用后，目标侧账号即每会话唯一、可反解到用户与会话，且 TTL 绑定会话生命周期，会话结束由 Vault 回收。
- **audit 模式（兜底）**：静态凭据/无 Vault 场景。在审计事件中补一条 `session-identity` observation，固定携带 `session_id/user_id/auth_account_id/target_id/credential_id/worker_id`，与现有 correlation-id 体系（`interceptor.go`）打通，事后可按会话 ID 关联"谁在什么时候拿到了什么权限"。

### 5.2 审计可关联性

现状已具备基础：Auth 审计事件含 `GrantsInfo`（每条带 role_id/scope_id/grant 原文，`event/event.go:31-39`），Response 事件含 session id，二者共享 correlation id；session 行持久化 `CorrelationId`（`session.go:144`）。快照表再固化 `session_id → grants_hash/entries`，形成三段可互查链路：

```
审计事件(correlation_id) ↔ session 行(correlation_id) ↔ 快照(session_id → role/grant/scope_path)
```

验收查询"谁在什么时候拿到了什么权限"：以 session_id 查快照即得全部授权条目与作用域路径，以 correlation_id 查审计即得时间戳与用户身份。

## 6. 实现清单

| # | 包/文件 | 内容 | 可测性 | 状态 |
|---|---|---|---|---|
| 1 | `internal/perms/composition.go` + `_test.go` | `CompositionPolicy` 枚举、`ACL.AllowedWithPolicy`、交集分层判定 | 纯逻辑，可离线单测 | ✅ 已实现，离线测试通过 |
| 2 | `internal/cmd/config`（`Authorization` 块、`authorization_config_test.go`） | HCL 块、默认值、非法值 fail-closed 校验 | 纯解析，可离线单测 | ✅ 已实现，离线测试通过 |
| 3 | `internal/session/authz_snapshot*.go` + migration `113/01_session_authz_snapshot.up.sql` | 快照领域类型、表、仓储、`DiffRevocation` 纯函数 | 纯函数离线；仓储需 PG | ✅ 已实现，纯函数测试通过；仓储集成测试待 PG |
| 4 | `internal/iam/revocation_hook.go` + 5 个变更点 | hook 接口、option 注入、提交后调用 | 接口/路由纯逻辑可测 | ✅ 已实现，离线测试通过 |
| 5 | `internal/session/job_revocation_reconcile.go`、`jobs.go` | 兜底对账 job，注册进 `session.RegisterJobs` | 调度逻辑可测，DB 部分需 PG | ✅ 已实现，构造与时延仿真测试通过 |
| 6 | `internal/daemon/controller/auth`、`handlers/targets`、`revocation_hook_adapter.go`、`live_grant_resolver.go` | 策略透传、快照写入、模板数据扩展、全局策略注册 | 辅助函数离线可测，端到端需 PG | ✅ 已实现，helper 测试通过 |
| 7 | `internal/session/term_reason.go` | 新终止原因 `authorization revoked` | 纯枚举 | ✅ 已实现 |
| 8 | `internal/util/template/principal.go` + `_test.go` | 每会话可追溯目标侧身份派生 | 纯逻辑，可离线单测 | ✅ 已实现，离线测试通过 |
| 9 | 测试矩阵 + 时延仿真（`composition_test.go`、`revocation_latency_test.go`） | 见第 7 节 | 矩阵/仿真离线可跑 | ✅ 已实现 |

### 待 PostgreSQL 验证的集成面（本环境无 PG，代码已通过编译与 vet）

- migration 113 在真实 Postgres 上的建表与 trigger 行为。
- `CreateSession` 同事务写快照、`ListOpenAuthzSnapshots`/`MarkAuthzSnapshotVerified`/`CancelSessionForRevocation` 的 SQL。
- 五类 IAM 变更端到端触发 hook → 会话 canceling → worker 心跳拆除。
- 仓库现有 DB 测试框架（`internal/db/sqltest`、controller 集成测试）下的回归。

## 7. 验收标准

### 7.1 越权判定测试矩阵（三维交叉，固定为表驱动用例）

三个维度：

- **作用域层级**：global / org / project / org+project 双层 / global+org+project 三层。
- **角色组合**：单角色直接绑定 / 单角色经组继承 / 同用户多角色（不同层）/ 组+直接混合 / 含 u_anon 或 u_auth 内置角色。
- **目标归属**：global 资源 / org 内资源 / project 内 target（含 children、descendants、this 三种 grant scope）。

每格分别在 `union` 与 `intersection` 两种策略下断言 `Authorized` 布尔值，并固定一组"基线默认策略（union）与现行 `ACL.Allowed` 输出完全一致"的回归用例。矩阵在 `perms` 包内零外部依赖执行。

### 7.2 回收失效验收

- 单元级：`DiffRevocation` 覆盖删角色、删单条 grant、解除用户-角色、移出组成员、managed-group 失效五类信号，断言命中会话 ID 集合与未误伤集合。
- 时延分布：蒙特卡洛仿真输出快路径与兜底路径的 P50/P99，数值断言第 4.3 节预算。
- 集成级（需 PG，沿用仓库 sqltest/controller test 框架）：建立会话→收权→断言会话在 `max_revocation_signal_lag` 内进入 `canceling`，且另一无关用户会话保持 `active`。
- 降级：注入 grant 查询失败，断言会话被保守失效且产生审计/sys 记录。

### 7.3 身份与审计验收

- ephemeral 模式：渲染后的目标侧 username 含可反解的 user/session 标识，且会话终止后凭据进入回收流程。
- 按 session_id 能从快照表取回完整 role/grant/scope_path；按 correlation_id 能在审计事件中取回同一授权的时间与用户。
