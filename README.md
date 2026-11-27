# NodeBridge — 个人电脑智能体安全执行网关

> **Cloud AI provides intelligence. Local Agent provides execution. The user owns the permissions.**

NodeBridge 是基于 Go 1.24 与官方 MCP Go SDK 构建的跨平台、本地优先、模型无关的 **Local Agent Daemon**，让云端或本地 MCP 客户端在严格目录隔离、分层命令策略、人工实时审批与一键急停保护下，安全操作本机代码仓库、Git 与终端。

详细方案与三阶段路线参见 [personal-computer-agent-gateway.md](./personal-computer-agent-gateway.md)，阶段一实施计划参见 [docs/stage1-implementation-plan.md](./docs/stage1-implementation-plan.md)。

## 阶段一核心特性

- **双传输兼容**：常驻 `Streamable HTTP`（默认仅监听 `127.0.0.1` + Origin 防护 + Bearer Token 鉴权，预留 OAuth 2.1 / Relay 扩展点）+ 轻量 `nodebridge stdio` 桥接子命令。
- **四层安全防线**：
  1. **目录隔离**：`EvalSymlinks` 真实路径防逃逸、Windows UNC/设备路径/ADS/保留名拦截、默认敏感文件（`.env`, `*.key`, `id_rsa*`, `.ssh/**` 等）全局拒绝。
  2. **分层命令策略（L0–L3）**：参数数组优先（`executable + args`），低风险白名单可控放行，未知程序与显式 Shell 强制升级人工审批，`sudo`/`curl | sh` 等高危操作硬拒绝。
  3. **无限等待人工审批与内嵌 Web 控制台**：零外部前端依赖，内嵌 SSE 实时审批页面，支持彩色 Unified Diff 预览、单次批准、L1 工作区限时批量授权与拒绝。
  4. **审计与一键急停（Kill Switch）**：全链路脱敏轮转 JSONL 审计日志；一键暂停新任务、强制终止全部运行中进程树（Windows Job Objects / Unix Process Group）并撤销临时授权。
- **10 个 P0 MCP 工具**：
  - 文件系统：`workspace.list`、`workspace.read`（含 `sha256`）、`workspace.search`、`workspace.patch`（Search/Replace + SHA256 乐观锁 + 路径锁）
  - Git：`git.status`、`git.diff`、`git.apply_patch`（路径预检 + `git apply --check`）
  - 异步终端：`terminal.start`、`terminal.poll`（增量输出 + 容量上限截断）、`terminal.cancel`

## 快速开始

### 1. 编译二进制

```bash
go build -o nodebridge ./cmd/nodebridge
```

### 2. 初始化配置文件（自动生成高熵随机 Token）

```bash
./nodebridge init --config nodebridge.yaml --workspace /path/to/your/project
```

### 3. 启动本地守护进程

```bash
./nodebridge daemon --config nodebridge.yaml
```

启动后默认监听：
- **MCP Streamable HTTP 端点**：`http://127.0.0.1:18765/mcp`（需携带 `Authorization: Bearer <mcp_token>`）
- **本地 Web 安全审批控制台**：`http://127.0.0.1:18766/`（使用 `admin_token` 登录）

### 4. 兼容仅支持 stdio 的本地 MCP 客户端

先运行 `nodebridge daemon`，再在客户端配置命令：

```bash
nodebridge stdio --config /path/to/nodebridge.yaml
```

### 5. CLI 管理与急停命令

```bash
nodebridge status --config nodebridge.yaml
nodebridge approve <approval_id> --grant-minutes 15
nodebridge reject <approval_id> --note "不符合预期"
nodebridge tasks --config nodebridge.yaml
nodebridge stop-all --config nodebridge.yaml   # 一键急停并终止全部运行中任务
nodebridge resume --config nodebridge.yaml     # 恢复运行
```

## 测试与跨平台验证

```bash
# 运行全部单元测试与端到端 MCP 客户端验收测试
go test -race -v ./...

# 跨平台交叉编译验证
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
```
