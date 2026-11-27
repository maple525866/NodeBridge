# NodeBridge — 个人电脑智能体安全执行网关

> **Cloud AI provides intelligence. Local Agent provides execution. The user owns the permissions.**

NodeBridge 是基于 Go 1.24 与官方 MCP Go SDK 构建的跨平台、本地优先、模型无关的 **Local Agent Daemon**，让云端网页端（Gemini Web / ChatGPT Web / Claude Web）或本地 MCP 客户端在严格目录隔离、分层命令策略、客户端级权限隔离、实时人工审批与一键急停保护下，安全操作本机代码仓库、Git 与终端。

- 总体架构与三阶段路线：[personal-computer-agent-gateway.md](./personal-computer-agent-gateway.md)
- 阶段一实施计划：[docs/stage1-implementation-plan.md](./docs/stage1-implementation-plan.md)
- 阶段二实施计划：[docs/stage2-implementation-plan.md](./docs/stage2-implementation-plan.md)
- 云端网页端远程 MCP 接入指南：[docs/cloud-client-setup.md](./docs/cloud-client-setup.md)

## 核心特性（阶段一 + 阶段二）

- **标准远程 MCP 接入与 OAuth 2.1（阶段二）**：
  - **托管安全隧道与外部反代**：内置编排本机 `cloudflared`（支持 Quick 临时域名与 Named 固定域名、断线指数退避自动重连、一键断开），同时支持 `external` 模式接入 Tailscale Funnel / Caddy / FRP。
  - **内置零依赖单用户 OAuth 2.1 授权服务器**：完整实现 RFC 9728（Protected Resource Metadata）、RFC 8414（AS Metadata）、RFC 7591（DCR）、PKCE S256 与 Refresh Token 轮换重放保护；公网授权页绝不接收 `admin_token`，支持本地控制台一键确认或 5 分钟单次一次性配对码绑定。
  - **客户端级最小权限隔离**：支持为每个远程 AI 客户端独立限定只读/读写权限与工作区子集、随时单点或全量吊销令牌；复合鉴权向下兼容本地静态 Bearer Token。
  - **混合短等待审批与幂等续接**：本地直连保留无限等待；远程请求支持可配置短窗口（默认 45s，附 MCP 进度保活），超时不销毁审批单并转为后台续接执行，新增 `approval.status` 只读工具与请求指纹幂等去重。
- **四层本地安全防线（阶段一）**：
  1. **目录隔离**：`EvalSymlinks` 真实路径防逃逸、Windows UNC/设备路径/ADS/保留名拦截、默认敏感文件（`.env`, `*.key`, `id_rsa*`, `.ssh/**` 等）全局拒绝。
  2. **分层命令策略（L0–L3）**：参数数组优先（`executable + args`），低风险白名单可控放行，未知程序与显式 Shell 强制升级人工审批，`sudo`/`curl | sh` 等高危操作硬拒绝。
  3. **实时审批与内嵌 Web 控制台**：零外部前端依赖，内嵌 SSE 实时审批、OAuth 客户端绑定管理与隧道控制面板，支持彩色 Unified Diff 预览、单次批准与 L1 工作区限时批量授权。
  4. **审计与分层急停（Kill Switch）**：全链路脱敏轮转 JSONL 审计日志；一键暂停、强杀全部进程树（Windows Job Objects / Unix Process Group）、独立一键断开公网隧道与吊销全部远程令牌。
- **11 个 MCP 工具**：
  - 文件系统：`workspace.list`、`workspace.read`（含 `sha256`）、`workspace.search`、`workspace.patch`（Search/Replace + SHA256 乐观锁 + 路径锁）
  - Git：`git.status`、`git.diff`、`git.apply_patch`（路径预检 + `git apply --check`）
  - 异步终端：`terminal.start`、`terminal.poll`（增量输出 + 容量上限截断）、`terminal.cancel`
  - 远程审批续接：`approval.status`（按客户端隔离查询挂起审批单状态与后台执行结果）

## 快速开始

### 1. 编译二进制

```bash
go build -o nodebridge ./cmd/nodebridge
```

### 2. 初始化配置文件（自动生成高熵随机 Token）

```bash
# 仅本地模式
./nodebridge init --config nodebridge.yaml --workspace /path/to/your/project

# 或一键开启 Cloudflare Quick Tunnel + 内置 OAuth 2.1 远程模式
./nodebridge init --config nodebridge.yaml --workspace /path/to/your/project --relay-mode cloudflared_quick
```

### 3. 启动守护进程与自检

```bash
./nodebridge daemon --config nodebridge.yaml
./nodebridge doctor --config nodebridge.yaml
```

启动后默认监听：
- **MCP Streamable HTTP 端点**：`http://127.0.0.1:18765/mcp`（远程模式下在控制台复制公网 `https://<domain>/mcp`）
- **本地 Web 安全审批与远程管控控制台**：`http://127.0.0.1:18766/`（使用 `admin_token` 登录）

### 4. 常用 CLI 管理、配对与应急止损命令

```bash
nodebridge status --config nodebridge.yaml
nodebridge pair --config nodebridge.yaml --readonly --workspaces default
nodebridge tunnel status|connect|disconnect --config nodebridge.yaml
nodebridge clients list|revoke <client_id>|revoke-all --config nodebridge.yaml
nodebridge approve <approval_id> --grant-minutes 15
nodebridge reject <approval_id> --note "不符合预期"
nodebridge tasks --config nodebridge.yaml
nodebridge stop-all --config nodebridge.yaml --disconnect-tunnel
nodebridge resume --config nodebridge.yaml
```

## 测试与跨平台验证

```bash
# 运行全部单元测试与阶段一/阶段二端到端验收测试
go test -race -v ./...

# 跨平台交叉编译验证
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
```
