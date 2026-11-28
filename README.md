# NodeBridge — 让 Gemini 网页端安全操作你的本地电脑

> **Cloud AI provides intelligence. Local Agent provides execution. The user owns the permissions.**

NodeBridge 是基于 Go 1.24 与官方 MCP Go SDK 构建的跨平台、本地优先、模型无关的 **Local Agent Daemon**。它通过 **Cloudflare Tunnel（或自有 HTTPS 反代）+ 标准远程 MCP（Streamable HTTP）+ 内置 OAuth 2.1**，让你把本机授权目录的代码仓库、Git 与终端能力安全接入 **Gemini 网页端**（同时兼容 ChatGPT Web、Claude Web 及本地 MCP 客户端），并且所有写入与高风险命令都必须经过本机实时人工审批。

> **当前项目范围说明**  
> 本项目已完成单机本地安全执行与远程云端 MCP 接入闭环（阶段一 + 阶段二），**当前聚焦稳定易用的单机远程接入体验，暂不推进阶段三**（暂不包含多设备中心 Relay 与桌面截图/键鼠自动化）。

---

## 目录

- [一、接入前准备](#一接入前准备)
- [二、手把手教程：从零接入 Gemini 网页端](#二手把手教程从零接入-gemini-网页端)
- [三、在 Gemini 网页端开始使用（示例与审批机制）](#三在-gemini-网页端开始使用示例与审批机制)
- [四、长期稳定使用：固定域名（Named Tunnel）与自有反代](#四长期稳定使用固定域名named-tunnel与自有反代)
- [五、已提供的 19 个 MCP 工具与四层安全防线](#五已提供的-19-个-mcp-工具与四层安全防线)
- [六、常用管理与应急止损命令](#六常用管理与应急止损命令)
- [七、常见排查问题（FAQ）](#七常见排查问题faq)
- [八、本地客户端接入与开发测试](#八本地客户端接入与开发测试)

---

## 一、接入前准备

开始前请确认本机满足以下条件：

1. **Go 1.24+**：用于从源码编译 `nodebridge` 单二进制程序。
2. **公网 HTTPS 通道（二选一）**：
   - **推荐（零域名 1 分钟上手）**：安装 Cloudflare 官方客户端 `cloudflared`，使用 Quick Tunnel 自动获得临时 `https://*.trycloudflare.com` 公网入口。
   - **进阶（固定域名）**：Cloudflare Named Tunnel，或自备 Tailscale Funnel / Caddy / Nginx / FRP HTTPS 反代。
3. **Git（推荐）**：用于启用 `git.status` / `git.diff` / `git.apply_patch` 工具；若未安装，文件与终端工具仍可正常运行。
4. **Gemini 网页端账号支持自定义远程 MCP**：请确认你的 Gemini 网页端（`gemini.google.com`）设置中已开放自定义连接器 / Remote MCP Server 入口（不同账号类型或地区灰度状态可能有所差异）。

---

## 二、手把手教程：从零接入 Gemini 网页端

以下演示最快的 **Cloudflare Quick Tunnel** 方式，无需购买域名，约 3 分钟即可跑通。

### 第 1 步：克隆并编译 NodeBridge

**Windows (PowerShell)：**
```powershell
git clone https://github.com/maple525866/NodeBridge.git
cd NodeBridge
go build -o nodebridge.exe ./cmd/nodebridge
```

**macOS / Linux：**
```bash
git clone https://github.com/maple525866/NodeBridge.git
cd NodeBridge
go build -o nodebridge ./cmd/nodebridge
```

### 第 2 步：安装 `cloudflared`

- **Windows**：`winget install --id Cloudflare.cloudflared`（安装完成后建议新开一个终端窗口确保 `cloudflared` 已进入 `PATH`）
- **macOS**：`brew install cloudflared`
- **Linux**：参考 [Cloudflare 官方下载说明](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) 安装 `cloudflared`

### 第 3 步：初始化配置并授权本地项目目录

将下方路径替换为你希望 Gemini 访问的**本机项目目录**（NodeBridge 仅允许访问此处明确授权的工作区，严禁直接授权整个磁盘或用户主目录）：

**Windows (PowerShell)：**
```powershell
.\nodebridge.exe init --config nodebridge.yaml --workspace "D:\projects\my-app" --relay-mode cloudflared_quick
```

**macOS / Linux：**
```bash
./nodebridge init --config nodebridge.yaml --workspace "/Users/you/projects/my-app" --relay-mode cloudflared_quick
```

该命令会自动生成 `nodebridge.yaml`，内置高熵随机 `mcp_token` 与 `admin_token`，并自动开启 `oauth.enabled: true`。

> **安全提示**：`nodebridge.yaml` 包含本机管理密钥，切勿提交到任何 Git 仓库或分享给他人。如需授权多个项目目录，可在 `nodebridge.yaml` 的 `workspaces` 列表中追加条目（详见 [configs/nodebridge.example.yaml](./configs/nodebridge.example.yaml)）。

### 第 4 步：启动守护进程并执行自检

在当前终端启动常驻守护进程（保持窗口开启）：

```bash
# Windows 使用 .\nodebridge.exe，macOS / Linux 使用 ./nodebridge
./nodebridge daemon --config nodebridge.yaml
```

启动后，NodeBridge 会监听两个**仅限本机回环**的端口，并通过 `cloudflared` 建立加密出站隧道：
- **本地 MCP 端点**：`http://127.0.0.1:18765/mcp`（由隧道安全转发至公网 HTTPS）
- **本地 Web 安全控制台**：`http://127.0.0.1:18766/`（绝不暴露公网）

打开**第二个终端窗口**，等待几秒隧道就绪后执行一键自检：

```bash
./nodebridge doctor --config nodebridge.yaml
```

确认以下检查项全部显示 `[OK]`：
- 配置文件校验 & `cloudflared` 检测
- 本地 MCP 服务 & Admin API
- 远程隧道状态（已获取到 `https://<随机子域>.trycloudflare.com`）
- RFC 9728（`/.well-known/oauth-protected-resource`）与 RFC 8414（`/.well-known/oauth-authorization-server`）元数据
- MCP 端点 `401 Unauthorized` + `WWW-Authenticate` OAuth 引导头

### 第 5 步：登录本地安全控制台并复制公网 MCP URL

1. 打开 `nodebridge.yaml`，复制 `server.admin_token` 的值。
2. 在本机浏览器访问 `http://127.0.0.1:18766/`，粘贴 `admin_token` 登录。
3. 在 **「远程安全隧道与公网 MCP 接入」** 卡片中，复制生成的公网 MCP 地址，格式为：
   ```text
   https://<随机子域>.trycloudflare.com/mcp
   ```

### 第 6 步：在 Gemini 网页端绑定并完成 OAuth 2.1 授权

1. 打开 **Gemini 网页端**（`gemini.google.com`），进入自定义应用 / 连接器（Custom MCP Server）配置界面。
2. 填入第 5 步复制的公网 MCP URL（`https://<domain>/mcp`），保存并点击连接 / 授权。
3. Gemini 会自动完成 OAuth 2.1 发现、动态客户端注册（RFC 7591 DCR）并跳转到 NodeBridge 的公网授权确认页（`/oauth/authorize`）。
4. 出于安全设计，**公网授权页绝不会要求你输入 `admin_token`**，请任选以下两种零凭据方式完成绑定：

   - **方式 A：本地控制台一键批准（推荐）**
     1. 切回本机浏览器中打开的 `http://127.0.0.1:18766/` 控制台。
     2. 顶部会实时弹出高亮卡片 **「待确认的云端 OAuth 客户端绑定请求」**。
     3. 按需勾选权限范围（**建议首次联调先勾选「仅授予只读权限」或仅勾选单个工作区**），点击批准。
     4. 公网授权页会自动收到确认并完成 302 回调，返回 Gemini 网页端即显示已连接。

   - **方式 B：5 分钟一次性配对码**
     1. 在本机控制台「一次性短期配对码（OAuth 绑定）」卡片点击 **生成 5 分钟配对码**，或在本地终端执行：
        ```bash
        ./nodebridge pair --config nodebridge.yaml --readonly --workspaces default
        ```
     2. 将生成的一次性配对码粘贴到公网授权页并提交即可（单次消费、5 分钟过期、带 IP 限流）。

---

## 三、在 Gemini 网页端开始使用（示例与审批机制）

绑定完成后，你就可以在 Gemini 网页端直接用自然语言操作授权工作区。

### 1. 只读探索（L0，授权工作区内自动放行）

直接在 Gemini 对话框提问，例如：
> 请列出我本地 `default` 工作区的目录结构，阅读核心入口代码并查看当前 `git status` 和 `git diff`，总结最近改了什么、有没有潜在 Bug。

Gemini 会自动调用 `workspace.list`、`workspace.read`、`workspace.search`、`git.status`、`git.diff`，无需人工逐次确认，同时 NodeBridge 会自动屏蔽 `.env`、私钥、`.ssh/` 等敏感文件。

### 2. 代码修改与运行测试（L1 / L2，本机实时人工审批）

如果你在绑定时授予了读写权限，可以让 Gemini 修改代码并跑测试：
> 请根据刚才的分析修复这个问题，应用补丁并在本地运行单元测试，把 Diff 和测试结果告诉我。

此时本机会触发安全审批保护：
1. 本地控制台 **「待人工审批工具队列」** 会实时弹出请求，完整展示 **彩色 Unified Diff 预览** 或 **将执行的精确命令与参数数组**。
2. 你可以选择：
   - **单次批准**：仅放行这一次调用；
   - **L1 工作区限时批量授权（如 15/30/60 分钟）**：适合连续改代码跑测试，仅对 L1 生效，L2 高风险命令仍每次单独拦截；
   - **拒绝**：立即拦截并把原因反馈给 Gemini。
3. **远程审批与结果查询**。远程调用默认同步等待 **45 秒**，审批和执行共用这段时间。到期时，Gemini 会收到 `pending: true` 和 `approval_id`。如果还在等待审批，你可以稍后在本地控制台批准；如果已经批准，操作会继续在后台执行。两种情况下都可以让 Gemini 用同一个 `approval_id` 调用只读工具 `approval.status` 查询结果。

### 3. 快捷权限与目录控制（可选：全部权限 & 默认全部目录）

在本地安全控制台（`http://127.0.0.1:18766/`）顶部 **「Agent 快捷权限与目录控制」** 面板中，提供了两个实时生效并自动持久化（保存于 `data/security_mode.json`，重启后该持久化状态优先于 `nodebridge.yaml` 中的默认值并打印启动提示）的快捷勾选开关：

- **全部权限（免审批自由执行）**：勾选后免除所有常规操作的逐次人工审批（包括 `workspace.patch`、`git.apply_patch` 与 `terminal.start`），同时自动放行当前未过期的挂起审批单，让 Agent 流畅连续执行。**一键急停（暂停新任务 / 强杀全部任务）始终保持最高优先级**；通过 OAuth 绑定时显式限制为「只读」的远程客户端仍受只读护栏约束，不会被全局全权限静默突破。
- **默认全部目录（不限单工作区）**：勾选后解除单一工作区根目录隔离，Agent 可在 `workspace.*`、`git.*`（支持可选 `path` 参数）及 `terminal.start`（`cwd`）中直接传入宿主机任意普通目录的绝对路径（支持 Windows 跨盘符），且 `workspace_id` 可留空或直接填目标目录路径。

> **密钥与凭证安全保护红线与输出脱敏**  
> 即使**同时勾选「全部权限」和「默认全部目录」**，文件系统工具（`workspace.*` / `git.*`，含符号链接解析与补丁预检）仍强制执行以下硬保护规则，**永久隐藏且禁止查看、列出、搜索、读取或修改（CRUD）**；同时终端命令层对直接访问敏感路径和 `-EncodedCommand` 执行静态拦截，并配合输出流式实时脱敏兜底（注意：在开启全权限自由执行本机任意脚本/Shell 时，无 OS 沙箱前提下命令静态拦截属纵深防御层，请仅对可信会话开启全权限）：
> - **敏感密钥目录**：`.ssh`、`.gnupg`、`.aws`、`.kube`（目录本身及内部所有文件，列出父目录时自动隐藏）
> - **私钥与密钥库文件**：`id_rsa*`、`id_ed25519*`、`id_ecdsa*`、`id_dsa*`、`authorized_keys`、`*.pem`、`*.key`、`*.ppk`、`*.p12`、`*.pfx`、`*.jks`、`*.keystore`、`*.kdbx`
> - **凭证与网关自身配置**：`.env`、`.env.*`、`.docker/config.json`、`.netrc`、`_netrc`、`.git-credentials`、`.npmrc`、`.pypirc`、`credentials.json`、`nodebridge.yaml`（`*secret*` 默认通过 `global_deny_globs` 拦截）
> - **终端输出流式实时脱敏兜底**：若任意子进程向 `stdout`/`stderr` 输出 OpenSSH / PEM / PGP / PuTTY 私钥块（含分片与截断）或明确格式的云端/平台密钥令牌，返回给 Agent 与落盘摘要前均会以单调递增流式状态机实时替换为 `[REDACTED_PRIVATE_KEY]` / `[REDACTED_SECRET]`。

---

## 四、长期稳定使用：固定域名（Named Tunnel）与自有反代

Quick Tunnel 每次重启 Daemon 都会分配新的临时域名，适合快速体验；如果你打算长期日常使用，推荐配置**固定域名**，这样只需在 Gemini 完成一次 OAuth 2.1 绑定，后续自动通过 Refresh Token 轮换保持登录。

### 方式 1：Cloudflare Named Tunnel（推荐）

1. 在 Cloudflare Zero Trust → Networks → Tunnels 创建一个 Tunnel，将公网域名（如 `mcp.yourdomain.com`）指向 `http://127.0.0.1:18765`，复制 Tunnel Token。
2. 将 Token 放入环境变量（避免明文写入 YAML）：
   ```powershell
   # Windows PowerShell
   $env:CLOUDFLARE_TUNNEL_TOKEN = "eyJhIjoi..."
   ```
   ```bash
   # macOS / Linux
   export CLOUDFLARE_TUNNEL_TOKEN="eyJhIjoi..."
   ```
3. 修改 `nodebridge.yaml`：
   ```yaml
   relay:
     mode: "cloudflared_named"
     public_url: "https://mcp.yourdomain.com"
     tunnel_token: "env:CLOUDFLARE_TUNNEL_TOKEN"
     kill_all_disconnect_tunnel: false
   oauth:
     enabled: true
   ```

### 方式 2：自有 HTTPS 反代（Tailscale Funnel / Caddy / Nginx / FRP）

确保反代将 `https://mcp.yourdomain.com` 转发到 `http://127.0.0.1:18765` 并保留原始 `Host` 头与 `X-Forwarded-Proto: https`：

```yaml
relay:
  mode: "external"
  public_url: "https://mcp.yourdomain.com"
oauth:
  enabled: true
```

### 开机自启动与系统守护进程（主机重启自动拉起）

在固定域名模式（`cloudflared_named` 或 `external`）下，直接运行已编译的二进制启动守护进程即可**自动注册开机自启动并交接给系统守护进程在后台运行**（无需额外安装命令，关掉终端窗口不会中断，崩溃后自动拉起，重启主机自动恢复服务与 `cloudflared` 隧道）：

```powershell
# Windows（以管理员身份运行将注册为原生 Windows Service，支持重启未登录桌面即自启；
# 普通终端运行将免提权注册为无黑框计划任务，登录桌面后静默自启）
.\nodebridge.exe daemon --config nodebridge.yaml
```

```bash
# macOS / Linux（默认注册用户级 LaunchAgent / systemd --user；加 --scope system 配合 sudo 可支持未登录开机自启）
./nodebridge daemon --config nodebridge.yaml
```

关键特性说明：
- **环境变量重启保活**：若配置了 `tunnel_token: "env:CLOUDFLARE_TUNNEL_TOKEN"`，自动交接时会安全捕获该变量与当前 `PATH`（含 `cloudflared` 路径）并写入 `0600` 权限的 `data/service/service.env`（已纳入内核密钥硬保护红线，Agent 永远不可读取），确保主机重启后不丢 Token。
- **日志轮转与前台调试**：后台守护进程日志自动写入 `data/logs/daemon.log`（按大小自动轮转），可通过 `nodebridge service logs --config nodebridge.yaml` 查看；如需临时留在前台终端看实时输出，附加 `--foreground` 即可（不会修改系统自启动项）。
- **控制台与 CLI 一体化管理**：在本地控制台 `http://127.0.0.1:18766/` 的「远程安全隧道与公网 MCP 接入」卡片中可直接查看守护状态，并点击 **「重启服务」** 或 **「取消开机自启并停止守护」**；也可通过 `nodebridge service status / restart / stop / uninstall` 管理（在 `nodebridge.yaml` 中设置 `service.auto_register: false` 可关闭自动交接）。

更多细节可参阅 [docs/cloud-client-setup.md](./docs/cloud-client-setup.md)。

---

## 五、已提供的 19 个 MCP 工具与四层安全防线

### MCP 工具清单

| 分类 | 工具名 | 风险级别 | 说明 |
| :--- | :--- | :---: | :--- |
| **环境自发现** | `system.info` | L0 只读 | 返回宿主机 OS/Arch、默认 Shell、已安装开发工具链、当前权限/目录模式与当前客户端可见工作区（隔离模式下隐藏绝对路径） |
| **文件系统** | `workspace.list` / `workspace.glob` / `workspace.read` / `workspace.search` | L0 只读 | 列目录、按通配符查文件、按行读取（附 `sha256`）与全文搜索（优先本机 `rg`，支持 `.gitignore`、忽略大小写与上下文行）；自动屏蔽敏感密钥目录与二进制 |
| **文件系统** | `workspace.patch` / `workspace.write` / `workspace.mkdir` / `workspace.move` | L1 写入 | Search/Replace 局部补丁、整文件新建/覆写（均含 SHA256 乐观锁与 Diff 预览）、安全建目录（默认支持递归建父目录），以及同一文件系统内的重命名和移动（目标父目录须已存在）。默认审批（支持限时批授），全权限模式免审批 |
| **文件系统** | `workspace.delete` | L1 / L2 | 删除单文件或空目录为 L1（支持批授）；`recursive=true` 删除非空目录自动升级为 L2 强制每次审批；始终禁止删根目录与敏感路径 |
| **Git** | `git.status` / `git.diff` / `git.log` / `git.show` | L0 只读 | 受控 Git 只读状态、工作区/暂存区/任意 ref 范围对比、提交历史与单次提交详情（自动排除敏感路径并脱敏） |
| **Git** | `git.apply_patch` | L1 写入 | 补丁路径安全预检 + `git apply --check` + 审批后应用（支持可选 `path` 指定仓库目录） |
| **异步/短等待终端** | `terminal.start` | L0 / L1 / L2 / L3 | 默认参数数组执行并短等待 10 秒（上限 30 秒，传 `wait_seconds=0` 立即异步返回），短命令一次直出完整输出与退出码；始终拦截访问 SSH/密钥目录命令 |
| **异步/短等待终端** | `terminal.poll` / `terminal.cancel` | L0 控制 | 增量拉取经私钥实时脱敏的输出（支持 `wait_seconds` 长轮询，超长截断时附带末尾 64KB `stdout_tail`/`stderr_tail`），或强杀完整子进程树 |
| **远程续接** | `approval.status` | L0 只读 | 按客户端隔离查询挂起审批单状态与后台续接执行结果 |

### 四层本地安全防线

1. **目录边界与不可绕过的密钥硬保护**：默认通过 `EvalSymlinks` 严格锁定授权工作区防逃逸，Windows 拦截 UNC/设备路径/ADS/保留名；可按需勾选「默认全部目录」控制任意普通目录，但 `.ssh`/`.gnupg`/`.aws`/`.kube`、`id_rsa*`/`id_ed25519*`、`*.pem`/`*.key`/`*.ppk`、`.env`、`nodebridge.yaml` 等密钥与凭据始终处于不可绕过的硬保护红线内，永久禁止查看与 CRUD。
2. **分层命令策略（L0–L3）与全权限模式**：默认 `git status/diff` 等 L0 只读免审，`go test`/`npm test` 等 L1 可按工作区限时批授，未知程序、包安装与显式 `use_shell=true` 强制 L2 逐次人工审批，`sudo`/`shutdown`/`diskpart`/`curl | sh` 等 L3 硬拒绝；可按需在控制台勾选「全部权限」免审批自由执行，但命令层仍硬拒绝直接访问 SSH 私钥与密钥目录。
3. **客户端最小权限隔离**：支持为每个云端 OAuth 客户端独立限定只读/读写模式与允许访问的工作区子集，公网 Host 精确白名单防止 DNS Rebinding，令牌落盘仅存 SHA-256 哈希，Refresh Token 轮换含重放检测。
4. **终端私钥实时脱敏、审计与分层急停（Kill Switch）**：终端 `stdout`/`stderr` 与 JSONL 审计日志均内置私钥块及高敏凭据实时脱敏；支持一键暂停新任务、一键强杀全部子进程树、一键断开公网隧道以及单点/全量吊销远程客户端令牌。

---

## 六、常用管理与应急止损命令

> 注意：CLI 选项参数（如 `--config`、`--readonly`）请放在位置参数（如 `<client_id>`、`<approval_id>`）之前。

```bash
# 运行状态与接入自检
./nodebridge doctor --config nodebridge.yaml
./nodebridge status --config nodebridge.yaml
./nodebridge tasks --config nodebridge.yaml

# 生成限定只读的 5 分钟一次性 OAuth 配对码
./nodebridge pair --config nodebridge.yaml --readonly --workspaces default

# 隧道控制：查看状态 / 重连 / 一键断开公网接入
./nodebridge tunnel status --config nodebridge.yaml
./nodebridge tunnel connect --config nodebridge.yaml
./nodebridge tunnel disconnect --config nodebridge.yaml

# 远程客户端治理：查看列表 / 吊销单个客户端 / 吊销全部远程令牌
./nodebridge clients list --config nodebridge.yaml
./nodebridge clients revoke --config nodebridge.yaml <client_id>
./nodebridge clients revoke-all --config nodebridge.yaml

# 命令行审批（可替代 Web 控制台操作）
./nodebridge approve --config nodebridge.yaml --grant-minutes 15 <approval_id>
./nodebridge reject --config nodebridge.yaml --note "不符合预期" <approval_id>

# 快捷权限与目录运行模式（查看 / 切换全部权限免审批与默认全部目录）
./nodebridge mode --config nodebridge.yaml
./nodebridge mode --config nodebridge.yaml --full-permissions=true --allow-all-dirs=true
./nodebridge mode --config nodebridge.yaml --full-permissions=false --allow-all-dirs=false

# 一键急停（暂停新任务 + 强杀运行中子进程树 + 可选联动断开隧道）与恢复
./nodebridge stop-all --config nodebridge.yaml --disconnect-tunnel
./nodebridge resume --config nodebridge.yaml

# 开机自启动与系统守护进程管理（状态 / 轮转日志 / 重启 / 停止 / 手动安装或卸载）
./nodebridge service status --config nodebridge.yaml
./nodebridge service logs --config nodebridge.yaml --lines 100
./nodebridge service restart --config nodebridge.yaml
./nodebridge service stop --config nodebridge.yaml
./nodebridge service uninstall --config nodebridge.yaml
```

---

## 七、常见排查问题（FAQ）

1. **`nodebridge doctor` 提示未找到 `cloudflared`**  
   确认已安装 `cloudflared` 且在终端可执行 `cloudflared --version`，或在 `nodebridge.yaml` 中显式填写 `relay.cloudflared_bin` 的绝对路径。
2. **公网访问返回 `403 forbidden host`**  
   NodeBridge 启用了精确 Host 白名单防止 DNS Rebinding。使用 `cloudflared_named` 或 `external` 模式时，请确认 `relay.public_url` 与实际公网访问域名完全一致，且反代保留了原始 `Host` 请求头。
3. **重启 Daemon 后 Gemini 网页端连不上了**  
   如果使用的是 `cloudflared_quick` 临时域名，每次重启都会换新地址，需要在 Gemini 网页端更新 URL 并重新绑定；建议按第四节切换到 `cloudflared_named` 固定域名。
4. **想立即切断所有云端访问怎么办？**  
   在本地控制台 `http://127.0.0.1:18766/` 点击 **「一键断开隧道」** 或 **「吊销全部远程令牌」**，或在终端直接执行 `./nodebridge stop-all --config nodebridge.yaml --disconnect-tunnel`。

---

## 八、本地客户端接入与开发测试

### 仅本地模式（CLI / IDE / stdio 客户端）

如果只想在本机使用而不暴露任何公网隧道：

```bash
./nodebridge init --config nodebridge.yaml --workspace /path/to/your/project
./nodebridge daemon --config nodebridge.yaml
```

支持直接以静态 Bearer Token 连接 `http://127.0.0.1:18765/mcp`，或通过轻量 `stdio` 桥接子命令对接仅支持 stdio 的本地 MCP 客户端：

```bash
./nodebridge stdio --config nodebridge.yaml
```

### 运行测试与跨平台构建

```bash
# 运行全部单元测试与阶段一 / 阶段二端到端验收测试
go test -race -v ./...

# 跨平台交叉编译验证
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
```

### 相关设计文档

- 总体架构方案：[personal-computer-agent-gateway.md](./personal-computer-agent-gateway.md)
- 云端网页端接入详细指南：[docs/cloud-client-setup.md](./docs/cloud-client-setup.md)
- 阶段一实施计划：[docs/stage1-implementation-plan.md](./docs/stage1-implementation-plan.md)
- 阶段二实施计划：[docs/stage2-implementation-plan.md](./docs/stage2-implementation-plan.md)
