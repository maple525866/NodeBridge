# NodeBridge 云端网页端 MCP 远程接入指南（阶段二）

本指南说明如何通过 **Cloudflare Tunnel** 或 **外部 HTTPS 反向代理** 将本地 NodeBridge 守护进程安全暴露为符合 **Streamable HTTP + OAuth 2.1（RFC 9728 / RFC 8414 / RFC 7591 / PKCE S256）** 标准的远程 MCP Server，供 **Gemini Web / ChatGPT Web / Claude Web** 等云端网页端 AI 在用户授权与实时审批下操作本机代码仓库。

---

## 1. 安全前提说明

- **绝不裸露本机端口**：NodeBridge 默认仅监听 `127.0.0.1:18765`，所有公网流量必须经加密隧道或可信 TLS 反代进入。
- **精确 Host 白名单防护**：网关仅放行本地回环与当前受信任公网域名 `Host`，拦截 DNS Rebinding。
- **零长期凭据暴露公网**：公网 `/oauth/authorize` 页面绝不会要求输入 `admin_token`，仅支持“本地控制台一键同意”或“5 分钟单次一次性配对码”。
- **客户端级最小权限**：可为不同云端 AI 客户端单独限定 **只读模式** 或 **工作区子集**，并随时单点吊销或一键断开隧道。

---

## 2. 三种公网 HTTPS 接入方式

### 方式 A：Cloudflare Quick Tunnel（零域名、1 分钟快速体验）

适合首次联调验证（每次重启会分配临时 `https://<random>.trycloudflare.com` 域名）。

1. 安装本机 `cloudflared`：
   - **Windows**：`winget install --id Cloudflare.cloudflared`
   - **macOS**：`brew install cloudflared`
   - **Linux**：参考 Cloudflare 官方包源安装 `cloudflared`。
2. 生成带 Quick Tunnel 配置的 `nodebridge.yaml`：
   ```bash
   nodebridge init --config nodebridge.yaml --workspace /path/to/your/project --relay-mode cloudflared_quick
   ```
3. 启动守护进程：
   ```bash
   nodebridge daemon --config nodebridge.yaml
   ```
4. 打开本地 Web 控制台 `http://127.0.0.1:18766/`，在 **“远程安全隧道与公网 MCP 接入”** 卡片中一键复制自动生成的公网地址：`https://<random>.trycloudflare.com/mcp`。

### 方式 B：Cloudflare Named Tunnel（固定自定义域名，推荐日常使用）

固定域名不会随重启变化，云端 AI 只需完成一次 OAuth 2.1 绑定即可长期稳定使用（自动 Refresh Token 轮换）。

1. 在 Cloudflare Zero Trust → Networks → Tunnels 创建一个 Tunnel，绑定公网域名（例如 `mcp.yourdomain.com`）指向本地 `http://127.0.0.1:18765`，并获取 Tunnel Token。
2. 将 Token 写入环境变量（避免明文写进配置文件）：
   ```powershell
   # Windows PowerShell
   $env:CLOUDFLARE_TUNNEL_TOKEN = "eyJhIjoi..."
   ```
3. 编辑 `nodebridge.yaml`：
   ```yaml
   relay:
     mode: "cloudflared_named"
     public_url: "https://mcp.yourdomain.com"
     tunnel_token: "env:CLOUDFLARE_TUNNEL_TOKEN"
     kill_all_disconnect_tunnel: false
   oauth:
     enabled: true
   ```
4. 启动 `nodebridge daemon --config nodebridge.yaml`。

### 方式 C：外部 HTTPS 反代（Tailscale Funnel / Caddy / Nginx / FRP）

如果您已有公网反代把 `https://mcp.yourdomain.com` 转发到 `http://127.0.0.1:18765`（注意保留原始 `Host` 头与 `X-Forwarded-Proto: https`）：

```yaml
relay:
  mode: "external"
  public_url: "https://mcp.yourdomain.com"
oauth:
  enabled: true
```

### 固定域名模式的开机自启动与守护进程

在 `cloudflared_named` 或 `external` 模式下，直接使用已编译二进制执行 `nodebridge daemon --config nodebridge.yaml` 会自动完成以下工作：
1. 自动捕获 `relay.tunnel_token` 引用的 `env:VAR` 环境变量及当前 `PATH`，写入 `0600` 权限且受内核密钥红线硬保护的 `data/service/service.env`。
2. 按权限自动适配系统守护后端并配置崩溃自动重启：
   - **Windows**：管理员终端自动注册原生 Windows Service（支持开机未登录桌面即启动 + SCM 故障自动重启）；普通终端免提权注册无黑框任务计划程序（登录桌面即启 + 失败自动重启）。
   - **Linux**：自动注册 `systemd`（`Restart=always`，`--scope user` 建议配合 `sudo loginctl enable-linger $USER` 实现未登录开机自启，或使用 `sudo ... --scope system`）。
   - **macOS**：自动注册 `launchd`（`KeepAlive=true`，`--scope user` 为 LaunchAgent，`sudo ... --scope system` 为 LaunchDaemon）。
3. 自动交接给系统守护进程在后台持续运行，日志轮转写入 `data/logs/daemon.log`；临时前台调试可附加 `--foreground`。

---

## 3. 接入前一键自检

启动 Daemon 后，运行内置诊断命令确认隧道、OAuth 2.1 元数据与 401 引导头全部就绪：

```bash
nodebridge doctor --config nodebridge.yaml
```

全部项显示 `[OK]` 即代表已完全符合主流云端网页端 MCP 接入标准。

---

## 4. 在云端网页端完成 OAuth 2.1 绑定

在 **Gemini Web**、**ChatGPT Web** 或 **Claude Web** 的自定义连接器 / MCP 设置页面中：

1. 填入您的远程 MCP Server URL（例如 `https://mcp.yourdomain.com/mcp`）。
2. 客户端会自动发现 `/.well-known/oauth-protected-resource` 与 `/.well-known/oauth-authorization-server`，完成动态客户端注册（RFC 7591）并弹出浏览器授权页面（`/oauth/authorize`）。
3. 选择以下任一零长期凭据方式完成确认：
   - **方式一（推荐）**：切换到您本机打开的 `http://127.0.0.1:18766/` 控制台，在顶部高亮的 **“待确认的云端 OAuth 客户端绑定请求”** 卡片中勾选所需工作区和只读/读写权限，点击 **批准客户端绑定**，公网授权页会自动跳转完成绑定。
   - **方式二（配对码）**：在本机终端运行 `nodebridge pair --config nodebridge.yaml`（可附加 `--readonly` 或 `--workspaces default`）获取 5 分钟单次有效配对码，粘贴到公网授权页提交。

---

## 5. 远程异步审批与应急止损命令

当云端模型发起修改文件（`workspace.patch` / `git.apply_patch`）或运行测试（`terminal.start`）时：
- 若您在 45 秒内于本地控制台点击 **批准**，结果会无缝返回云端对话。
- 若您超过 45 秒才看到审批弹窗，审批单不会丢失，云端模型会收到 `APPROVAL_PENDING`（含 `approval_id`）；您事后批准后，本地后台会自动执行，云端调用 `approval.status` 即可取回完整结果。

常用应急与管理命令：

```bash
# 生成限定只读的 5 分钟一次性配对码
nodebridge pair --config nodebridge.yaml --readonly --workspaces default

# 查看公网隧道状态 / 一键断开公网隧道 / 重新连接
nodebridge tunnel status --config nodebridge.yaml
nodebridge tunnel disconnect --config nodebridge.yaml
nodebridge tunnel connect --config nodebridge.yaml

# 查看已授权云端客户端 / 单点吊销 / 吊销全部远程令牌
nodebridge clients list --config nodebridge.yaml
nodebridge clients revoke --config nodebridge.yaml <client_id>
nodebridge clients revoke-all --config nodebridge.yaml

# 一键急停并联动断开远程隧道
nodebridge stop-all --config nodebridge.yaml --disconnect-tunnel

# 开机自启动守护进程运维（状态 / 日志 / 重启 / 停止 / 卸载）
nodebridge service status --config nodebridge.yaml
nodebridge service logs --config nodebridge.yaml --lines 100
nodebridge service restart --config nodebridge.yaml
nodebridge service stop --config nodebridge.yaml
nodebridge service uninstall --config nodebridge.yaml
```
