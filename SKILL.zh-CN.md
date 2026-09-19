---
name: ai-agent-permission-probe-zh
description: 只读的 AI Agent 权限边界审计 Skill，用于探测 AI Agent 在当前电脑上实际拥有的权限面。当用户要求探测/审计 AI Agent 对本机的访问能力（文件系统读写执行、shell 执行、网络出网、环境变量、凭据文件存在性、系统信息、GUI/浏览器资源、macOS 安全基线），评估 Agent 沙箱或最小权限边界，或需要产出权限矩阵/安全审计报告用于评审或合规时使用。不修改系统状态，绝不读取任何秘密内容。
---

# AI Agent 权限边界探测（只读审计）

审计以当前用户身份运行的 AI Agent 在本机实际能做什么，并把结果整理成带风险评级与加固建议的权限矩阵。

## 1. 目的

本 Skill 回答一个问题：**AI Agent 在这台电脑上的"爆炸半径"有多大？** 它探测运行环境（文件系统访问、shell 能力、网络出网、凭据可达性、系统信息、GUI/浏览器资源、安全基线），产出结构化、带证据的报告。它是**防御性安全评估工具**：不利用、不提权、不修改任何东西。

## 2. 安全契约（不可协商）

- **严格只读。** 探测脚本只在自身报告目录内写入；唯一例外是一枚用于真实验证可写性的临时文件（立即创建并删除）。
- **不读取秘密内容。** 环境变量**值**、私钥正文、凭据文件**内容**一律不读、不打印、不写入报告；只报告"存在与否"和名称。
- **不提权。** `sudo` 仅以 `-n -l` 方式查询（只列权限、绝不弹密码框、绝不以 root 执行任何东西）。
- **不利用。** 网络检查仅为带短超时的 TCP 连接尝试，不发送任何载荷。
- 探测以**当前用户**身份运行——只报告 Agent 所运行账号的权限，仅此而已。

## 3. 适用 / 不适用

**适用：**
- 用户要求探测/审计 AI Agent 在这台电脑上能访问什么（文件、shell、网络、凭据、GUI）。
- 部署 Agent 前评估沙箱或最小权限边界。
- 产出权限矩阵/安全基线报告，用于评审、合规或 GTV 类贡献文档。
- 回答"如果 Agent 被攻破，能造成多大破坏"这类问题。

**不适用（拒绝）：**
- 用户要求"突破"沙箱、提权、绕过安全控制——超出范围，直接拒绝。
- 用户要求读取真实秘密（密码、密钥、令牌）——拒绝；本审计只报告存在性。

## 4. 工作流程

### 第 1 步 — 检查环境
- 确认 Python 3.9+：`python3 --version`。
- 主目标为 macOS（建议 macOS 12+）；Linux 可运行核心检查，GUI/安全项自动降级。

### 第 2 步 — 运行探测

```bash
python3 scripts/probe_permissions.py --output-dir ./probe-report
```

参数：
- `--output-dir DIR` — 报告输出目录（默认 `./probe-report`，生成 `probe_report.json` / `probe_report.md` / `probe_report.html`）。
- `--json` / `--md` / `--html` — 单选一种输出格式（默认三种全出）。
- `--no-network` — 跳过出站 TCP 与 DNS 检查（隔离网络或敏感网络使用）。

请在允许 Agent 写入的目录中运行；不要把输出指向系统目录。

### 第 3 步 — 读取报告
- `probe_report.json` — 结构化结果：`meta`、`risk_summary`、`checks[]`、`recommendations[]`、`fixes[]`。
- `probe_report.md` — 人类可读的权限矩阵 + 发现 + 加固建议。
- `probe_report.html` — 单文件可视化报告：界面中英文可切换、按风险筛选、关键字搜索、检查项 `?` 可点开术语解释（是什么/危害/怎么处理），底部为修复中心（每条加固项可复制命令或交给 Agent 修复）。

### 第 4 步 — 综合输出
向用户交付：
1. **权限矩阵** — 各权限面及总体状态。
2. **高/中风险发现** — 每条附证据与影响说明。
3. **加固建议** — 按优先级排列、与发现一一对应。
4. **局限说明** — 哪些项未能检查及原因。

完整矩阵在 Markdown 报告里；对话中只讲重点发现与建议，不要逐行念 68 项。

### 第 5 步 — 未经批准不得基于发现动手
探测是诊断性的。不得根据发现擅自 chmod、删除、安装、改配置或变更系统；除非用户明确要求并获得确认。

**可选修复（仅当用户明确要求加固时）：** `scripts/apply_fixes.py` 以非破坏方式执行加固——不加 `--apply` 绝不改动（`--fix <id>` 先预览将执行的变更），修改任何配置文件前自动备份（`<file>.bak.<时间戳>`），需管理员权限的项在普通用户下自动跳过并提示用 sudo。用户没有要求修复时，到第 4 步即可结束。

## 5. 探测维度

| # | 类别 | 检查内容 |
|---|------|----------|
| 1 | 身份 | 用户/uid/gid、所属组、HOME/shell、sudo（`-n -l`，绝不弹窗）、umask |
| 2 | 文件系统 | 用户/系统/项目/敏感目录的读-写-执行权限、其他用户家目录、真实可写性验证、sticky 位识别 |
| 3 | Shell | shell 执行能力、可用工具清单、PATH 卫生（用户可写/当前目录条目）、homebrew |
| 4 | 网络 | 代理环境变量、DNS 解析、出站 TCP 连通性、本地监听端口、默认路由 |
| 5 | 凭据 | 敏感环境变量**存在性**、凭据文件**存在性**（仅路径与条目名） |
| 6 | 系统 | 平台、macOS 版本、CPU/内存、运行时长、磁盘、已装应用、进程可见性 |
| 7 | GUI（macOS） | 剪贴板（`pbpaste`）、浏览器配置文件存在性（Chrome/Safari/Firefox） |
| 8 | 安全基线（macOS） | SIP、Gatekeeper、FileVault |

## 6. 输出结构（JSON）

```json
{
  "meta": { "tool": "...", "version": "...", "generated_at": "...", "host": "...",
            "platform": "...", "user": "...", "python": "...", "network_checks": "..." },
  "risk_summary": { "high": 0, "medium": 0, "low": 0, "info": 0 },
  "checks": [
    { "category": "filesystem", "check": "access::tmp (/tmp)", "status": "granted",
      "evidence": "exists=True R=True W=True X=True", "risk": "low",
      "recommendation": "..." }
  ],
  "recommendations": ["..."],
  "fixes": [
    { "id": "fix-path", "title_zh": "...", "title_en": "...", "detail_zh": "...",
      "detail_en": "...", "commands": ["..."], "needs_sudo": false }
  ]
}
```

`status` ∈ `granted | denied | partial | unknown | na`；`risk` ∈ `high | medium | low | info`。

## 7. 风险分级标准

- **high（高）** — 可写的非 sticky 系统目录、免密 sudo、PATH 含用户可写条目、SIP 关闭。
- **medium（中）** — 敏感目录（`.ssh`、`.aws` 等）可达、可读其他用户家目录、存在监听端口、存在敏感环境变量/凭据文件/浏览器配置、剪贴板可读、FileVault/Gatekeeper 关闭。
- **low（低）** — sticky 全局可写目录（如 `/tmp`）、PATH 干净、无 sudo 权限。
- **info（信息）** — 身份、版本、资源数量等上下文行。

## 8. 加固建议（对应发现）

1. 用专用最小权限账号运行 Agent，绝不授予免密 sudo。
2. 将文件系统访问范围限制在 Agent 自己的工作区。
3. 让秘密远离 Agent：无凭据文件、无敏感环境变量、无浏览器/钥匙串访问。
4. 出站目标白名单化，关闭任务不需要的出口。
5. 保持 SIP、Gatekeeper、FileVault 开启，系统及时打补丁。
6. 设置收紧的 umask；PATH 中不含用户可写或当前目录条目。
7. 复查本地监听服务，关闭不必要端口。
8. 环境变更后重跑本探测，报告纳入安全评审。

## 9. 常见坑与排障

- `os.access` 在 macOS TCC 拒绝时仍可能返回 `True`；脚本的临时文件写入测试更接近真实。两者不一致时如实报告。
- `sudo -n -l` 退出码：`0`=有列出（检查是否含 `NOPASSWD`）、`1`=无权限、其他=需要密码/不可用。`-n` 保证绝不弹窗。
- `pbpaste` 返回空，可能是剪贴板为空**或** TCC 拒绝——"空"不能判定为有权限。
- 公司代理/防火墙会导致 TCP 超时；用 `--no-network` 并注明局限。
- `lsof` 可能受限；脚本自动回退到 `netstat -an`。
- `csrutil`/`spctl`/`fdesetup` 不在普通用户 PATH（位于 `/usr/bin`、`/usr/sbin`）；脚本用绝对路径调用。
- 报告含本机主机名/用户信息——`probe-report/` 不要纳入版本控制（本仓库已 gitignore）。

完整踩坑记录见 [`docs/pitfalls.md`](docs/pitfalls.md)。

## 10. 参考与相关项目

- OWASP — LLM AI Security & Governance Guide（Agent 安全）：https://owasp.org/www-project-ai-security-and-governance-guide/
- OWASP Top 10 for LLM Applications：https://owasp.org/www-project-top-10-for-large-language-model-applications/
- NIST AI 风险管理框架：https://www.nist.gov/itl/ai-risk-management-framework
- MITRE ATLAS（AI 系统对抗威胁全景）：https://atlas.mitre.org/
- Apple 平台安全文档（TCC、SIP）：https://support.apple.com/guide/security/welcome/web

以上仅作为背景与最佳实践对齐参考；本 Skill 为原创实现，与其无代码复用关系。
