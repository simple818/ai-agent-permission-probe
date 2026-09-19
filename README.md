# ai-agent-permission-probe

**AI Agent 权限边界探测（只读审计）** —— 一个 Skill 与配套脚本：探测 AI Agent 在当前电脑上实际拥有的权限，输出带证据的权限矩阵与加固建议。

本仓库是信息安全开源持续贡献项目的一个迭代，聚焦 **AI Agent 安全**方向，采用「一个项目、中英双语文档」结构（`SKILL.md` 英文可加载版 + `SKILL.zh-CN.md` 中文对照版），以只读、合规、可溯源的方式回答：**Agent 在这台机器上的爆炸半径有多大？**

## 功能特性

- **只读探测**：不修改系统状态、不提权、不发送网络载荷，探测脚本自身的写入仅限报告目录与一枚即建即删的临时文件。
- **8 大权限面**：身份与 sudo、文件系统读写执行、shell 与工具、网络出网、凭据可达性（仅存在性）、系统信息、GUI/浏览器资源、macOS 安全基线（SIP / Gatekeeper / FileVault）。
- **三格式报告**：JSON（结构化，便于程序消费）+ Markdown（权限矩阵，便于人读）+ HTML（可视化审计报告，中英切换、可筛选搜索）。
- **真实可写性验证**：用临时文件测试而非仅看权限位，规避 TCC/ACL 下的误判。
- **风险分级与加固建议**：每条发现带 high / medium / low / info 评级与对应处置建议。
- **可选修复中心**：HTML 报告底部 8 条加固项逐条给出修复命令——〔复制命令〕手动执行，或〔交给 Agent 修复〕自动处理；修复脚本默认只预览，`--apply` 才改动，修改前自动备份。
- **术语点击解释**：矩阵检查项后的 `?` 展开"是什么 / 危害 / 加固"。
- **零第三方依赖**：仅用 Python 标准库，Python 3.9+ 即可运行。

## 目录结构

```
ai-agent-permission-probe/
├── SKILL.md                  # Skill 英文版
├── SKILL.zh-CN.md            # Skill 中文版
├── scripts/
│   ├── probe_permissions.py  # 只读探测脚本（macOS 优先，跨平台降级）
│   └── apply_fixes.py        # 可选修复脚本（默认预览，--apply 执行，改前备份）
├── docs/
│   ├── features.md           # 功能说明
│   ├── requirements.md       # 环境依赖
│   ├── tutorial.md           # 运行教程
│   ├── pitfalls.md           # 踩坑总结
│   └── disclaimer.md         # 风险声明与免责
├── README.md                 # 本文件（中文）
├── README.en.md              # 英文版 README
├── LICENSE                   # MIT 协议
└── .gitignore
```

## 快速开始

```bash
# 1. 进入项目目录
cd ai-agent-permission-probe

# 2. 直接运行（无需安装任何依赖）
python3 scripts/probe_permissions.py --output-dir ./probe-report

# 3. 查看报告
open probe-report/probe_report.md
```

常用参数：

| 参数 | 说明 |
| --- | --- |
| `--output-dir DIR` | 报告输出目录（默认 `./probe-report`） |
| `--json` / `--md` / `--html` | 仅输出 JSON / Markdown / HTML（默认三者全出） |
| `--no-network` | 跳过出站 TCP 与 DNS 检查（隔离网络使用） |

## 输出说明

- `probe_report.json`：`meta`（环境与时间戳）、`risk_summary`（风险计数）、`checks[]`（68 项检查，含状态/证据/风险/建议）、`recommendations[]`（加固建议）、`fixes[]`（8 条可选修复项）。
- `probe_report.md`：风险摘要表 + 权限矩阵表 + 高/中风险发现 + 加固建议。
- `probe_report.html`：可视化审计报告，界面中英文可切换，支持按风险等级筛选与关键字搜索；检查项 `?` 可点开术语解释；底部为可选的修复中心（复制命令 / 交给 Agent 修复）。
- **每次运行产出一份全新报告（含 UTC 时间戳）**，可按日期归档多份，便于整改前后对比与审计留痕。
- 报告含本机主机名与用户名等本地信息，**请勿**提交到公开仓库（`.gitignore` 已排除 `probe-report/`）。

## 合规与定位

- 本项目仅做**安全防御、审计、检测**方向，无任何攻击、爆破、漏洞利用内容。
- 探测为只读审计：不读秘密内容、不提权、不修改系统；输出仅用于权限评估与加固。
- 使用前请阅读 [docs/disclaimer.md](docs/disclaimer.md)。

## 参考

背景对齐：OWASP AI Security & Governance Guide、OWASP Top 10 for LLM Applications、NIST AI RMF、MITRE ATLAS、Apple Platform Security。本实现为原创，与上述资料无代码复用。

## 开源协议

[MIT](LICENSE) © 2026