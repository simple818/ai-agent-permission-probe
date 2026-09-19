# 运行教程

## 一、安装

无需安装。项目零第三方依赖，clone 或下载后直接运行：

```bash
git clone <你的仓库地址> ai-agent-permission-probe
cd ai-agent-permission-probe
```

## 二、运行

```bash
python3 scripts/probe_permissions.py
```

默认在 `./probe-report/` 下生成三份报告：`probe_report.json`、`probe_report.md` 与 `probe_report.html`。

## 三、常用示例

```bash
# 1. 完整探测（默认）
python3 scripts/probe_permissions.py

# 2. 指定输出目录
python3 scripts/probe_permissions.py --output-dir /tmp/audit/probe-report

# 3. 仅输出 JSON（供程序消费）
python3 scripts/probe_permissions.py --json

# 4. 仅输出 HTML 可视化报告
python3 scripts/probe_permissions.py --html

# 5. 隔离网络 / 敏感环境：跳过出站检查
python3 scripts/probe_permissions.py --no-network

# 6. 查看报告（macOS；HTML 报告用浏览器打开）
open probe-report/probe_report.html

# 7. 查看可选修复项列表
python3 scripts/apply_fixes.py --list

# 8. 预览某条修复会改什么（不会真的改）
python3 scripts/apply_fixes.py --fix fix-path

# 9. 真正执行某条修复（修改前自动备份）
python3 scripts/apply_fixes.py --fix fix-path --apply
```

## 四、读取报告

1. **先看风险摘要**：`risk_summary` 或 Markdown 的 "Risk summary" 表——高/中风险计数一眼可知。
2. **再看高/中风险发现**：Markdown 的 "High / medium findings" 段，每条含证据与处置建议。
3. **细看权限矩阵**：68 行逐项核对，`status` 列看权限状态，`evidence` 列看证据。
4. **修复中心（HTML 报告底部）**：8 条加固项逐条修复——〔复制命令〕自己粘贴执行，或〔交给 Agent 修复〕由 AI 代跑 `apply_fixes.py`；不需要的跳过即可。
5. **术语解释**：矩阵里检查项后的 `?` 按钮，点击展开"是什么 / 危害 / 怎么处理"。

> 修复是可选的。`apply_fixes.py` 默认只预览，加 `--apply` 才真正改动，且改配置前自动备份。

## 五、状态与风险字段速查

| 字段 | 取值 | 含义 |
| --- | --- | --- |
| `status` | `granted` | 该项权限存在 |
| | `denied` | 该项权限被拒绝 |
| | `partial` | 部分可用（如剪贴板为空） |
| | `unknown` | 无法判定（工具缺失/受限） |
| | `na` | 不适用（如非 macOS） |
| `risk` | `high` / `medium` / `low` / `info` | 风险等级，见 docs/features.md 第五节 |

## 六、把 Skill 接入 Agent 使用

本仓库是标准 Skill 结构，可直接作为 Agent 技能加载：

- **英文版**：`SKILL.md`；
- **中文版**：`SKILL.zh-CN.md`。

将整个仓库目录（或含 `SKILL.md`/`SKILL.zh-CN.md` 与 `scripts/` 的目录）放入 Agent 的技能目录即可。加载后，AI Agent 会在需要审计权限边界时自动按 `SKILL.md` 的流程运行探测并输出报告。

## 七、常见问题

| 问题 | 处理 |
| --- | --- |
| 报告目录创建失败 | 检查 `--output-dir` 父目录是否有写权限 |
| 网络检查全部超时 | 处于代理/防火墙环境，加 `--no-network` |
| `pbpaste` 返回空 | 剪贴板为空或 TCC 拒绝，属于正常现象，不代表脚本异常 |
| 运行报 `command not found` | 确认 `python3` 可用（`python3 --version`） |
