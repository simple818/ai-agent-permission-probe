# 环境依赖

## 一、运行环境

| 项 | 要求 | 说明 |
| --- | --- | --- |
| 操作系统 | macOS 12+（推荐）；Linux 部分兼容 | GUI 与安全基线检查（SIP/Gatekeeper/FileVault、剪贴板）仅 macOS 生效，其余平台自动降级为 `na` |
| Python | 3.9+ | 仅使用标准库，**无任何第三方依赖** |
| 磁盘 | 报告目录可写即可 | 默认 `./probe-report`，约几十 KB |

## 二、可选系统工具（缺失自动降级，不影响主流程）

| 工具 | 用途 | 缺失时的表现 |
| --- | --- | --- |
| `lsof` | 枚举本地监听端口 | 自动回退到 `netstat -an` |
| `netstat` | 监听端口、默认路由 | 对应检查报 `unknown` |
| `pbpaste`（macOS） | 剪贴板可读性 | 对应检查报 `denied` / 空 |
| `csrutil`（macOS） | SIP 状态 | 对应检查报 `unknown` |
| `spctl`（macOS） | Gatekeeper 状态 | 对应检查报 `unknown` |
| `fdesetup`（macOS） | FileVault 状态 | 对应检查报 `unknown` |
| `ps` | 进程可见性 | 对应检查报 `denied` |
| `sudo` | 提权状态查询（`-n -l`） | 对应检查报 `unknown` |

> 说明：`csrutil` / `spctl` / `fdesetup` 位于 `/usr/bin`、`/usr/sbin`，脚本已用绝对路径调用，不依赖用户 PATH 配置。

## 三、网络环境

- 默认会做 4 个出站 TCP 连接尝试（`1.1.1.1:443`、`8.8.8.8:53`、`github.com:443`、`example.com:443`）与一次 DNS 解析。
- 隔离网络 / 敏感环境请使用 `--no-network` 跳过。

## 四、权限要求

- 以**普通用户**身份运行即可，无需管理员权限、无需 sudo。
- 探测脚本自身不需要任何提权；它只报告当前账号的权限状态。
