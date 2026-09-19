# 踩坑总结

本文件记录开发与使用过程中遇到的真实问题与规避方法，供后续维护与二次开发参考。

## 1. `os.access()` 与 TCC/ACL 不一致

- **现象**：`os.access(path, os.W_OK)` 返回 `True`，但实际写入被 macOS TCC（隐私权限）或 ACL 拒绝。
- **原因**：`os.access` 只检查权限位与 ACL 的传统部分，不感知 TCC 的隐私授权（如文件夹访问、剪贴板）。
- **处理**：脚本对关键目录做了**临时文件写入测试**（`tempfile.mkstemp` + 立即删除），以实测结果为准；两者不一致时如实报告 `unknown`/`partial` 并在证据中注明。

## 2. `sudo -n -l` 退出码语义

- **现象**：不同机器返回码不同，容易误判。
- **语义**：
  - `0` 且输出含 `NOPASSWD` → 存在免密 sudo（高危）；
  - `0` 无 `NOPASSWD` → sudo 可用但可能需要密码（中危）；
  - `1` → 当前用户无 sudo 权限（低危）；
  - 其他（如 `255`）→ sudo 不存在或需要密码且无 TTY（判为 unknown）。
- **注意**：必须带 `-n`，否则会弹出密码框挂起；脚本已用 `stdin=DEVNULL` 兜底。

## 3. `pbpaste` 返回空的歧义

- **现象**：`pbpaste` 退出码 0 但输出为空。
- **原因**：可能是剪贴板确实为空，也可能是 TCC 拒绝读取剪贴板。
- **处理**：空输出判为 `partial` 而非 `granted`，并在报告证据中提示歧义，避免误报"可读"。

## 4. 代理 / 防火墙导致网络检查超时

- **现象**：TCP 连接尝试全部 `timeout`，误判为"无出网"。
- **原因**：公司代理、防火墙或 GFW 类环境会静默丢包。
- **处理**：提供 `--no-network` 开关；报告 `network_checks: disabled` 便于留痕。使用时在结论中注明"网络检查已跳过"。

## 5. `lsof` 权限受限

- **现象**：`lsof -nP -iTCP -sTCP:LISTEN` 在某些环境返回非 0 或无输出。
- **原因**：进程可见性受 TCC/权限限制。
- **处理**：自动回退到 `netstat -an` 过滤 `LISTEN`；两者都不可用时报 `unknown`，不硬编结论。

## 6. `/usr/bin`、`/usr/sbin` 不在用户 PATH

- **现象**：`csrutil`、`spctl`、`fdesetup` 直接调用报 `not found`。
- **原因**：普通用户 PATH 通常不含 `/usr/sbin`，部分不含 `/usr/bin`。
- **处理**：脚本用绝对路径 `/usr/bin/csrutil`、`/usr/sbin/spctl`、`/usr/bin/fdesetup` 调用。

## 7. `stat.S_ISVTX`（sticky 位）误报

- **现象**：`/tmp` 等目录"全局可写"被初版误判为 high。
- **原因**：`/tmp` 设计上全局可写，但带 sticky 位（仅属主可删自己的文件），属正常配置。
- **处理**：系统目录可写且带 sticky 位时降为 `low`；无 sticky 位的可写系统目录才判 `high`。

## 8. 报告含本机信息，勿提交公开仓库

- **现象**：报告含主机名、用户名、监听端口、目录路径等本地信息。
- **风险**：直接提交 GitHub 等公开仓库会泄露环境细节。
- **处理**：`.gitignore` 已排除 `probe-report/`；README 与教程均提示勿提交。

## 9. 中文字符编码

- **现象**：Windows 下直接输出中文可能乱码（本项目主要面向 macOS，但二次开发需注意）。
- **处理**：所有报告文件显式以 UTF-8 写入（`encoding="utf-8"`），JSON 使用 `ensure_ascii=False`。

## 10. 以管理员/root 身份运行导致误报

- **现象**：用 root 运行时，`os.access` 对几乎所有路径返回可写，报告失去区分度。
- **原因**：root 绕过权限位检查。
- **处理**：文档明确要求以普通用户运行；脚本在 meta 中记录 `user`，审计时核对运行身份。
