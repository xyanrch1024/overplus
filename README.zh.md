# Overplus

<p align="center">
  <a href="README.md">English</a> | <a href="README.zh.md">中文</a>
</p>

轻量高性能 C++17 代理服务器，支持 Trojan、SOCKS5、HTTPS 及自定义 V-Protocol。

> **注意：** 原始仓库 `xyanrch/overplus` 因 2FA 账户问题已无法访问。本仓库（`xyanrch1024/overplus`）为当前维护版本。

## 性能

在 2 核 Xeon Skylake / 2GB 内存 / Ubuntu 24.04 上实测：

| 指标 | 数值 |
|------|------|
| 并发连接数 | **146** |
| 内存占用（146 连接） | **25 MB** |
| 单连接内存 | **~170 KB** |
| CPU 占用 | **< 1%** |
| TLS 重连 | **< 1ms**（会话复用） |
| DNS 解析 | **0ms**（首次查询后缓存） |

### 为什么这么快？

- **SSL 会话复用** — 客户端重连 <1ms，跳过完整的 TLS 握手（证书交换 + 密钥协商）。
- **DNS 缓存** — DNS 结果全局缓存 10 分钟（可配置），重复连接同一域名无需 DNS 解析。
- **64KB 缓冲区** — 更大的读写缓冲区减少系统调用次数，同时保持低内存占用。
- **静态链接** — Boost 和 OpenSSL 静态链接，零运行时依赖，无共享库冲突。

## 对比

| | Overplus | Trojan-Go | V2Ray/Xray |
|---|---|---|---|
| 语言 | C++17 | Go | Go |
| 内存（100 连接） | **~20 MB** | ~50 MB | ~80 MB |
| 二进制大小 | **13 MB** | 15 MB | 20+ MB |
| 静态链接 | **零依赖** | 零依赖 | 零依赖 |
| 协议 | Trojan/SOCKS5/HTTPS/V-Protocol | Trojan | VMess/VLESS |
| Windows GUI 客户端 | **有** | 无 | 有 |
| 配置复杂度 | 简单 JSON | 简单 JSON | 复杂 |

## 快速开始

### 一键安装

```bash
curl -O https://raw.githubusercontent.com/xyanrch1024/overplus/master/install.sh && chmod +x install.sh && sudo ./install.sh
```

> 服务端二进制文件为静态链接，在任何 x86_64 Linux 系统上无需外部依赖。
>
> **推荐：开启 BBR 以获得更好的网络性能。**
> [Ubuntu/CentOS 开启 BBR](https://cloud.tencent.com/developer/article/1946062)

### 下载

- **Linux 服务端**：[overplus-linux-x86_64.zip](https://github.com/xyanrch1024/overplus/releases/latest) — 二进制 + 配置 + 服务文件
- **Windows 客户端**：[overplus-client-windows-x64.zip](https://github.com/xyanrch1024/overplus/releases/latest) — GUI 客户端，含所有依赖

### 客户端

[Release 页面](https://github.com/xyanrch1024/overplus/releases) 提供 Windows GUI 客户端。Overplus 完全支持 Trojan 协议，任何兼容 Trojan 的客户端均可使用。若使用自签名证书，请禁用证书验证。

## 配置

### 服务端

```json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": "443",
    "allowed_passwords": ["your_password"],
    "log_level": "NOTICE",
    "log_dir": "",
    "ssl": {
        "cert": "/path/to/cert.pem",
        "key": "/path/to/key.pem"
    },
    "websocketEnabled": false,
    "dns_cache_ttl": 600,
    "dns_cleanup_interval": 600
}
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `dns_cache_ttl` | DNS 缓存有效期（秒） | 600 |
| `dns_cleanup_interval` | 过期 DNS 条目清理间隔（秒） | 600 |

### 客户端

```json
{
    "run_type": "client",
    "local_addr": "0.0.0.0",
    "local_port": "1080",
    "remote_addr": "YOUR_SERVER_IP",
    "remote_port": "443",
    "password": "YOUR_PASSWORD"
}
```

## 编译

依赖：Boost 和 OpenSSL。默认静态链接，无需共享库。

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

输出二进制 `build/overplus` 完全静态（仅需 glibc）。

### Windows 编译

使用 vcpkg 管理依赖：

```bash
git clone https://github.com/Microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat
.\vcpkg\vcpkg.exe install --triplet x64-windows
cmake -B build -DCMAKE_TOOLCHAIN_FILE="..\vcpkg\scripts\buildsystems\vcpkg.cmake"
cmake --build build
```

## 工作原理

Overplus 使用类 Trojan 协议，请求格式：

```
+----------+---------+-----------+-----------+----------------+
| Password | Command | DST.ADDR  | DST.PORT  | Payload        |
+----------+---------+-----------+-----------+----------------+
| string   | uint8   | string    | string    | string         |
+----------+---------+-----------+-----------+----------------+
```

服务端验证密码后将连接代理到目标。TLS 加密保护整个流程，使流量与正常 HTTPS 无异。

![流程图](asset/flow.png)

## Telegram

https://t.me/+JfKOqh2wH25kMWFl

## 路线图

- [x] Trojan 协议 UDP 代理
- [x] WebSocket 支持
- [x] 全局 DNS 缓存（可配置 TTL）
- [x] SSL 会话复用
- [x] 静态链接（零依赖）
- [ ] Web 管理控制台
- [ ] 连接池
