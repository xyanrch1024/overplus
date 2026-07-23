# Overplus 项目状态

## 基本信息

- **项目**: Overplus v1.1.0
- **协议**: SOCKS5 / HTTPS / Trojan / V-Protocol（自定义）
- **架构**: Client（本地代理） → TLS/WebSocket → Server（远程代理） → 目标网站
- **技术栈**: C++17, Boost.Asio, OpenSSL, CMake
- **平台**: Linux + Windows
- **GitHub**: https://github.com/xyanrch1024/overplus.git

## 部署架构

```
客户端 (Windows/WSL)              服务器 (38.226.195.218, Ubuntu 24.04)
┌──────────────┐                 ┌──────────────────────────┐
│ overplus_client│── TLS:443 ──→ │ overplus (端口 443→10037) │
└──────────────┘                 └──────────────────────────┘
```

- SSH 端口: 10036 → 22
- Overplus 端口: 10037 → 443
- 证书 CN: `server_fanhtMEC1kNXjtEM`，有效期至 2036
- 静态链接: Boost + OpenSSL 零外部依赖

## 开发历程

### Bug 修复

| 改动 | 文件 | 说明 |
|------|------|------|
| 编码修复 | `Shared/Encoding.h` | UTF-8 BOM 日志文件，ToUTF8() 转换 |
| 客户端日志修复 | `Client/Session.cpp` | 逗号→`<<` 语法错误，缺少 `return`，命名修正 |
| HTTP 模块恢复 | `Protocol/http/http.h/cpp` | 补回缺失的 HTTP 协议解析 |
| WebSocket destroy | `Server/TlsSession.cpp` | WebSocket 会话关闭逻辑修复 |
| UDPPacket 解析 | `Server/Session.cpp` | UDP 偏移索引修复 |
| 密码哈希匹配 | `Server/Session.cpp:40-41` | Trojan 协议密码明文 vs SHA224 哈希 |

### 性能优化

| 改动 | 文件 | 说明 |
|------|------|------|
| TCP_NODELAY | `Server/Service.cpp:98`, `Server/Session.cpp:307` | 减少 Nagle 延迟 |
| 缓冲区调整 | `Session.h:72` | 64KB，平衡吞吐与内存 |
| TCP DNS 缓存 | `Server/Session.cpp` | TTL 300s，避免重复解析 |
| UDP DNS 缓存 | `Server/Session.cpp` | TTL 300s |
| SSL Session 缓存 | `Server/Service.cpp` | `SSL_SESS_CACHE_SERVER` 复用 TLS 会话 |
| `.append()` 优化 | `Server/Session.cpp` | 减少字符串拷贝 |

### 日志优化

| 改动 | 文件 | 说明 |
|------|------|------|
| UTF-8 BOM | `Shared/Encoding.h` | Windows 编辑器兼容 |
| 按天轮转 + 自动清理 | `Shared/LogFile.cpp` | `.YYYYMMDD.log`，保留 30 天 |
| 跨平台兼容 | `Shared/LogFile.cpp` | `std::filesystem` 替代 `dirent.h` |
| 热路径日志降级 | `Session.cpp`, `TlsSession.cpp` | 断连/重置日志从 ERROR → DEBUG |
| 服务端日志全面修正 | `Server/` 多个文件 | 语法、命名、方向标签统一 |

### 工程化

| 改动 | 说明 |
|------|------|
| 静态链接 | Boost + OpenSSL 静态编译，零依赖 |
| install.sh | v1.1.0 自动安装脚本 |
| GitHub Release | 自动打包 `overplus-linux-x86_64` |
| systemd service | 开机自启，自动重启 |

## 服务器环境

- **OS**: Ubuntu 24.04.3 LTS, 2核 Intel Xeon Skylake, 2GB RAM
- **Nginx**: 端口 8080（备用），静态文件服务
- **Trojan-Go**: 已卸载（此前用于对比测试）

## 测试记录

### Trojan-Go 对比测试（已停止）

曾部署 Trojan-Go v0.10.6 进行性能对比：
- Overplus Trojan 模式: 密码明文传输，端口 10037
- Trojan-Go: 密码 SHA224 哈希，端口 10090
- Trojan-Go 已卸载，不再维护

### 优化后性能反馈

部署 TCP DNS 缓存 + SSL Session 缓存后，客户端体感延迟明显降低。

## 当前状态

- 服务端 v1.1.0 运行稳定
- 5.6MB 内存占用，CPU 几乎为零
- 27 个活跃 TCP 连接
- 无 ERROR 日志（热路径日志已降级为 DEBUG）
