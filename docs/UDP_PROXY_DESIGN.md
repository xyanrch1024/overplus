# Overplus UDP 代理实现方案

## 1. 概述

为 Overplus 客户端/服务器添加 UDP 代理支持，采用 **DTLS 独立连接**方案，支持 DNS 查询、游戏、QUIC (HTTP/3) 等全部 UDP 流量场景。

## 2. 架构设计

```
                        Overplus 系统边界
                    ┌──────────────────────────┐
                    │                          │
  应用 ──UDP──▶     │  Client                  │
  (浏览器/游戏)     │  ┌──────────────────┐    │
                    │  │ SOCKS5 UDP 中继   │    │
                    │  │ (本地 UDP 监听)   │    │
                    │  └────────┬─────────┘    │
                    │           │               │
                    │  ┌────────▼─────────┐    │
                    │  │ 自定义帧封装       │    │
                    │  └────────┬─────────┘    │
                    │           │               │
                    │  ┌────────▼─────────┐    │
                    │  │ DTLS 客户端       │    │
                    │  └────────┬─────────┘    │
                    │           │ DTLS over UDP │
                    │           │ (独立端口)     │
                    └───────────┼──────────────┘
                                │
                                ▼
                    ┌──────────────────────────┐
                    │  Server                  │
                    │  ┌──────────────────┐    │
                    │  │ DTLS 监听器       │    │  ◀── 独立 UDP 端口 (如 8443)
                    │  └────────┬─────────┘    │
                    │           │               │
                    │  ┌────────▼─────────┐    │
                    │  │ 密码认证          │    │
                    │  └────────┬─────────┘    │
                    │           │               │
                    │  ┌────────▼─────────┐    │
                    │  │ 帧解析 + DNS 缓存 │    │
                    │  └────────┬─────────┘    │
                    │           │               │
                    │  ┌────────▼─────────┐    │
                    │  │ UDP 转发到目标    │    │
                    │  └──────────────────┘    │
                    └──────────────────────────┘
                                │
                                ▼ UDP
                         目标服务器
```

## 3. 自定义 UDP 帧格式

### 3.1 帧结构

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Magic (0x0D0A)        |        Total Length           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   ATYP        |  Address (variable)         |    Port         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload (variable)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 字段说明

| 字段 | 长度 | 说明 |
|------|------|------|
| Magic | 2 bytes | 固定值 `0x0D0A`，标识 UDP 帧 |
| Total Length | 2 bytes | 整帧长度（含 Magic），大端序 |
| ATYP | 1 byte | 地址类型：`0x01`=IPv4, `0x03`=域名, `0x06`=IPv6 |
| Address | 变长 | IPv4=4B, 域名=1B长度+N字节, IPv6=16B |
| Port | 2 bytes | 目标端口，大端序 |
| Payload | 变长 | 实际 UDP 数据 |

### 3.3 地址编码（复用 SOCKS5 格式）

```
IPv4:   [0x01][4 bytes IP][2 bytes port]           = 7 bytes
域名:   [0x03][1 byte len][N bytes domain][2 bytes port] = 4+N bytes
IPv6:   [0x06][16 bytes IP][2 bytes port]          = 19 bytes
```

### 3.4 与 Trojan UDP 帧的区别

| | Trojan UDP 帧 | Overplus UDP 帧 |
|---|---|---|
| 格式 | SOCKS5Address + Length(2) + "\r\n" + Payload | Magic(2) + TotalLength(2) + Address + Payload |
| 分隔符 | 需要 `\r\n` 分隔 | 无需分隔符，靠 Length 定界 |
| 解析复杂度 | 需要搜索 `\r\n` | 直接读取 Length |
| 效率 | 略低 | 更高 |

## 4. Server 端实现

### 4.1 DTLS 监听器

```cpp
// Server/DtlsListener.h
class DtlsListener : private boost::noncopyable {
public:
    DtlsListener(boost::asio::io_context& io_ctx,
                 const std::string& listen_addr,
                 uint16_t listen_port,
                 boost::asio::ssl::context& ssl_ctx,
                 const std::string& password);

    void start();
    void stop();

private:
    void do_receive();
    void handle_dtls_handshake(udp::endpoint sender_ep,
                               std::shared_ptr<ssl::stream<udp::socket>> dtls_stream);
    void handle_auth(std::shared_ptr<Session<DTLSSocket>> session,
                     const std::string& password);

    udp::socket socket_;
    ssl::context& ssl_ctx_;
    std::string password_;
    std::array<char, 65535> recv_buf_;
};
```

### 4.2 DTLS Session 模板特化

```cpp
// 使用 DTLSSocket 作为上游传输
using DTLSSocket = boost::asio::ssl::stream<boost::asio::ip::udp::socket>;

// 特化 upstream_udp_write
template<>
void Session<DTLSSocket>::upstream_udp_write(int direction, const std::string& packet) {
    // 通过 DTLS 流发送 UDP 帧回客户端
    upstream_socket.async_write_some(
        boost::asio::buffer(packet),
        [this, self = shared_from_this()](boost::system::error_code ec, std::size_t) {
            if (ec) { destroy(); return; }
            udp_async_bidirectional_read(direction);
        });
}
```

### 4.3 认证流程

```
1. 收到 UDP 数据报 (DTLS ClientHello)
2. DTLS 握手（使用证书）
3. 握手完成后，第一条应用数据格式：
   [密码长度(1B)][密码][UDP帧...]
4. Server 验证密码
5. 密码正确 → 开始转发 UDP 帧
6. 密码错误 → 关闭连接
```

### 4.4 关键代码注入点

| 文件 | 改动 |
|------|------|
| `Server/Service.h` | 添加 `DtlsListener` 成员 |
| `Server/Service.cpp` | 在 `run()` 中启动 DTLS 监听 |
| `Server/Session.h` | 添加 `DTLSSocket` 模板特化声明 |
| `Server/Session.cpp` | 实现 `upstream_udp_write` 特化 |
| `Server/DtlsListener.h` | 新文件：DTLS 监听器 |
| `Server/DtlsListener.cpp` | 新文件：DTLS 监听器实现 |

## 5. Client 端实现

### 5.1 SOCKS5 UDP 中继

```cpp
// Client/UdpRelay.h
class UdpRelay : private boost::noncopyable {
public:
    UdpRelay(boost::asio::io_context& io_ctx,
             const std::string& remote_addr,
             uint16_t remote_port,
             const std::string& password);

    // 启动本地 UDP 监听，返回监听端口
    uint16_t start_local_relay();

    // 停止中继
    void stop();

private:
    void do_receive_local();      // 收到应用 UDP 数据
    void do_receive_dtls();       // 收到 Server 回传数据
    void send_to_server(const std::string& frame);
    void send_to_local(const boost::asio::ip::udp::endpoint& ep,
                       const std::string& payload);

    udp::socket local_socket_;           // 本地 UDP 监听
    DTLSSocket dtls_socket_;             // DTLS 连接到 Server
    udp::endpoint client_ep_;            // 应用端点（用于回传）
};
```

### 5.2 SOCKS5 UDP ASSOCIATE 处理

```cpp
// Client/Session.cpp — 替换被注释的代码
void Session::read_socks5_request() {
    // ... 解析 SOCKS5 请求 ...
    if (socks5_req.cmd == Request::UDP_ASSOCIATE) {
        do_handle_socks5_udp_associate();  // 实现此函数
    } else {
        do_resolve();
    }
}

void Session::do_handle_socks5_udp_associate() {
    // 1. 创建 UdpRelay
    auto relay = std::make_shared<UdpRelay>(
        context_, config.remote_addr, config.remote_port, config.text_password);

    // 2. 启动本地 UDP 监听
    uint16_t local_udp_port = relay->start_local_relay();

    // 3. 回复 SOCKS5 BND.ADDR + BND.PORT
    // 告诉应用："向 127.0.0.1:local_udp_port 发送 UDP 数据"
    socks5::Reply reply;
    reply.repResult = socks5::Reply::SUCCEEDED;
    reply.addrtype = socks5::ADDRTYPE::V4;
    reply.realRemoteIP = "127.0.0.1";
    reply.realRemotePort = local_udp_port;

    // 4. 发送 SOCKS5 回复给应用
    std::string reply_data = reply.stream();
    boost::asio::async_write(in_socket, boost::asio::buffer(reply_data),
        [this, relay](ec, len) {
            // 5. 进入 UDP 中继循环
            // TCP 连接保持但不再传输数据
            // UDP 数据通过 relay 双向转发
        });
}
```

### 5.3 数据流

```
应用 --UDP--> local_socket (127.0.0.1:local_port)
    |
    | 封装 UDP 帧
    v
dtls_socket --DTLS--> Server
    |
    v
Server 转发 --> 目标服务器
    |
    v
目标响应 <-- UDP
    |
Server <--DTLS-- dtls_socket
    |
    | 解封装 UDP 帧
    v
local_socket --UDP--> 应用
```

## 6. 配置扩展

### 6.1 Server 配置 (server.json)

```json
{
    "local_addr": "0.0.0.0",
    "local_port": "443",
    "certificate_chain": "server.crt",
    "server_private_key": "server.key",
    "password": ["your_password"],

    "dtls_enabled": true,
    "dtls_port": 8443,
    "dtls_cert": "server.crt",
    "dtls_key": "server.key",
    "dtls_mtu": 1400
}
```

### 6.2 Client 配置 (client.json)

```json
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": "1080",
    "remote_addr": "server.com",
    "remote_port": "443",
    "password": "your_password",

    "udp_enabled": true,
    "dtls_port": 8443
}
```

## 7. ConfigManage 扩展

```cpp
// Shared/ConfigManage.h — ServerConfig 新增字段
struct ServerConfig {
    // ... 现有字段 ...

    // DTLS 配置
    bool dtls_enabled = false;
    std::string dtls_port = "8443";
    std::string dtls_cert;
    std::string dtls_key;
    uint16_t dtls_mtu = 1400;
};

// Shared/ConfigManage.h — ClientConfig 新增字段
struct ClientConfig {
    // ... 现有字段 ...

    // UDP 配置
    bool udp_enabled = false;
    std::string dtls_port = "8443";
};
```

## 8. CMakeLists.txt 扩展

```cmake
# Server/CMakeLists.txt
set(SERVER_SRCS
    main.cpp
    Session.cpp
    DtlsListener.cpp    # 新增
    ${SHARED_SRCS}
)

# 链接 OpenSSL（已包含 DTLS 支持）
target_link_libraries(overplus_server PRIVATE
    OpenSSL::SSL OpenSSL::Crypto
    # ... 其他依赖 ...
)
```

## 9. OpenSSL DTLS API 使用

### 9.1 Server 端 DTLS 上下文

```cpp
// 创建 DTLS 上下文
ssl::context ssl_ctx(ssl::context::dtls);
ssl_ctx.use_certificate_chain_file("server.crt");
ssl_ctx.use_private_key_file("server.key", ssl::context::pem);

// DTLS cookie 验证（防反射攻击）
ssl::dtls::cookie_verify_function verify_cookie;
```

### 9.2 Client 端 DTLS 连接

```cpp
// 创建 DTLS socket
udp::socket udp_sock(io_ctx, udp::endpoint(udp::v4(), 0));
ssl::stream<udp::socket> dtls_sock(std::move(udp_sock), ssl_ctx);

// DTLS 握手
dtls_sock.async_handshake(ssl::stream_base::client,
    [](boost::system::error_code ec) {
        if (!ec) {
            // 握手成功，开始发送数据
        }
    });
```

## 10. 实现阶段

| 阶段 | 内容 | 预估工时 | 依赖 |
|------|------|----------|------|
| 1 | 自定义 UDP 帧编解码 | 2h | 无 |
| 2 | ConfigManage DTLS 配置扩展 | 1h | 无 |
| 3 | Server DTLS 监听器 + 密码认证 | 4h | 阶段1,2 |
| 4 | Server DTLS Session 模板特化 | 3h | 阶段3 |
| 5 | Client UdpRelay 类 | 4h | 阶段1,2 |
| 6 | Client SOCKS5 UDP ASSOCIATE | 3h | 阶段5 |
| 7 | Client DTLS 连接 | 3h | 阶段5 |
| 8 | 双向数据流联调 | 4h | 阶段4,6,7 |
| 9 | 超时/清理/错误处理 | 3h | 阶段8 |
| 10 | 测试 (DNS/QUIC/游戏) | 4h | 阶段9 |
| **总计** | | **31h** | |

## 11. 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| OpenSSL DTLS API 复杂 | 握手/cookie 验证实现困难 | 参考 Boost.Asio SSL 示例，使用 `ssl::stream<udp::socket>` |
| UDP 不可靠 | 数据包丢失无重传 | 依赖上层协议 (DNS 有重传, QUIC 有自己的可靠性) |
| NAT 穿透 | 客户端在 NAT 后时 Server 回传困难 | DTLS cookie 验证 + 端口预测 |
| MTU 分片 | 大 UDP 包超过 MTU 被分片 | 设置 `dtls_mtu=1400`，避免 IP 分片 |
| 并发管理 | 多个 DTLS session 需要独立状态 | 每个 session 独立的 UDP socket 映射 |
| 内存占用 | 每个 session 需要缓冲区 | 限制最大 session 数，使用环形缓冲区 |

## 12. 测试计划

| 测试场景 | 验证方法 | 预期结果 |
|----------|----------|----------|
| DNS 查询 | `dig @127.0.0.1 example.com` 通过代理 | 返回正确 IP，延迟 <50ms |
| HTTP/3 (QUIC) | Chrome 访问 `https://cloudflare-quic.com` | 正常加载，HTTP/3 协议协商成功 |
| 游戏 UDP | 连接 UDP 游戏服务器 | 延迟 <100ms，无丢包 |
| 大流量 | `iperf3 -u` 测试 | 吞吐量 >50Mbps |
| 并发 session | 同时 100+ UDP 会话 | 无内存泄漏，CPU <50% |
| 密码错误 | 使用错误密码连接 DTLS | 拒绝连接，日志记录 |
| 超时清理 | 空闲 session 30s | 自动关闭，资源释放 |
