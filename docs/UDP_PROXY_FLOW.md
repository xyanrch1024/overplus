# Overplus UDP 代理数据流

当前实现版本：共享 DTLS + session_id 多路复用（`v1.1.0`）

---

## 关键架构决策

| 决策 | 旧方案 | 当前方案 |
|------|--------|----------|
| DTLS 连接数 | 每个 UDP ASSOCIATE 一条独立 DTLS | 整个 Client 共享一条 DTLS |
| 会话区分 | N/A（每条连接一个会话） | `session_id`（2B 前缀） |
| 认证时机 | 每建立一条 DTLS 都需握手+认证 | 启动时一次握手+认证 |
| 路由 | 每个 TcpSession 管理自己的 UdpRelay | Server 持有 `relays_` 全局 map |

---

## 整体架构

```
┌──────────────────────────────────────────────────────────────────┐
│ Client side                                                      │
│                                                                  │
│  App ──TCP:1080──→ Session (SOCKS5 ASSOCIATE)                   │
│       ──UDP:relay─→ UdpRelay ──session_id+UdpFrame──→ Server   │
│                                                          │      │
│  Server                                                          │
│  ┌────────────────────────────────────────────────────────┐      │
│  │ Server (shared owner)                                   │      │
│  │  ├─ DtlsChannel (1条，所有UDP共享)                     │      │
│  │  ├─ relays_[session_id → UdpRelay]                     │      │
│  │  └─ on_dtls_data(): 按session_id派发                    │      │
│  └────────────────────────────────────────────────────────┘      │
│           │ DTLS over UDP (公网)                                 │
└───────────┼──────────────────────────────────────────────────────┘
            ▼
┌──────────────────────────────────────────────────────────────────┐
│ Server side                                                      │
│                                                                  │
│  DtlsListener ──→ DtlsServerSession (每客户端一条)              │
│     │                                                            │
│     ├─ target_socket_ (单 UDP socket，收发所有目标)              │
│     ├─ target_to_session_[target_ep → session_id]               │
│     └─ target_recv_buf_ + do_read_target() 循环                  │
│           │                                                      │
│           ▼ UDP                                                  │
│     目标服务器 (DNS/游戏/QUIC...)                                 │
└──────────────────────────────────────────────────────────────────┘
```

---

## 上行数据流：App → 目标服务器

```
Step 1: SOCKS5 UDP 封装
─────────────────────────────────────────────────────────────────
  App → localhost:relay_port
  UDP payload: [RSV:3(0x00)][FRAG:1(0x00)][ATYP:1][DST.ADDR:var][DST.PORT:2][DATA...]

Step 2: UdpRelay::do_receive_local() 收到后解析
─────────────────────────────────────────────────────────────────
  a. 校验 RSV + FRAG
  b. 解析 ATYP/DST.ADDR/DST.PORT
  c. 构造 UdpFrame (内部格式):
       [MAGIC:2(0x0D0A)][TOTAL_LEN:2][ATYPE:1][ADDR:var][PORT:2][DATA...]
  d. 前插 session_id:
       [SESSION_ID_HI][SESSION_ID_LO][UdpFrame...]
  e. 调用 dtls_->send(pkt)

Step 3: 共享 DtlsChannel 加密发送
─────────────────────────────────────────────────────────────────
  a. SSL_write(ssl_, pkt) → DTLS 加密 → write_bio
  b. BIO_read(write_bio) → UDP sendto(server:dtls_port)
  c. 跨公网传输

Step 4: 服务端接收
─────────────────────────────────────────────────────────────────
  DtlsListener 收到 UDP → 按 client_ep 找到对应的 DtlsServerSession
  DtlsServerSession::on_datagram() → SSL_read() 解密

Step 5: 帧解析 + 目标路由
─────────────────────────────────────────────────────────────────
  a. 提取前2字节: session_id
  b. 解析 UdpFrame: MAGIC → TOTAL_LEN → ATYPE → ADDR → PORT → payload
  c. 记录路由: target_to_session_[target_ep] = session_id
  d. target_socket_.async_send_to(target_ep, payload)
```

---

## 下行数据流：目标服务器 → App

```
Step 1: 接收目标响应
─────────────────────────────────────────────────────────────────
  DtlsServerSession::do_read_target()
  a. async_receive_from 收到响应
  b. target_to_session_.find(sender_ep) → session_id

Step 2: 封装返回
─────────────────────────────────────────────────────────────────
  a. 构造 UdpFrame: [MAGIC:TOTAL_LEN:ATYPE:ADDR:PORT:payload]
  b. 前插 session_id: [session_id:2][UdpFrame...]
  c. SSL_write() → DTLS 加密 → 发回客户端

Step 3: 客户端派发
─────────────────────────────────────────────────────────────────
  DtlsChannel 收到 → SSL_read() 解密
  → Server::on_dtls_data()
     → 提取 session_id: [sid_hi][sid_lo]
     → locks relays_mutex_
     → relays_.find(session_id) → UdpRelay::on_dtls_data()

Step 4: 回写 App
─────────────────────────────────────────────────────────────────
  UdpRelay::on_dtls_data()
  a. 解析 UdpFrame
  b. 构造 SOCKS5 UDP 响应:
       [RSV:3][FRAG:1][ATYPE:1][SRC.ADDR:var][SRC.PORT:2][DATA...]
  c. local_socket_.send_to(pkt, sender_ep_)  → App recvfrom
```

---

## 关键数据结构

### 客户端 Server 侧

```cpp
// Client/Server.h
std::unique_ptr<DtlsChannel> dtls_;              // 共享 DTLS 连接
std::atomic<uint16_t> next_session_id_{1};        // session_id 分配器
std::mutex relays_mutex_;
std::unordered_map<uint16_t, UdpRelay*> relays_;  // session_id → relay 映射
```

### 服务端 DtlsServerSession 侧

```cpp
// Server/DtlsServerSession.h
boost::asio::ip::udp::socket target_socket_;      // 唯一的对外 UDP 套接字
std::map<udp::endpoint, uint16_t> target_to_session_;  // 目标端点 → session_id 映射
std::array<char, 65535> target_recv_buf_;          // target 接收缓冲区
```

---

## 核心约束

| 约束 | 说明 |
|------|------|
| 一个 DtlsServerSession 对应一个远端客户端 | 按 client:port 区分 |
| 一个 DtlsServerSession 只有一个 target_socket_ | 所有目标共享一个 UDP socket |
| session_id 在客户端全局唯一 | Server 原子计数器分配，永不重复 |
| target_to_session_ 按 endpoint 精确匹配 | DNS 查询必须源端口固定才能匹配响应 |
| sender_ep_ 记录最后一次发送来源 | 响应回给该来源，同一端口多线程会竞态 |

---

## 当前问题

| 问题 | 描述 | 影响 |
|------|------|------|
| sender_ep_ 单点覆盖 | `on_dtls_data` 回写时固定用 `sender_ep_`（最后发数据的来源） | 同一端口多 App 连接时响应可能错发 |
| target_to_session_ 粘连 | 响应靠 `sender_ep` 匹配映射，无法区分同一目标的不同查询 | 连续并发查询可能串 session |
| 无超时清理 | session_id 只增不减，target_to_session_ 只增不删 | 长期运行内存增长 |
