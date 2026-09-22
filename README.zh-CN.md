# Krymux

通过反向隧道安全地访问服务。

[English](README.md) | **简体中文** | [日本語](README.ja.md) | [Deutsch](README.de.md) | [Français](README.fr.md) | [Español](README.es.md)
> 测试与 CI：每个 commit 三并行 job——覆盖率（Rust 门槛 55%，Go/Python/TS 一并汇总）、Linux 集成（参数化边界矩阵 54 组合 + 各语言 interop + 跨语言矩阵）、Windows 全量 E2E。详见英文版 Testing & CI 节。

> SDK 为多语言单仓：Rust 参考实现（crates/krymux）+ TypeScript / Go / Python（sdks/），均线兼容并通过与 Rust 二进制的互操作测试。

`krymux` 通过 frp 这类明文 TCP 中继（relay）把本地服务暴露到公网——这类中继既不提供端到端加密，也没有针对单个客户端的访问控制。它在服务所在的机器上运行一个反向代理，并与客户端建立 **TLS 1.3 双向认证加密隧道**（frp 自始至终只能看到密文）。隧道之内是一组**多路复用的逻辑 stream**，具备**逐 stream 压缩**、**基于信用额度（credit）的流控**、**半关闭（half-close）**与**保活（keepalive）**。其信任模型与 WireGuard/SSH 同构：服务器持有一份客户端 **Ed25519 公钥指纹**（`sha256(SPKI)`）白名单，客户端则**固定（pin）服务器指纹**以防范中间人攻击。

本仓库是其中的 **Rust 实现**：单个约 5.3 MB 的静态二进制文件即包含全部应用程序（文件同步、浏览器 WebSocket 访问、SOCKS5/HTTP 前端）。它与 **Node 参考实现**（[`../ectun`](../ectun)）**线协议（wire protocol）兼容**——相同的 Ed25519 指纹身份体系、相同的 JSON 配置 schema，两端可自由互换并相互交叉基准测试。

```
User program ── local SOCKS5/HTTP proxy or SDK ──> krymux client
     ═══ TLS 1.3 (mutual Ed25519 auth) + multiplexing + compression ═══   ← frp sees only ciphertext
              via frps (public) → frpc relay → machine-local preset port
                                          └──> krymux server (reverse proxy)
                                               ├─ host a.test  → 127.0.0.1:3000
                                               ├─ host *.test  → 127.0.0.1:8080
                                               └─ any port / Unix socket / client-chosen target (optional)

Browser (no client process needed)
     ═══ wss:// → TLS → WebSocket → P-256 signature auth + CMPX multiplexing ═══
              same port (HTTP GET detection branch), likewise relayed through frp
                                          └──> same krymux server
```

## 功能特性

- **端到端加密** — 仅 TLS 1.3（ALPN `krymux`）、Ed25519 证书、AES-GCM/ChaCha20-Poly1305；frp 链路上传输的只有密文。
- **公钥白名单** — `sha256(SPKI)` 指纹*即是*身份；握手之后按 fail-closed（失败即拒绝）方式准入。客户端固定（pin）服务器指纹。
- **多路复用** — 一条 TLS 连接承载数百个全双工逻辑 stream（浏览器开 50 个连接 = 1 次握手）。
- **逐 stream 压缩** — `deflate` / `brotli` / `zstd`，带连续上下文与流式 flush；`none` 直通；`auto` 自动协商。支持级别预设，如 `"zstd:9"`、`"brotli:11"`、`"deflate:9"`。
- **魔数旁路（magic-byte bypass）** — 首 chunk 嗅探检测已是压缩格式的内容（gzip/zstd/zip/png/jpeg/7z/rar/pdf/bzip2/mp4），并自动把该 stream 切换为 `none`（省 CPU、避免膨胀）。
- **基于 credit 的流控** — 逐 stream 窗口按*解压后*字节数计量；慢速消费方不会耗尽内存，也不会饿死其他 stream。动态窗口自动增长：stream 处于排空状态时，授予额度每 100 ms 翻倍——50 ms RTT 下单 stream 吞吐 4 → 32.4 MB/s（窗口从旧的固定 256 KB 自动增长至 4 MB 上限）。
- **协议透明** — 保留 TCP 字节流语义与半关闭（half-close）；HTTP/WebSocket/SSH/数据库协议原样透传。
- **vhost 路由** — 客户端指明主机名；服务器按 host / 端口 / fallback / 客户端自选目标，把流量路由到不同 upstream。
- **浏览器（WebSocket）访问** — `wss://` 加 P-256 应用层签名认证，共用同一份指纹白名单；内置启动页；零依赖浏览器 SDK。
- **双向文件同步** — SHA-1 哈希比对、mtime 时钟偏移对齐、原子写入、锁检测、带服务器推送变更 hint 的 watch 守护进程（daemon）。
- **后量子（post-quantum）构建** — `--features pq`（aws-lc-rs 后端）协商 X25519MLKEM768 混合 KEM。
- **单一二进制、无运行时依赖** — 基础构建为纯 Rust 依赖链。

## 架构定位
> 仓库布局：Krymux 是一个 SDK（`crates/krymux` 纯库）；应用构建于其上——`krymux-tunnel`（隧道运维 CLI）、`krymux-sync`（文件同步）、`browser/`（浏览器 JS SDK）。

**协议 SDK 保持多语言；应用程序仅限 Rust。**

- 协议 SDK（帧 / 多路复用 / TLS / 压缩）保留两个实现——Node（参考实现）与 Rust——互为回归基线；Go 与 Python 在计划中。
- 更高层的应用程序（文件同步、WS 前端扩展等）**仅以 Rust 实现**，以保持较小的维护面。
- Node 包定位为**纯协议参考**（不含应用程序）；生产部署使用本 Rust 二进制。

### 实现说明（Rust）

- **TLS**：rustls（ring 后端），仅 TLS 1.3，ALPN `krymux`。服务器要求出示客户端证书（任意签发者均可），再依据 `sha256(SPKI)` 白名单决定是否准入（fail-closed）。客户端固定（pin）服务器指纹。证书由 rcgen 生成（Ed25519）。
- **多路复用**：与 Node 版相同的帧格式（见 [`../ectun/docs/PROTOCOL.md`](../ectun/docs/PROTOCOL.md)）——逐 stream 的 credit 流控（按解压后字节计量）、连续压缩上下文、半关闭传播。
- **任务模型**：每连接两个任务（读/写）+ 逐 stream 的入站/出站泵 + credit 定时器 + keepalive；数据经 tokio duplex 送达应用。隧道 socket 设置 `TCP_NODELAY`。
- **压缩**：`deflate`（flate2）、`brotli`（brotli crate，底层 push API）、`zstd`（可选 feature）。Brotli 解压使用 `BrotliDecompressStream` 底层 API——`DecompressorWriter` 会把输出滞留在内部缓冲区，且其 flush 不会驱动解码，在跨实现的大传输中会丢失尾部字节；底层路径可避免此问题。
- **已修复（事后分析已归档）**：一个由 `Drop` 双重加锁自死锁导致的 EOF 尾部 bug（不可重入的 std `Mutex` 在 `if let` 谓词内被再次加锁——永久挂起，`JoinHandle` 永不返回）。同批修复：tokio split 的写半边在 drop 时不发送 EOF（显式 `poll_shutdown` + 服务器端 `stream.shutdown()`）；并已记录：“先写完、再读”的背压模式在裸 TCP 上同样死锁——正确模式是边读边写，浏览器/curl 天然如此。

## 构建

```bash
cargo build --release                                # workspace: SDK + both apps, pure-Rust dependency chain
cargo build --release --features krymux/zstd         # + zstd (C compilation verified under MSVC/gcc) — recommended
cargo build --release --features krymux/pq           # + aws-lc-rs post-quantum KEM (~5.7 MB binaries)
cargo build --release --features "krymux/pq krymux/zstd"  # everything
# artifacts: target/release/krymux-tunnel and target/release/krymux-sync — no runtime dependencies
```

交叉编译 Linux 目标（部署到服务器或 LXD 时）：

```bash
rustup target add x86_64-unknown-linux-gnu
# with a Linux-side linker: cargo build --release --target x86_64-unknown-linux-gnu
# or use cross / cargo-zigbuild
```

注意：基础构建在 HELLO 协商中通告 `none`/`deflate`/`brotli`；`zstd` 需要 `zstd` feature。

## 快速开始

CLI 命令一览（与 Node 版形状相同）：

| 命令 | 用途 |
|---|---|
| `krymux-tunnel keygen --out <dir> --role server\|client [--name x] [--cn cn]` | 生成 Ed25519 身份（密钥 + 自签名证书 + 指纹） |
| `krymux-tunnel fingerprint <key-or-cert.pem>` | 打印 PEM 文件的指纹 |
| `krymux-tunnel probe <host:port>` | 显示服务器的密钥指纹（TOFU 辅助） |
| `krymux-tunnel server --config server.json` | 运行反向代理服务器 |
| `krymux-tunnel client --config client.json [--socks5 h:p] [--http-proxy h:p]` | 运行客户端（可选附带本地代理前端） |
| `krymux-sync sync-server --path <dir> [--port 17890] [--mode bidir\|readonly]` | 在 krymux 后面运行文件同步服务器 |
| `krymux-sync sync-client --path <dir> --config client.json [--mode …] [--watch] [--interval 30]` | 通过隧道运行文件同步客户端 |

### 1. 在两端生成身份

```bash
./target/release/krymux-tunnel keygen --out ./keys --role server
./target/release/krymux-tunnel keygen --out ./keys --role client --name alice
```

每条命令都会打印该身份的 `sha256:` 指纹。

### 2. （TOFU）核对服务器指纹

如果你尚不知道服务器指纹，请先通过带外方式核实一次，并写入配置：

```bash
./target/release/krymux-tunnel probe frp.example.com:7000
```

### 3. 服务器配置（位于服务机器上——frpc 转发的就是这个端口）

```jsonc
// server.json
{
  "listen": "127.0.0.1:7443",                       // ← frpc's localPort points here
  "identity": { "key": "keys/server.key.pem", "cert": "keys/server.crt.pem" },
  "auth": {
    "mode": "whitelist",
    "fingerprints": [ "sha256:<alice fingerprint, printed by keygen>" ]
  },
  "routes": [
    { "host": ["nas.example"], "upstream": ["127.0.0.1", 5000] },
    { "host": ["*.example"],   "upstream": ["127.0.0.1", 80] },
    { "host": ["db"], "port": 5432, "upstream": ["127.0.0.1", 5432] }
  ],
  "fallbackUpstream": ["127.0.0.1", 80],            // route for unmatched hosts
  "clientTargets": { "enabled": false }             // true = allow clients to pick arbitrary host:port
}
```

```bash
./target/release/krymux-tunnel server --config server.json
```

### 4. 客户端配置（任意位置）

```jsonc
// client.json
{
  "endpoint": "frp.example.com:7000",               // ← the public port frps exposes
  "identity": { "key": "keys/alice.key.pem", "cert": "keys/alice.crt.pem" },
  "serverFingerprint": "sha256:<server fingerprint from probe>",
  "compression": "auto"
}
```

```bash
./target/release/krymux-tunnel client --config client.json --socks5 127.0.0.1:1080
```

### 5. 开始使用

把浏览器或 curl 指向本地 SOCKS5 代理——**主机名即成为 vhost 路由键**：

```bash
curl --socks5-hostname 127.0.0.1:1080 http://nas.example/
```

改用 `--http-proxy 127.0.0.1:8080` 则提供 HTTP/1.1 代理前端（CONNECT + absolute-form）。配置字段与 Node 版完全一致；完整场景见 [`../ectun/examples/`](../ectun/examples/)。

## 文件同步

```bash
# Host A (server side, behind krymux)
krymux-sync sync-server --path /data --port 17890 [--mode bidir|readonly]
# krymux server config: { "host": ["sync"], "upstream": ["127.0.0.1", 17890] }

# Host B (client side, through the tunnel)
krymux-sync sync-client --path /data --config client.json [--mode bidir|readonly]

# Daemon mode: keep running, push local changes immediately, pull remote changes,
# auto-reconnect on failure
krymux-sync sync-client --path /data --config client.json --watch --interval 30
```

### 同步引擎

- **双向**：服务器 → 客户端下载、客户端 → 服务器上传，由 **SHA-1 哈希比对**、两台机器之间的 **mtime 时钟偏移对齐**、**原子写入**（临时文件 → 改名）与**锁检测**驱动。
- **只读模式经协商确定**（`hello_ack`）：服务器为只读时客户端自动抑制上传，且服务器无论如何仍会拒绝 `put`。
- 针对并发编辑的**冲突报告**（见下文多客户端语义）。
- **路径穿越防护**：`..` 片段、绝对路径与盘符一律拒绝。

### Watch 守护进程（`--watch`，`apps/krymux-sync/src/sync/daemon.rs`）

- **本地变更** → notify 事件，带 **700 ms 去抖静默期**，跳过 `*.sync-tmp` 与读事件（inotify 会把我们自己扫描时的哈希读取报告为变更；不加过滤在 Linux 上会自我触发循环）。
- **远端变更** → 由服务器主动推送（`rescan_hint`）：sync-server 监视自身的目录树（`apps/krymux-sync/src/sync/notify.rs`），一有变更立即通知已连接的 daemon——hint 到达为秒级。**同步会话进行期间 hint 被抑制**（这样服务器不会回声它正在接收的上传）；会话结束时触发一个合并后的 hint，这也是变更传播到其他客户端的途径。不支持 hint 的旧服务器会静默降级，由 interval 接管。
- **`--interval`**（默认 30 s）周期性对账如今只是**兜底手段**（应对丢失的 hint / 旧服务器），而非主要机制。
- **重连**：隧道丢失后下一轮 pass 失败，以指数退避重建隧道，起始 1 s、上限 60 s。
- **任意时刻 kill 均安全**：所有写入都走 tmp+改名，扫描跳过残片。

### 多客户端语义

N 个客户端可同时同步同一服务器根目录。某一客户端的变更会在数秒内经会话结束 hint 广播给其他客户端（无需等待 interval）。对同一文件的并发编辑按 **mtime 后写者胜（last-writer-wins）** 收敛——每个端点最终达成一致，不会出现内容混杂。

### 锁与启动冲突（由 `edge-e2e.sh` 的 8 个阶段验证）

- **根目录互斥**：sync-server/sync-client 启动时对 `<root>/.sync.lock` 取排他性 OS 文件锁（std 1.89 原生 API：Windows 上为 `LockFileEx`，Unix 上为 `flock`）。同一根上的第二个进程会被直接拒绝；崩溃的进程自动释放锁——无需陈锁恢复。
- **启动锁检查**：若根内任一文件被其他进程排他持有，则拒绝启动并列出涉事文件。
- **运行时锁**：客户端侧被锁定的文件本轮跳过（不触碰）。服务器侧被锁定或不可读的文件（含扫描时读取失败 = 哈希为 `None`）按*无法判定 → 本轮跳过*处理，绝不会被误判为冲突。
- **崩溃残片**：任意时刻 `kill -9` 都安全（tmp+改名的原子性；经 500 MB E2E 测试，无撕裂）。启动时会清理存在 ≥ 1 h 的陈旧 `*.sync-tmp` 文件。
- **单点失败隔离**：单个无法安装的文件（如目录占位符）被跳过，不会饿死本轮其余同步；下载校验失败（大小/哈希）在本轮内重试一次。
- **验证边界**：文件锁的端到端路径在 Windows 上经过验证（真实的共享冲突）；无特权 Linux 容器无法模拟不可写文件（root 无视 chmod；chattr 需要 `CAP_LINUX_IMMUTABLE`），因此 Linux 侧通过双进程 `flock` 互斥加 kill 后复活来验证。

### 跨操作系统兼容性（Windows ↔ Linux，经 LXD 代理模拟中继测试）

- **连接层**：多地址解析、逐个尝试，且**每个地址独立 5 s 超时**——当 IPv6 被黑洞化时，拥有多条 A/AAAA 记录的 mDNS/DNS 名称不再耗尽连接预算（实测 `myhost.local` 返回 3 条 IPv6 + 2 条 IPv4，黑洞化的 IPv6 曾导致必然超时）。
- **文件名**：UTF-8（中文文件名 + 内容）双向无损；**Windows 非法名称**（`<>:"|?*`、`CON`/`COM1` 等保留名、末尾的点/空格）警告后跳过；**大小写冲突**（Linux 上 `Foo.txt` + `foo.txt`）在所有平台告警，大小写不敏感平台只同步最先见到的名称（避免无休止的下载-覆盖来回翻转）；长路径可用（Windows `\\?\` 前缀，实测 212 字符）。
- **符号链接**：按 `lstat` 语义跳过（不跟随、不传播、无环风险）。
- **跨文件系统的 mtime**：NTFS↔ext4 往返凭哈希短路保持稳定（内容相同 = 无操作）。
- **边界**：macOS（FSEvents watcher）从未构建或运行过——未验证。

### 删除传播（tombstone）

删除会传播到所有客户端（`.sync-tombstones.json` 墓碑存储、30 天过期、时钟偏移校正的 mtime 后写者保护、readonly 双向抑制）；删除后他处再编辑则以较新内容胜出。`deletion-semantics-probe.sh` 双向验证无复活。注：性能与基准数字以英文版与 `bench/BASELINE.md` 为准。

## 浏览器（WebSocket）访问

服务器在**同一个 TLS 端口**上服务三种连接类型，按检测区分双模式：原生 mTLS 客户端（Ed25519 证书 + ALPN `krymux`）与其余一切不带客户端证书的连接，后者中 HTTP `GET` 分流进入 WebSocket/静态路径。frp 只是继续转发 TCP 密文——无需额外配置。

1. 启动服务器。它会自动生成一个浏览器身份（`ws-p256.key.pem`，P-256）并记录其 `wsFingerprint`。
2. 在浏览器中打开 `https://<frps-public-port>/`（一次性接受自签名证书例外）——内置启动页随即加载。
3. 把页面上显示的身份指纹加入服务器的 `auth.fingerprints`——即原生客户端所用的**同一份白名单**。
4. 刷新、输入目标 `host:port`、连接——任意已路由服务都可从浏览器标签页访问。

认证强度与 mTLS 等价：同一份 `sha256(SPKI)` 白名单混含 Ed25519（原生）与 P-256（浏览器）条目；客户端的应用层签名证明白名单身份，服务器的签名证明被固定（pin）的身份（位于 TLS 之内）。Rust 服务器强制 10 s 认证超时与 256 个并发 WS 连接上限。SDK 是零依赖单文件 ESM（`ectun-browser.mjs`，已内置于本仓库 `browser/ectun-browser.mjs`——可直接托管或 import；线协议完全相同）：

```js
import { getIdentity, connect } from '/sdk/ectun-browser.mjs';
const id = await getIdentity();          // P-256 identity, persisted in IndexedDB
// id.fingerprint → add to the server whitelist
const c = await connect({
  endpoint: 'wss://frps.example:7000',
  serverFingerprint: 'sha256:…',         // pin the server's WS identity
  identity: id,
});
const s = await c.openStream({ host: 'a.test', port: 80 });
await s.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: a.test\r\n…'));
await s.end();
s.onData((chunk) => …); s.onEnd(() => …);
```

SDK v1 通告 `none` 压缩（CMPX 协商已为日后的升级就绪）。协议细节：[`../ectun/docs/PROTOCOL.md` §6A](../ectun/docs/PROTOCOL.md)。

## 验证

```bash
bash e2e-sync-test.sh   # file sync: 9-phase main flow
bash edge-e2e.sh        # file sync: 8 edge phases (locks / crash / conflicts)
```

- 对 Node 参考实现的**互操作 11/11**（`interop/test-interop.mjs`）：
  - Node 客户端 → Rust 服务器：none/deflate/brotli 1 MB 回显逐字节一致、双 vhost 路由、未路由目标被拒、非白名单密钥被拒；
  - Rust 客户端 → Rust 服务器：SOCKS5 + vhost（以 curl 实测）；
  - Rust 客户端 → Node 服务器：none/deflate/brotli 1 MB 回显逐字节一致。
- **指纹互操作**：Node 的 `fingerprint` 命令对 Rust keygen 生成的证书计算出相同的值，反之亦然。
- **LXC 部署模板**：[`deploy/lxc/`](deploy/lxc/) 中的双容器配置——`server.json` / `client.json` / server、sync-server 与 sync-client 的 systemd 单元。真机结果：100 MB 传输 md5 一致、跨客户端传播约 2 s、rescan-hint 送达约 1 s。

## 性能

回环基准测试（Node 数据来自 Node 参考实现，Node 24.15，见 [`../ectun/docs/BENCHMARKS.md`](../ectun/docs/BENCHMARKS.md)；Rust 数据来自 `examples/bench`，16 MB 回显）：

| 配置 | 吞吐量 |
|---|---|
| Rust，16 MB 回显，无压缩 | ~405 MB/s |
| Rust，16 MB 回显，zstd（可压缩文本） | ~739 MB/s |
| Node 参考实现，无压缩（×1/×4 stream） | ~80 MB/s（单核 JS 上限） |
| Node 参考实现，zstd ×4 stream（文本） | ~319 MB/s |
| Node 参考实现，brotli ×4 stream（文本） | ~285 MB/s |
| **窗口自动增长，单 stream @ 50 ms RTT** | **4.0 → 32.4 MB/s**（固定 256 KB → 自动至 4 MB 上限） |
| 经 TCP 中继（模拟 frp） | 无可测损耗 |
| stream 打开延迟 | p50 0.28 ms（已建立的连接内） |
| 完整 TLS 握手 | ~6 ms（回环） |

压缩常常*提高*吞吐量（线上字节更少）；真实 frp 链路上的窗口瓶颈已被自动增长消除，剩下的限制只有公网带宽与压缩 CPU。

## 配置参考

JSON 采用 camelCase 键名，两个实现的 schema 完全一致。

### server.json

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `listen` | string | *必填* | 监听的 `host:port`；frpc 的 `localPort` 指向此处 |
| `identity.key`, `identity.cert` | string | *必填* | 由 `keygen` 生成的 Ed25519 PEM 路径 |
| `auth.mode` | string | `"whitelist"` | 准入模式 |
| `auth.fingerprints` | string[] | `[]` | `sha256(SPKI)` 客户端白名单（`auth.clients` 条目会被合并进来） |
| `routes[].host`（别名 `hosts`） | string 或 string[] | — | vhost 匹配键；支持 `*.example` 这类通配符 |
| `routes[].port`（别名 `ports`） | number、`"n"`、`"a-b"`、`"*"` 或数组 | — | 该路由的可选端口模式 |
| `routes[].upstream` | `[host, port]`、`"host:port"`、`"unix:/path"` 或 `{host, port}` / `{unix}` | — | 匹配流量的送达目的地 |
| `fallbackUpstream`（别名 `defaultUpstream`） | upstream | — | 未匹配任何路由的主机的去向 |
| `clientTargets.enabled` | bool | `false` | 允许客户端指定任意 `host:port` 目标 |
| `clientTargets.allowHosts` | string[] | `["*"]` | 客户端可选择的 host 模式 |
| `clientTargets.allowPorts` | pattern[] | — | 客户端可选择的端口模式 |
| `keepaliveSec` | integer | `30` | keepalive 间隔 |
| `maxStreams` | integer | `1024` | 每连接的最大逻辑 stream 数 |
| `rxWindow` | integer | `262144` (256 KB) | 每 stream 的初始接收窗口 |
| `rxWindowMax` | integer | `4194304` (4 MB) | 自动增长上限；设为与 `rxWindow` 相等即禁用增长 |
| `log.level` | string | `"info"` | 日志级别 |
| `statsIntervalMs` | integer | — | 周期性统计打印 |

### client.json

| 字段 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `endpoint` | string | *必填* | frps 暴露的公网 `host:port` |
| `identity.key`, `identity.cert` | string | *必填* | 客户端 Ed25519 PEM 路径 |
| `serverFingerprint` | string | *必填* | 固定（pin）的服务器指纹 `sha256:…` |
| `compression` | string | `"auto"` | `none` / `auto` / `deflate` / `brotli` / `zstd`（zstd 构建），或 `"zstd:9"`、`"brotli:11"`、`"deflate:9"` 这类级别预设（作用于发送侧） |
| `keepaliveSec` | integer | `30` | keepalive 间隔 |
| `rxWindow` | integer | `262144` (256 KB) | 每 stream 的初始接收窗口（两端均可设置） |
| `rxWindowMax` | integer | `4194304` (4 MB) | 自动增长上限 |
| `socks5` | string | — | 本地 SOCKS5 前端地址，例如 `127.0.0.1:1080` |
| `httpProxy` | string | — | 本地 HTTP/1.1 代理前端（CONNECT + absolute-form） |
| `log.level` | string | `"info"` | 日志级别 |

窗口自动增长：当某个 stream 消耗了超过一半窗口并将其排空时，授予额度每 100 ms 翻倍；处于背压状态的 stream 不增长。两端均可配置 `rxWindow`/`rxWindowMax`；`rxWindowMax = rxWindow` 即禁用增长。

## 故障排查

- `KRYMUX_LOG=debug` 开启调试日志。
- `KRYMUX_MUX_TRACE=1` 在 stderr 上输出帧级跟踪（含 flags）。

## 路线图

- **删除传播**（墓碑机制：一个 `.sync-tombstones` 目录，按过期时间清理）。
- **zstd 字典（`zstdd`）** — 设计已定稿：离线 `zstd --train`，双方引用同一字典，HELLO 压缩协商 `zstdd` 并附字典指纹后缀校验；预计短 stream（HTTP/API）的首包缩小 2–4×。Node 侧需要原生绑定，或协商回退到普通 zstd。
- **PAD 帧长度分桶**，配合固定速率掩护流量（已在协议 v1.1 预留）。
- **集群 / 多核**吞吐量。
- **UDP** 支持。
- **Go / Python SDK**。
- 用于 WS 认证的 **Noise 风格密钥推导**。
- **macOS** 构建与验证（FSEvents watcher）。

## 许可证

MIT
