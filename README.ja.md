# Krymux

リバーストンネル経由の安全なサービスアクセス。

[English](README.md) | [简体中文](README.zh-CN.md) | **日本語** | [Deutsch](README.de.md) | [Français](README.fr.md) | [Español](README.es.md)
> SDK はマルチ言語モノリポ：Rust リファレンス実装（crates/krymux）+ TypeScript / Go / Python（sdks/）— いずれも線互換で Rust バイナリとの相互運用テスト合格済み。
> テストと CI：コミットごとに 3 並列ジョブ — カバレッジ（Rust ゲート 55%、Go/Python/TS はサマリに統合）、Linux 統合（パラメータ化エッジ行列 54 組み合わせ＋各言語相互運用＋他言語間行列）、Windows フル E2E。詳細は英語版の Testing & CI 節を参照。

`krymux` は、frp のような平文 TCP リレー経由でローカルサービスをインターネットに公開するためのツールです — そうしたリレーはエンドツーエンド暗号化もクライアント単位のアクセス制御も提供しません。サービス機上でリバースプロキシを動かし、クライアントとの間に **TLS 1.3 相互認証による暗号化トンネル**を確立します（frp から見えるのは暗号文だけです）。トンネル内部は**多重化された論理ストリーム**で、**ストリームごとの圧縮**、**クレジットベースのフロー制御**、**ハーフクローズ**、**キープアライブ**を備えています。トラストモデルは WireGuard/SSH 型です。サーバーはクライアントの **Ed25519 公開鍵フィンガープリント**（`sha256(SPKI)`）のホワイトリストを保持し、クライアントは中間者攻撃への対策としてサーバーのフィンガープリントを**ピン留め（pin）**します。

本リポジトリはその **Rust 実装**です。すべてのアプリケーション（ファイル同期、ブラウザ WebSocket アクセス、SOCKS5/HTTP フロントエンド）を含む単一の約 5.3 MB のスタティックバイナリです。**Node リファレンス実装**（[`../ectun`](../ectun)）と**ワイヤープロトコル互換**であり、Ed25519 フィンガープリントのアイデンティティシステムも JSON 設定スキーマも同じで、両端は自由に入れ替え可能、相互にベンチマーク比較も行われています。

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

## 機能

- **エンドツーエンド暗号化** — TLS 1.3 のみ（ALPN `krymux`）、Ed25519 証明書、AES-GCM/ChaCha20-Poly1305。frp リンク上を運ばれるのは暗号文だけです。
- **公開鍵ホワイトリスト** — `sha256(SPKI)` フィンガープリントがアイデンティティ*そのもの*です。ハンドシェイク後の入場判定はフェイルクローズド。クライアントはサーバーのフィンガープリントをピン留めします。
- **多重化** — 1 本の TLS 接続上に数百の全二重論理ストリーム（ブラウザが 50 接続を開いてもハンドシェイクは 1 回）。
- **ストリームごとの圧縮** — 継続コンテキストとストリーミングフラッシュ付きの `deflate` / `brotli` / `zstd`。`none` はパススルー、`auto` はネゴシエーション。`"zstd:9"`、`"brotli:11"`、`"deflate:9"` のようなレベルプリセットも指定できます。
- **マジックバイトバイパス** — 先頭チャンクのスニッフィングで既に圧縮済みのコンテンツ（gzip/zstd/zip/png/jpeg/7z/rar/pdf/bzip2/mp4）を検出し、そのストリームを自動的に `none` へ切り替えます（CPU 節約、膨張の回避）。
- **クレジットベースのフロー制御** — ストリームごとのウィンドウは*展開後のバイト数*で計上されます。遅いコンシューマーがメモリを使い果たしたり他のストリームを餓死させたりすることはありません。動的ウィンドウ自動拡大は、ストリームが捌けている間 100 ms ごとに付与量を倍増します: 50 ms RTT で単一ストリームにおいて 4 → 32.4 MB/s（旧来の固定 256 KB ウィンドウから 4 MB 上限まで）。
- **プロトコル透過性** — ハーフクローズを保持した TCP バイトストリームセマンティクス。HTTP/WebSocket/SSH/データベースプロトコルがそのまま通過します。
- **vhost ルーティング** — クライアントがホスト名を名指しすると、サーバーは host / port / fallback / クライアント指定ターゲットで異なるアップストリームへ振り分けます。
- **ブラウザ（WebSocket）アクセス** — 同じフィンガープリントホワイトリストを共有する P-256 アプリケーション層署名認証付きの `wss://`。内蔵ランチャーページ、依存ゼロのブラウザ SDK。
- **双方向ファイル同期** — SHA-1 ハッシュ差分、mtime クロックオフセット整合、アトミック書き込み、ロック検出、サーバーからプッシュされる変更ヒント付きのウォッチデーモン。
- **ポスト量子ビルド** — `--features pq`（aws-lc-rs バックエンド）は X25519MLKEM768 ハイブリッド KEM をネゴシエートします。
- **単一バイナリ、ランタイム依存なし** — ベースビルドの依存チェーンはピュア Rust。

## アーキテクチャ上の位置づけ
> リポジトリ構成: Krymux は SDK（`crates/krymux`、純ライブラリ）であり、アプリはその上に構築されます — `krymux-tunnel`（トンネル運用 CLI）、`krymux-sync`（ファイル同期）、`browser/`（ブラウザ JS SDK）。

**プロトコル SDK は多言語のまま、アプリケーションは Rust のみ。**

- プロトコル SDK（フレーム / 多重化 / TLS / 圧縮）は Node（リファレンス）と Rust の 2 実装を相互リグレッションの基準として維持します。Go と Python は計画中です。
- より上位のアプリケーション（ファイル同期、WS フロントエンド拡張など）は保守範囲を小さく抑えるため **Rust のみ**で実装されています。
- Node パッケージは**純粋なプロトコルリファレンス**（アプリケーションなし）という位置づけで、本番デプロイにはこの Rust バイナリを使用します。

### 実装メモ（Rust）

- **TLS**: rustls（ring バックエンド）、TLS 1.3 のみ、ALPN `krymux`。サーバーは任意の発行者によるクライアント証明書を要求し、その後 `sha256(SPKI)` ホワイトリストと照合して接続を許可します（フェイルクローズド）。クライアントはサーバーのフィンガープリントをピン留めします。証明書は rcgen（Ed25519）で生成されます。
- **多重化**: Node 版と同じフレーム形式（[`../ectun/docs/PROTOCOL.md`](../ectun/docs/PROTOCOL.md) 参照）— ストリームごとのクレジットフロー制御（展開後バイト数で計上）、継続圧縮コンテキスト、ハーフクローズ伝播。
- **タスクモデル**: 接続ごとに 2 タスク（reader/writer）+ ストリームごとの inbound/outbound ポンプ + クレジットティッカー + キープアライブ。データは tokio デュプレックス経由でアプリケーションに届きます。トンネルソケットには `TCP_NODELAY` を設定します。
- **圧縮**: `deflate`（flate2）、`brotli`（brotli クレート、低レベル push API）、`zstd`（オプション機能）。Brotli の展開には低レベル API の `BrotliDecompressStream` を使用します。`DecompressorWriter` は出力を内部バッファに溜め込み、その flush ではデコードが進まないため、実装をまたぐ大きな転送で末尾バイトが失われることがあります。低レベルパスはこれを回避します。
- **修正済み（ポストモーテム記録済み）**: `Drop` での二重ロック自己デッドロック（非リエントラントな std `Mutex` を `if let` の条件式内でもう一度ロック — 永久ハング、`JoinHandle` が戻らない）が原因の EOF 末尾バグ。あわせて修正: tokio スプリットの書き込みハーフがドロップ時に EOF を送らない問題（明示的な `poll_shutdown` + サーバー側 `stream.shutdown()`）。さらに、「すべて書いてから読む」パターンのバックプレッシャーデッドロックは生 TCP でも同じように発生することを文書化しました — 正しいパターンは読みながら書くことであり、ブラウザ/curl は自然にそうしています。

## ビルド

```bash
cargo build --release                                # workspace: SDK + both apps, pure-Rust dependency chain
cargo build --release --features krymux/zstd         # + zstd (C compilation verified under MSVC/gcc) — recommended
cargo build --release --features krymux/pq           # + aws-lc-rs post-quantum KEM (~5.7 MB binaries)
cargo build --release --features "krymux/pq krymux/zstd"  # everything
# artifacts: target/release/krymux-tunnel and target/release/krymux-sync — no runtime dependencies
```

Linux 向けクロスコンパイル（サーバーや LXD へのデプロイ）:

```bash
rustup target add x86_64-unknown-linux-gnu
# with a Linux-side linker: cargo build --release --target x86_64-unknown-linux-gnu
# or use cross / cargo-zigbuild
```

注: ベースビルドは HELLO ネゴシエーションで `none`/`deflate`/`brotli` を通知します。`zstd` には `zstd` フィーチャーが必要です。

## クイックスタート

CLI の構成（Node 版と同じ形状）:

| コマンド | 用途 |
|---|---|
| `krymux-tunnel keygen --out <dir> --role server\|client [--name x] [--cn cn]` | Ed25519 アイデンティティを生成（鍵 + 自己署名証明書 + フィンガープリント） |
| `krymux-tunnel fingerprint <key-or-cert.pem>` | PEM ファイルのフィンガープリントを表示 |
| `krymux-tunnel probe <host:port>` | サーバーの鍵フィンガープリントを表示（TOFU 用ヘルパー） |
| `krymux-tunnel server --config server.json` | リバースプロキシサーバーを実行 |
| `krymux-tunnel client --config client.json [--socks5 h:p] [--http-proxy h:p]` | クライアントを実行（ローカルプロキシフロントエンドをオプションで併設） |
| `krymux-sync sync-server --path <dir> [--port 17890] [--mode bidir\|readonly]` | krymux の背後でファイル同期サーバーを実行 |
| `krymux-sync sync-client --path <dir> --config client.json [--mode …] [--watch] [--interval 30]` | トンネル経由でファイル同期クライアントを実行 |

### 1. 両端でアイデンティティを生成

```bash
./target/release/krymux-tunnel keygen --out ./keys --role server
./target/release/krymux-tunnel keygen --out ./keys --role client --name alice
```

各コマンドは、そのアイデンティティの `sha256:` フィンガープリントを出力します。

### 2. （TOFU）サーバーのフィンガープリントを確認

サーバーのフィンガープリントをまだ知らない場合は、帯域外の手段で一度検証し、設定に書き込んでください:

```bash
./target/release/krymux-tunnel probe frp.example.com:7000
```

### 3. サーバー設定（サービス機上 — frpc の転送先となるポート）

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

### 4. クライアント設定（任意の場所）

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

### 5. 使ってみる

ブラウザや curl をローカルの SOCKS5 プロキシに向けてください — **ホスト名がそのまま vhost ルーティングキーになります**:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://nas.example/
```

代わりに `--http-proxy 127.0.0.1:8080` を指定すると、HTTP/1.1 プロキシフロントエンド（CONNECT + absolute-form）が提供されます。設定フィールドは Node 版と同一です。完全なシナリオは [`../ectun/examples/`](../ectun/examples/) を参照してください。

## ファイル同期

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

### 同期エンジン

- **双方向**: サーバー → クライアント方向のダウンロードとクライアント → サーバー方向のアップロードを、**SHA-1 ハッシュ比較**、2 台のマシン間の **mtime クロックオフセット整合**、**アトミック書き込み**（tmp ファイル → rename）、**ロック検出**によって駆動します。
- **読み取り専用モードはネゴシエートされます**（`hello_ack` 経由）。サーバーが読み取り専用の場合、クライアントは自動的にアップロードを抑制し、それとは無関係にサーバー側でも `put` を拒否し続けます。
- 並行編集に対する**競合レポート**（下記のマルチクライアントセマンティクスを参照）。
- **パストラバーサル保護**: `..` セグメント、絶対パス、ドライブレターは常に拒否されます。

### ウォッチデーモン（`--watch`、`apps/krymux-sync/src/sync/daemon.rs`）

- **ローカル変更** → notify イベントを **700 ms のデバウンス静寂期間**付きで処理し、`*.sync-tmp` と読み取りイベントをスキップします（inotify は自身のスキャンによるハッシュ読み取りも変更として報告するため、フィルターしないと Linux で自己ループが発生します）。
- **リモート変更** → サーバーが `rescan_hint` として能動的にプッシュします。sync-server は自身のツリーを監視して（`apps/krymux-sync/src/sync/notify.rs`）おり、変更があると接続中のデーモンに即座に通知します — ヒントの到着は秒単位です。ヒントは**同期セッション実行中は抑制されます**（サーバーが受信中のアップロードをエコーバックしないため）。セッション終了時に統合された 1 個のヒントが発火し、これが他のクライアントへの変更伝播も担います。ヒント非対応の古いサーバーでは黙って機能が低下し、インターバルが引き継ぎます。
- **`--interval`**（デフォルト 30 秒）による定期突き合わせは、現在では主機構ではなく**安全網**（失われたヒント / 古いサーバー対策）です。
- **再接続**: トンネル喪失が起きると次のパスが失敗し、1 秒から始まり 60 秒で上限に達する指数バックオフでトンネルを再構築します。
- **どの瞬間でも kill セーフ**: すべての書き込みは tmp+rename を経由し、スキャンは残骸をスキップします。

### マルチクライアントセマンティクス

N 台のクライアントが同じサーバールートを同時に同期できます。あるクライアントの変更は、セッション終了ヒント経由で数秒以内に他のクライアントへブロードキャストされます（インターバルを待つ必要はありません）。同じファイルの並行編集は **mtime による last-writer-wins** に収束します — すべてのエンドポイントが最終的に一致し、混在コンテンツは生じません。

### ロックと起動時の競合（`edge-e2e.sh` の 8 フェーズで検証）

- **ルートの相互排他**: sync-server/sync-client は起動時に `<root>/.sync.lock` に対して排他的な OS ファイルロックを取得します（std 1.89 ネイティブ API: Windows では `LockFileEx`、Unix では `flock`）。同じルートでの 2 つ目のプロセスは即座に拒否され、クラッシュしたプロセスはロックを自動的に解放します — スタールロックの回復は不要です。
- **起動時ロックチェック**: ルート内のいずれかのファイルが他のプロセスによって排他的に保持されていた場合、起動を拒否し、該当ファイルを一覧表示します。
- **実行時のロック**: クライアント側でロックされているファイルはそのパスではスキップされます（未処置のまま）。サーバー側でロックされているか読み取り不能なファイル（スキャン時の読み取り失敗 = ハッシュ `None` を含む）は*判定不能 → このパスはスキップ*として扱われ、競合に誤分類されることは決してありません。
- **クラッシュ残骸**: どの瞬間の `kill -9` も安全です（tmp+rename のアトミック性。500 MB で E2E 検証済み、破断なし）。1 時間以上前の古い `*.sync-tmp` ファイルは起動時にクリーンアップされます。
- **単点障害の隔離**: 配置できないファイル（例: ディレクトリプレースホルダ）が 1 つあっても、パスの残りを止めることなくスキップされます。ダウンロード検証（サイズ/ハッシュ）の失敗はパス内で 1 回再試行されます。
- **検証境界**: ファイルロックのエンドツーエンド経路は Windows で検証済みです（実際の共有違反）。非特権 Linux コンテナでは書き込み不能ファイルをシミュレートできません（root は chmod を無視、chattr には `CAP_LINUX_IMMUTABLE` が必要）ので、Linux 側は 2 プロセスでの `flock` 排他と kill & 復活によって検証しています。

### クロス OS 相互運用性（Windows ↔ Linux、LXD プロキシでシミュレートしたリレー経由で検証）

- **接続層**: 複数アドレス解決を順次試行し、**アドレスごとに独立した 5 秒のタイムアウト**を適用します — 複数の A/AAAA レコードを持つ mDNS/DNS 名が、IPv6 がブラックホール化されているときに接続予算を使い果たすことがなくなります（`myhost.local` が 3×IPv6 + 2×IPv4 を返し、ブラックホール化した IPv6 が確実なタイムアウトを引き起こす事例を観測）。
- **ファイル名**: UTF-8（中国語のファイル名 + 内容）が双方向でロスレス。**Windows で不正な名前**（`<>:"|?*`、`CON`/`COM1` のような予約名、末尾のドット/スペース）は警告付きでスキップされます。**大文字小文字の衝突**（Linux で `Foo.txt` + `foo.txt`）はすべてのプラットフォームで警告し、大文字小文字を区別しないプラットフォームでは最初に見つかった名前のみを同期します（ダウンロードが永遠に上書きを繰り返すフリップフロップを防止）。ロングパスも動作します（Windows `\\?\` プレフィックス、212 文字で検証済み）。
- **シンボリックリンク**: `lstat` セマンティクスによりスキップされます（追跡しない、伝播しない、循環リスクなし）。
- **ファイルシステム間の mtime**: NTFS↔ext4 のラウンドトリップはハッシュ短絡により安定します（同一内容 = no-op）。
- **境界**: macOS（FSEvents ウォッチャー）は一度もビルド・実行されていません — 未検証です。

### 削除伝播（トゥームストーン）

削除は全クライアントへ伝播します（`.sync-tombstones.json`、30 日期限、時計オフセット補正付き mtime last-writer-wins、readonly 双方向抑止）。削除後に別拠点で編集された場合は新しい内容が勝ちます。`deletion-semantics-probe.sh` が双方向の非復活を検証します。注：性能・ベンチマーク数値は英語版および `bench/BASELINE.md` を正としてください。

## ブラウザ（WebSocket）アクセス

サーバーは**同一の TLS ポート**で 3 種類の接続を、検出によるデュアルモードで扱います: ネイティブ mTLS クライアント（Ed25519 証明書 + ALPN `krymux`）と、クライアント証明書を持たないすべての接続（そこでは HTTP `GET` が WebSocket/静的パスへ分岐）。frp は TCP の暗号文を転送し続けるだけです — 追加設定は不要です。

1. サーバーを起動します。ブラウザ用アイデンティティ（`ws-p256.key.pem`、P-256）が自動生成され、その `wsFingerprint` がログに出力されます。
2. ブラウザで `https://<frps-public-port>/` を開きます（自己署名証明書の例外を一度だけ受け入れてください）— 内蔵ランチャーページが読み込まれます。
3. ページに表示されたアイデンティティフィンガープリントをサーバーの `auth.fingerprints` に追加します — ネイティブクライアントが使うのと**同じホワイトリスト**です。
4. 再読み込みし、対象の `host:port` を入力して接続します — ルーティングされたサービスならどれでもブラウザタブから到達できます。

認証は強度において mTLS と等価です。1 つの `sha256(SPKI)` ホワイトリストに Ed25519（ネイティブ）と P-256（ブラウザ）のエントリが混在し、クライアントのアプリケーション層署名がホワイトリスト上のアイデンティティを証明し、サーバーの署名がピン留めされたアイデンティティ（TLS 内）を証明します。Rust サーバーは 10 秒の認証タイムアウトと 256 接続の同時 WS 上限を強制します。SDK は依存ゼロの単一ファイル ESM です（`ectun-browser.mjs`、このリポジトリの `browser/ectun-browser.mjs` として同梱 — サーブしても import しても使えます。ワイヤープロトコルは同一です）:

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

SDK v1 は `none` 圧縮を通知します（CMPX ネゴシエーションは将来のアップグレードに備えて準備済み）。プロトコル詳細: [`../ectun/docs/PROTOCOL.md` §6A](../ectun/docs/PROTOCOL.md)。

## 検証

```bash
bash e2e-sync-test.sh   # file sync: 9-phase main flow
bash edge-e2e.sh        # file sync: 8 edge phases (locks / crash / conflicts)
```

- Node リファレンスに対する**相互運用 11/11**（`interop/test-interop.mjs`）:
  - Node クライアント → Rust サーバー: none/deflate/brotli の 1 MB エコーがバイト同一、デュアル vhost ルーティング、非ルーティングターゲットの拒否、ホワイトリスト外の鍵の拒否。
  - Rust クライアント → Rust サーバー: SOCKS5 + vhost（curl で実施）。
  - Rust クライアント → Node サーバー: none/deflate/brotli の 1 MB エコーがバイト同一。
- **フィンガープリント相互運用**: Node の `fingerprint` コマンドは Rust keygen の証明書に同じ値を算出し、その逆も同様です。
- **LXC デプロイテンプレート**: [`deploy/lxc/`](deploy/lxc/) に 2 コンテナ構成 — server / sync-server / sync-client 用の `server.json` / `client.json` / systemd ユニット。実機での結果: 100 MB 転送で md5 同一、クライアント間伝播は約 2 秒、rescan ヒント配信は約 1 秒。

## パフォーマンス

ループバックベンチマーク（Node の数値は Node リファレンス、Node 24.15、[`../ectun/docs/BENCHMARKS.md`](../ectun/docs/BENCHMARKS.md) 参照。Rust の数値は `examples/bench`、16 MB エコー）:

| 構成 | スループット |
|---|---|
| Rust、16 MB エコー、圧縮なし | ~405 MB/s |
| Rust、16 MB エコー、zstd（圧縮可能なテキスト） | ~739 MB/s |
| Node リファレンス、圧縮なし（×1/×4 ストリーム） | ~80 MB/s（シングルコア JS の上限） |
| Node リファレンス、zstd ×4 ストリーム（テキスト） | ~319 MB/s |
| Node リファレンス、brotli ×4 ストリーム（テキスト） | ~285 MB/s |
| **ウィンドウ自動拡大、単一ストリーム @ 50 ms RTT** | **4.0 → 32.4 MB/s**（固定 256 KB → 最大 4 MB まで自動） |
| TCP リレー経由（frp をシミュレート） | 測定可能なペナルティなし |
| ストリームオープンレイテンシ | p50 0.28 ms（確立済み接続内） |
| TLS フルハンドシェイク | ~6 ms（ループバック） |

圧縮はしばしばスループットを*引き上げます*（ワイヤー上のバイト数が減るため）。実 frp リンクでのウィンドウボトルネックは自動拡大によって解消され、残る律速は公開帯域幅と圧縮 CPU です。

## 設定リファレンス

camelCase キーの JSON で、スキーマは両実装で同一です。

### server.json

| フィールド | 型 | デフォルト | 説明 |
|---|---|---|---|
| `listen` | string | *必須* | リッスンする `host:port`。frpc の `localPort` はここを指す |
| `identity.key`, `identity.cert` | string | *必須* | `keygen` が生成する Ed25519 PEM のパス |
| `auth.mode` | string | `"whitelist"` | アドミッションモード |
| `auth.fingerprints` | string[] | `[]` | `sha256(SPKI)` クライアントホワイトリスト（`auth.clients` のエントリもマージされる） |
| `routes[].host`（エイリアス `hosts`） | string または string[] | — | vhost のマッチキー。`*.example` のようなワイルドカード可 |
| `routes[].port`（エイリアス `ports`） | number、`"n"`、`"a-b"`、`"*"`、または配列 | — | ルートのオプションのポートパターン |
| `routes[].upstream` | `[host, port]`、`"host:port"`、`"unix:/path"`、または `{host, port}` / `{unix}` | — | マッチしたトラフィックの配送先 |
| `fallbackUpstream`（エイリアス `defaultUpstream`） | upstream | — | どのルートにもマッチしないホスト向けのルート |
| `clientTargets.enabled` | bool | `false` | クライアントによる任意の `host:port` ターゲット指定を許可 |
| `clientTargets.allowHosts` | string[] | `["*"]` | クライアントが選択可能なホストパターン |
| `clientTargets.allowPorts` | pattern[] | — | クライアントが選択可能なポートパターン |
| `keepaliveSec` | integer | `30` | キープアライブ間隔 |
| `maxStreams` | integer | `1024` | 接続あたりの最大論理ストリーム数 |
| `rxWindow` | integer | `262144`（256 KB） | ストリームごとの初期受信ウィンドウ |
| `rxWindowMax` | integer | `4194304`（4 MB） | 自動拡大の上限。`rxWindow` と同値にすると拡大を無効化 |
| `log.level` | string | `"info"` | ログレベル |
| `statsIntervalMs` | integer | — | 統計の定期出力 |

### client.json

| フィールド | 型 | デフォルト | 説明 |
|---|---|---|---|
| `endpoint` | string | *必須* | frps が公開する `host:port` |
| `identity.key`, `identity.cert` | string | *必須* | クライアントの Ed25519 PEM パス |
| `serverFingerprint` | string | *必須* | ピン留めするサーバーフィンガープリント `sha256:…` |
| `compression` | string | `"auto"` | `none` / `auto` / `deflate` / `brotli` / `zstd`（zstd ビルド）、または `"zstd:9"`、`"brotli:11"`、`"deflate:9"` のようなレベルプリセット（送信側に適用） |
| `keepaliveSec` | integer | `30` | キープアライブ間隔 |
| `rxWindow` | integer | `262144`（256 KB） | ストリームごとの初期受信ウィンドウ（両端で設定可能） |
| `rxWindowMax` | integer | `4194304`（4 MB） | 自動拡大の上限 |
| `socks5` | string | — | ローカル SOCKS5 フロントエンドのアドレス（例: `127.0.0.1:1080`） |
| `httpProxy` | string | — | ローカル HTTP/1.1 プロキシフロントエンド（CONNECT + absolute-form） |
| `log.level` | string | `"info"` | ログレベル |

ウィンドウ自動拡大: ストリームがウィンドウの半分超を消費してそれを払い出した（drain した）とき、付与量は 100 ms ごとに倍増します。バックプレッシャー中のストリームは拡大しません。`rxWindow`/`rxWindowMax` は両端で設定でき、`rxWindowMax = rxWindow` で拡大を無効化します。

## トラブルシューティング

- デバッグロギングには `KRYMUX_LOG=debug`。
- stderr へのフレームレベルトレース（フラグを含む）には `KRYMUX_MUX_TRACE=1`。

## ロードマップ

- **削除の伝播**（トゥームストーン: 期限ベースのクリーンアップ付き `.sync-tombstones` ディレクトリ）。
- **zstd 辞書（`zstdd`）** — 設計確定済み: オフラインの `zstd --train`、両側が同一の辞書を参照、辞書フィンガープリントのサフィックス照合付きの `zstdd` HELLO 圧縮ネゴシエーション。短いストリーム（HTTP/API）の先頭パケットが 2〜4 倍小さくなる見込み。Node 側にはネイティブバインディング、またはネゴシエーションによるプレーン zstd へのフォールバックが必要。
- 固定レートのカバートラフィック付き **PAD フレーム長バケッティング**（プロトコル v1.1 で予約済み）。
- **クラスター / マルチコア**のスループット。
- **UDP** サポート。
- **Go / Python SDK**。
- WS 認証への **Noise 型鍵導出**。
- **macOS** のビルドと検証（FSEvents ウォッチャー）。

## ライセンス

MIT
