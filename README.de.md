# Krymux

Sicherer Dienstzugriff über Reverse-Tunnel.

**English** | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | **Deutsch** | [Français](README.fr.md) | [Español](README.es.md)
> Das SDK ist multilingual in einem Repo: Rust-Referenzimplementierung (crates/krymux) + TypeScript / Go / Python (sdks/) — alle drahtkompatibel und durch Interop-Tests gegen die Rust-Binaries abgedeckt.
> Tests & CI: drei parallele Jobs pro Commit — Coverage (Rust-Gate 55 %, Go/Python/TS zusammengefasst), Linux-Integration (parametrisierte Edge-Matrix mit 54 Kombinationen + SDK-Interop je Sprache + sprachübergreifende Matrix), Windows-Voll-E2E. Details im englischen Abschnitt Testing & CI.

`krymux` macht lokale Dienste über ein unverschlüsseltes TCP-Relay wie frp im Internet erreichbar — Relays, die weder Ende-zu-Ende-Verschlüsselung noch Zugriffskontrolle pro Client bieten. Auf der Dienstmaschine betreibt es einen Reverse-Proxy und baut zum Client einen **gegenseitig authentifizierten, verschlüsselten TLS-1.3-Tunnel** auf (frp sieht ausschließlich Chiffrat). Im Tunnel liegt ein **multiplexierter Verbund logischer Streams** mit **Kompression pro Stream**, **Credit-basierter Flusssteuerung**, **Half-Close** und **Keepalive**. Das Vertrauensmodell ist WireGuard/SSH-artig: Der Server hält eine Whitelist aus **Ed25519-Public-Key-Fingerabdrücken** der Clients (`sha256(SPKI)`), und der Client **pinnt den Fingerabdruck des Servers**, um Man-in-the-Middle-Angriffe abzuwehren.

Dieses Repository ist die **Rust-Implementierung**: ein einzelnes, rund 5,3 MB großes statisches Binary, das sämtliche Anwendungen enthält (Dateisynchronisation, WebSocket-Browser-Zugriff, SOCKS5/HTTP-Frontends). Sie ist **wire-protokollkompatibel mit der Node-Referenzimplementierung** ([`../ectun`](../ectun)) — dasselbe Ed25519-Fingerabdruck-Identitätssystem, dasselbe JSON-Konfigurationsschema, beide Enden frei austauschbar und im Kreuzvergleich gebenchmarkt.

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

## Funktionen

- **Ende-zu-Ende-Verschlüsselung** — ausschließlich TLS 1.3 (ALPN `krymux`), Ed25519-Zertifikate, AES-GCM/ChaCha20-Poly1305; die frp-Verbindung trägt nichts als Chiffrat.
- **Public-Key-Whitelist** — der `sha256(SPKI)`-Fingerabdruck *ist* die Identität; fail-closed-Zulassung nach dem Handshake. Der Client pinnt den Server-Fingerabdruck.
- **Multiplexing** — hunderte logische Vollduplex-Streams über eine einzige TLS-Verbindung (ein Browser, der 50 Verbindungen öffnet = 1 Handshake).
- **Kompression pro Stream** — `deflate` / `brotli` / `zstd` mit fortlaufenden Kontexten und Streaming-Flush; `none` als Durchreichemodus; `auto`-Aushandlung. Level-Presets wie `"zstd:9"`, `"brotli:11"`, `"deflate:9"`.
- **Magic-Byte-Bypass** — Sniffing des ersten Chunks erkennt bereits komprimierte Inhalte (gzip/zstd/zip/png/jpeg/7z/rar/pdf/bzip2/mp4) und schaltet diesen Stream automatisch auf `none` um (spart CPU, vermeidet Aufblähung).
- **Credit-basierte Flusssteuerung** — Fenster pro Stream, abgerechnet auf *dekomprimierten* Bytes; langsame Konsumenten können weder Speicher erschöpfen noch andere Streams aushungern lassen. Das dynamische Fenster-Autowachstum verdoppelt den Grant alle 100 ms, solange ein Stream abfließt: 4 → 32,4 MB/s auf einem einzelnen Stream bei 50 ms RTT (vom alten festen 256-KB-Fenster bis zur 4-MB-Obergrenze).
- **Protokolltransparenz** — TCP-Byte-Stream-Semantik unter Wahrung des Half-Close; HTTP/WebSocket/SSH/Datenbankprotokolle werden unverändert durchgereicht.
- **vhost-Routing** — der Client nennt einen Hostnamen; der Server leitet nach Host / Port / Fallback / clientseitig gewähltem Ziel an verschiedene Upstreams weiter.
- **Browser-Zugriff (WebSocket)** — `wss://` mit P-256-Signaturauthentifizierung auf Anwendungsschicht, die dieselbe Fingerabdruck-Whitelist nutzt; eingebaute Launcher-Seite; Browser-SDK ohne Abhängigkeiten.
- **Bidirektionale Dateisynchronisation** — SHA-1-Hash-Diff, Ausgleich des mtime-Uhrzeitversatzes, atomare Schreibvorgänge, Lock-Erkennung, Watch-Daemon mit vom Server gepushten Änderungs-Hints.
- **Post-Quantum-Build** — `--features pq` (aws-lc-rs-Backend) handelt den hybriden KEM X25519MLKEM768 aus.
- **Ein einzelnes Binary, keine Laufzeitabhängigkeiten** — die Abhängigkeitskette des Basis-Builds ist reines Rust.

## Architektur-Einordnung
> Repo-Layout: Krymux ist ein SDK (`crates/krymux`, reine Bibliothek); Anwendungen bauen darauf auf — `krymux-tunnel` (Tunnel-Operations-CLI), `krymux-sync` (Dateisynchronisation), `browser/` (Browser-JS-SDK).

**Das Protokoll-SDK bleibt mehrsprachig; die Anwendungen bleiben auf Rust beschränkt.**

- Das Protokoll-SDK (Frames / Multiplexing / TLS / Kompression) behält zwei Implementierungen bei — Node (Referenz) und Rust — als gegenseitige Regressionsbaselines; Go und Python sind geplant.
- Anwendungen der höheren Ebene (Dateisynchronisation, WS-Frontend-Erweiterungen, …) werden **ausschließlich in Rust** implementiert, um die Wartungsfläche klein zu halten.
- Das Node-Paket ist als **reine Protokollreferenz** positioniert (ohne Anwendungen); im Produktionseinsatz läuft dieses Rust-Binary.

### Implementierungshinweise (Rust)

- **TLS**: rustls (ring-Backend), ausschließlich TLS 1.3, ALPN `krymux`. Der Server verlangt ein Client-Zertifikat eines beliebigen Ausstellers und lässt die Verbindung anschließend anhand der `sha256(SPKI)`-Whitelist zu (fail-closed). Der Client pinnt den Server-Fingerabdruck. Zertifikate werden von rcgen erzeugt (Ed25519).
- **Multiplexing**: dasselbe Frame-Format wie in der Node-Version (siehe [`../ectun/docs/PROTOCOL.md`](../ectun/docs/PROTOCOL.md)) — Credit-Flusssteuerung pro Stream (abgerechnet auf dekomprimierten Bytes), fortlaufende Kompressionskontexte, Half-Close-Weitergabe.
- **Task-Modell**: zwei Tasks pro Verbindung (Reader/Writer) + Inbound-/Outbound-Pumps je Stream + Credit-Ticker + Keepalive; die Daten erreichen die Anwendung über Tokio-Duplexe. Tunnel-Sockets setzen `TCP_NODELAY`.
- **Kompression**: `deflate` (flate2), `brotli` (brotli-Crate, Low-Level-Push-API), `zstd` (optionales Feature). Die Brotli-Dekompression verwendet die Low-Level-API `BrotliDecompressStream` — `DecompressorWriter` parkt die Ausgabe in einem internen Puffer, und dessen Flush treibt die Dekodierung nicht an, sodass bei großen Transfers zwischen den Implementierungen Endbytes verloren gehen; der Low-Level-Pfad vermeidet dies.
- **Behoben (Postmortem archiviert)**: ein EOF-Endblock-Bug, verursacht durch einen `Drop`-Doppelsperr-Selbstdeadlock (eine nicht reentrante std-`Mutex` wurde innerhalb einer `if let`-Bedingung erneut gesperrt — dauerhafte Blockade, `JoinHandle` kehrt nie zurück). Ebenfalls behoben: Die tokio-Schreibhälfte (split) sendete beim Drop kein EOF (explizites `poll_shutdown` + serverseitiges `stream.shutdown()`); außerdem ist dokumentiert, dass die Backpressure-Verklemmung „erst alles schreiben, dann lesen“ auch auf rohem TCP identisch auftritt — das korrekte Muster ist, während des Lesens zu schreiben, was Browser/curl von Natur aus tun.

## Build

```bash
cargo build --release                                # workspace: SDK + both apps, pure-Rust dependency chain
cargo build --release --features krymux/zstd         # + zstd (C compilation verified under MSVC/gcc) — recommended
cargo build --release --features krymux/pq           # + aws-lc-rs post-quantum KEM (~5.7 MB binaries)
cargo build --release --features "krymux/pq krymux/zstd"  # everything
# artifacts: target/release/krymux-tunnel and target/release/krymux-sync — no runtime dependencies
```

Cross-Kompilierung für Linux (Deployment auf einen Server oder nach LXD):

```bash
rustup target add x86_64-unknown-linux-gnu
# with a Linux-side linker: cargo build --release --target x86_64-unknown-linux-gnu
# or use cross / cargo-zigbuild
```

Hinweis: Der Basis-Build bewirbt `none`/`deflate`/`brotli` in der HELLO-Aushandlung; `zstd` erfordert das Feature `zstd`.

## Schnellstart

CLI-Oberfläche (mit demselben Aufbau wie die Node-Version):

| Befehl | Zweck |
|---|---|
| `krymux-tunnel keygen --out <dir> --role server\|client [--name x] [--cn cn]` | Erzeugt eine Ed25519-Identität (Schlüssel + selbstsigniertes Zertifikat + Fingerabdruck) |
| `krymux-tunnel fingerprint <key-or-cert.pem>` | Gibt den Fingerabdruck einer PEM-Datei aus |
| `krymux-tunnel probe <host:port>` | Zeigt den Schlüssel-Fingerabdruck eines Servers (TOFU-Helfer) |
| `krymux-tunnel server --config server.json` | Startet den Reverse-Proxy-Server |
| `krymux-tunnel client --config client.json [--socks5 h:p] [--http-proxy h:p]` | Startet den Client (optional mit lokalen Proxy-Frontends) |
| `krymux-sync sync-server --path <dir> [--port 17890] [--mode bidir\|readonly]` | Startet einen Dateisynchronisations-Server hinter krymux |
| `krymux-sync sync-client --path <dir> --config client.json [--mode …] [--watch] [--interval 30]` | Startet einen Dateisynchronisations-Client durch den Tunnel |

### 1. Identitäten auf beiden Seiten erzeugen

```bash
./target/release/krymux-tunnel keygen --out ./keys --role server
./target/release/krymux-tunnel keygen --out ./keys --role client --name alice
```

Jeder Befehl gibt den `sha256:`-Fingerabdruck der Identität aus.

### 2. (TOFU) Den Server-Fingerabdruck prüfen

Falls Sie den Server-Fingerabdruck noch nicht kennen, verifizieren Sie ihn einmal über einen getrennten Kanal und tragen Sie ihn in die Konfiguration ein:

```bash
./target/release/krymux-tunnel probe frp.example.com:7000
```

### 3. Server-Konfiguration (auf der Dienstmaschine — dies ist der Port, an den frpc weiterleitet)

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

### 4. Client-Konfiguration (an einem beliebigen Ort)

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

### 5. Verwendung

Richten Sie einen Browser oder curl auf den lokalen SOCKS5-Proxy — **der Hostname wird zum vhost-Routing-Schlüssel**:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://nas.example/
```

`--http-proxy 127.0.0.1:8080` stellt stattdessen ein HTTP/1.1-Proxy-Frontend (CONNECT + absolute-form) bereit. Die Konfigurationsfelder entsprechen exakt der Node-Version; vollständige Szenarien finden Sie in [`../ectun/examples/`](../ectun/examples/).

## Dateisynchronisation

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

### Sync-Engine

- **Bidirektional**: Download Server → Client und Upload Client → Server, gesteuert durch **SHA-1-Hash-Vergleich**, **Ausgleich des mtime-Uhrzeitversatzes** zwischen den beiden Maschinen, **atomare Schreibvorgänge** (Tmp-Datei → Umbenennen) und **Lock-Erkennung**.
- **Der Read-only-Modus wird über `hello_ack` ausgehandelt**: Ist der Server read-only, unterdrückt der Client Uploads automatisch; der Server lehnt `put` ungeachtet dessen weiterhin ab.
- **Konfliktberichte** bei gleichzeitigen Bearbeitungen (siehe die Multi-Client-Semantik unten).
- **Path-Traversal-Schutz**: `..`-Segmente, absolute Pfade und Laufwerksbuchstaben werden stets abgelehnt.

### Watch-Daemon (`--watch`, `apps/krymux-sync/src/sync/daemon.rs`)

- **Lokale Änderungen** → Notify-Events mit einer **Debounce-Ruhephase von 700 ms**; `*.sync-tmp` und Lese-Events werden übersprungen (inotify meldet die Hash-Lesezugriffe des eigenen Scans als Änderungen; ungefiltert löst sich das unter Linux selbst in einer Endlosschleife aus).
- **Entfernte Änderungen** → werden vom Server proaktiv gepusht (`rescan_hint`): Der Sync-Server beobachtet seinen eigenen Baum (`apps/krymux-sync/src/sync/notify.rs`) und benachrichtigt verbundene Daemons sofort bei Änderungen — Hints treffen im Sekundenbereich ein. Hints werden **unterdrückt, solange eine Sync-Session aktiv ist** (damit der Server die empfangenen Uploads nicht zurücksendet); am Session-Ende feuert ein zusammengefasster Hint — genau dieser propagiert die Änderungen auch an andere Clients. Alte Server ohne Hint-Unterstützung schalten stillschweigend zurück, und das Intervall übernimmt.
- Die periodische Abstimmung über **`--interval`** (Standard: 30 s) ist inzwischen ein **Sicherheitsnetz** (verlorene Hints / alte Server) statt des primären Mechanismus.
- **Wiederverbindung**: Geht der Tunnel verloren, schlägt der nächste Durchlauf fehl und baut den Tunnel mit exponentiellem Backoff neu auf — beginnend bei 1 s, gedeckelt bei 60 s.
- **Zu jedem Zeitpunkt kill-sicher**: Alle Schreibvorgänge laufen über tmp+rename, und Scans überspringen Überreste.

### Multi-Client-Semantik

N Clients können dieselbe Server-Wurzel gleichzeitig synchronisieren. Die Änderungen eines Clients werden über den Hint am Session-Ende binnen Sekunden an die anderen übertragen (kein Warten auf das Intervall). Gleichzeitige Bearbeitungen derselben Datei konvergieren nach dem Prinzip **Last-Writer-Wins anhand der mtime** — jeder Endpunkt steht am Ende auf demselben Stand, ohne gemischte Inhalte.

### Locks und Startkonflikte (verifiziert durch die 8 Phasen von `edge-e2e.sh`)

- **Gegenseitiger Ausschluss an der Wurzel**: sync-server/sync-client legen beim Start eine exklusive OS-Dateisperre auf `<root>/.sync.lock` (native std-1.89-API: `LockFileEx` unter Windows, `flock` unter Unix). Ein zweiter Prozess auf derselben Wurzel wird rundweg abgewiesen; ein abgestürzter Prozess gibt die Sperre automatisch frei — eine Wiederherstellung veralteter Sperren ist nicht nötig.
- **Sperrprüfung beim Start**: Wird irgendeine Datei in der Wurzel exklusiv von einem anderen Prozess gehalten, wird der Start verweigert und die betroffenen Dateien aufgelistet.
- **Laufzeit-Locks**: Clientseitig gesperrte Dateien werden für den Durchlauf übersprungen (unangetastet). Serverseitig gesperrte oder unlesbare Dateien (einschließlich Lesefehlern beim Scan = Hash `None`) gelten als *nicht bestimmbar → diesen Durchlauf überspringen* und werden nie fälschlich als Konflikte eingestuft.
- **Absturzreste**: `kill -9` ist zu jedem Zeitpunkt sicher (tmp+rename-Atomizität; E2E-getestet mit 500 MB, kein Tearing). Veraltete `*.sync-tmp`-Dateien, die ≥ 1 h alt sind, werden beim Start bereinigt.
- **Isolation von Einzelfehlern**: Eine nicht ablegbare Datei (z. B. ein Verzeichnis-Platzhalter) wird übersprungen, ohne den Rest des Durchlaufs auszuhungern; eine fehlgeschlagene Download-Verifikation (Größe/Hash) wird innerhalb des Durchlaufs einmalig wiederholt.
- **Verifikationsgrenze**: Der Dateisperren-Pfad Ende-zu-Ende ist unter Windows verifiziert (echte Sharing-Violations); unprivilegierte Linux-Container können unbeschreibbare Dateien nicht simulieren (root ignoriert chmod; chattr benötigt `CAP_LINUX_IMMUTABLE`), daher ist die Linux-Seite über `flock`-Ausschluss zwischen zwei Prozessen plus Kill-und-Wiederbeleben verifiziert.

### Betriebssystemübergreifende Kompatibilität (Windows ↔ Linux, getestet über ein mittels LXD-Proxy simuliertes Relay)

- **Connect-Schicht**: Auflösung mehrerer Adressen mit sequenziellen Versuchen und einem **unabhängigen 5-s-Timeout pro Adresse** — mDNS/DNS-Namen mit mehreren A/AAAA-Einträgen zehren das Verbindungsbudget nicht mehr auf, wenn IPv6 geblackholed ist (beobachtet bei `myhost.local` mit 3×IPv6 + 2×IPv4, wo geblackholetes IPv6 garantierte Timeouts verursachte).
- **Dateinamen**: UTF-8 (chinesische Dateinamen + Inhalte) verlustfrei in beide Richtungen; **unter Windows unzulässige Namen** (`<>:"|?*`, reservierte Namen wie `CON`/`COM1`, abschließende Punkte/Leerzeichen) werden mit Warnung übersprungen; **Kollisionen der Groß-/Kleinschreibung** (Linux `Foo.txt` + `foo.txt`) warnen auf jeder Plattform, und Plattformen ohne Unterscheidung der Groß-/Kleinschreibung synchronisieren nur den zuerst gesehenen Namen (das verhindert das ewige Überschreib-Ping-Pong beim Download); lange Pfade funktionieren (Windows-Präfix `\\?\`, getestet bei 212 Zeichen).
- **Symlinks**: gemäß `lstat`-Semantik übersprungen (weder gefolgt noch propagiert, kein Zyklusrisiko).
- **mtime über Dateisysteme hinweg**: NTFS↔ext4-Round-Trips bleiben über den Hash-Kurzschluss stabil (identischer Inhalt = no-op).
- **Grenze**: macOS (FSEvents-Watcher) wurde nie gebaut oder ausgeführt — unverifiziert.

### Lösch-Propagation (Tombstones)

Löschungen propagieren zu allen Clients (`.sync-tombstones.json`, 30 Tage Gültigkeit, um Offset korrigierte mtime last-writer-wins, readonly-Unterdrückung auf beiden Seiten); nach einer Löschung anderswo editierte Dateien gewinnen mit dem neueren Inhalt. `deletion-semantics-probe.sh` verifiziert beidseitig ohne Wiederherstellung. Hinweis: maßgeblich für Leistungs- und Benchmark-Zahlen sind die englische Version und `bench/BASELINE.md`.

## Browser-Zugriff (WebSocket)

Der Server bedient drei Verbindungsarten auf **demselben TLS-Port**, im Dual-Modus per Erkennung: native mTLS-Clients (Ed25519-Zertifikat + ALPN `krymux`) auf der einen Seite, alles ohne Client-Zertifikat auf der anderen, wobei ein HTTP-`GET` in den WebSocket-/Static-Pfad verzweigt. frp leitet weiterhin schlicht TCP-Chiffrat weiter — keine zusätzliche Konfiguration.

1. Starten Sie den Server. Er erzeugt automatisch eine Browser-Identität (`ws-p256.key.pem`, P-256) und loggt deren `wsFingerprint`.
2. Öffnen Sie `https://<frps-public-port>/` in einem Browser (akzeptieren Sie die Ausnahme für das selbstsignierte Zertifikat einmalig) — die eingebaute Launcher-Seite wird geladen.
3. Fügen Sie den auf der Seite angezeigten Identitäts-Fingerabdruck zur `auth.fingerprints`-Whitelist des Servers hinzu — **dieselbe Whitelist**, die auch native Clients verwenden.
4. Laden Sie die Seite neu, geben Sie ein Ziel-`host:port` ein und verbinden Sie sich — jeder geroutete Dienst ist aus dem Browser-Tab erreichbar.

Die Authentifizierung ist im Sicherheitsniveau äquivalent zu mTLS: Eine einzige `sha256(SPKI)`-Whitelist mischt Ed25519-Einträge (nativ) und P-256-Einträge (Browser); die Signatur des Clients auf Anwendungsschicht beweist die Whitelist-Identität, die Signatur des Servers beweist die gepinnte Identität (innerhalb von TLS). Der Rust-Server erzwingt ein Auth-Timeout von 10 s und eine Obergrenze von 256 gleichzeitigen WS-Verbindungen. Das SDK ist eine einzelne ESM-Datei ohne Abhängigkeiten (`ectun-browser.mjs`, in diesem Repository unter `browser/ectun-browser.mjs` mitgeliefert — liefern Sie sie aus oder importieren Sie sie; das Wire-Protokoll ist identisch):

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

SDK v1 bewirbt die Kompression `none` (die CMPX-Aushandlung ist für künftige Upgrades bereit). Protokolldetails: [`../ectun/docs/PROTOCOL.md` §6A](../ectun/docs/PROTOCOL.md).

## Verifikation

```bash
bash e2e-sync-test.sh   # file sync: 9-phase main flow
bash edge-e2e.sh        # file sync: 8 edge phases (locks / crash / conflicts)
```

- **Interop 11/11** gegen die Node-Referenz (`interop/test-interop.mjs`):
  - Node-Client → Rust-Server: none/deflate/brotli 1-MB-Echo byte-identisch, Dual-Vhost-Routing, nicht geroutetes Ziel abgelehnt, nicht gelisteter Schlüssel abgelehnt;
  - Rust-Client → Rust-Server: SOCKS5 + vhost (mit curl erprobt);
  - Rust-Client → Node-Server: none/deflate/brotli 1-MB-Echo byte-identisch.
- **Fingerabdruck-Interoperabilität**: Der Node-Befehl `fingerprint` berechnet für Rust-keygen-Zertifikate denselben Wert — und umgekehrt.
- **LXC-Deployment-Vorlage**: Zwei-Container-Setup in [`deploy/lxc/`](deploy/lxc/) — `server.json` / `client.json` / systemd-Units für server, sync-server und sync-client(s). Dortige Ergebnisse auf realer Maschine: 100 MB übertragen und md5-identisch, clientübergreifende Propagation in ~2 s, rescan-hint-Zustellung in ~1 s.

## Performance

Loopback-Benchmarks (Node-Zahlen aus der Node-Referenz, Node 24.15, siehe [`../ectun/docs/BENCHMARKS.md`](../ectun/docs/BENCHMARKS.md); Rust-Zahlen aus `examples/bench`, 16-MB-Echo):

| Konfiguration | Durchsatz |
|---|---|
| Rust, 16-MB-Echo, ohne Kompression | ~405 MB/s |
| Rust, 16-MB-Echo, zstd (komprimierbarer Text) | ~739 MB/s |
| Node-Referenz, ohne Kompression (×1/×4 Streams) | ~80 MB/s (Single-Core-JS-Decke) |
| Node-Referenz, zstd ×4 Streams (Text) | ~319 MB/s |
| Node-Referenz, brotli ×4 Streams (Text) | ~285 MB/s |
| **Fenster-Autowachstum, einzelner Stream @ 50 ms RTT** | **4,0 → 32,4 MB/s** (fest 256 KB → automatisch bis 4 MB) |
| Durch ein TCP-Relay (frp simuliert) | kein messbarer Verlust |
| Stream-Open-Latenz | p50 0,28 ms (innerhalb einer bestehenden Verbindung) |
| Vollständiger TLS-Handshake | ~6 ms (Loopback) |

Kompression *erhöht* den Durchsatz oft (weniger Bytes auf der Leitung); der Fenster-Flaschenhals auf echten frp-Verbindungen wird durch das Autowachstum beseitigt — als Grenzen bleiben die öffentliche Bandbreite und die Kompressions-CPU.

## Konfigurationsreferenz

JSON mit camelCase-Schlüsseln, identisches Schema in beiden Implementierungen.

### server.json

| Feld | Typ | Standard | Beschreibung |
|---|---|---|---|
| `listen` | string | *erforderlich* | `host:port`, auf dem gelauscht wird; `localPort` von frpc zeigt hierhin |
| `identity.key`, `identity.cert` | string | *erforderlich* | Ed25519-PEM-Pfade aus `keygen` |
| `auth.mode` | string | `"whitelist"` | Zulassungsmodus |
| `auth.fingerprints` | string[] | `[]` | `sha256(SPKI)`-Client-Whitelist (Einträge aus `auth.clients` werden zusammengeführt) |
| `routes[].host` (Alias `hosts`) | string oder string[] | — | vhost-Abgleichsschlüssel; Wildcards wie `*.example` |
| `routes[].port` (Alias `ports`) | number, `"n"`, `"a-b"`, `"*"` oder Array | — | optionales Port-Muster für die Route |
| `routes[].upstream` | `[host, port]`, `"host:port"`, `"unix:/path"` oder `{host, port}` / `{unix}` | — | wohin abgeglichener Traffic ausgeliefert wird |
| `fallbackUpstream` (Alias `defaultUpstream`) | upstream | — | Route für Hosts, die auf keine Route passen |
| `clientTargets.enabled` | bool | `false` | erlaubt Clients, beliebige `host:port`-Ziele anzugeben |
| `clientTargets.allowHosts` | string[] | `["*"]` | Host-Muster, die ein Client wählen darf |
| `clientTargets.allowPorts` | pattern[] | — | Port-Muster, die ein Client wählen darf |
| `keepaliveSec` | integer | `30` | Keepalive-Intervall |
| `maxStreams` | integer | `1024` | maximale Anzahl logischer Streams pro Verbindung |
| `rxWindow` | integer | `262144` (256 KB) | anfängliches Empfangsfenster pro Stream |
| `rxWindowMax` | integer | `4194304` (4 MB) | Obergrenze des Autowachstums; auf denselben Wert wie `rxWindow` setzen, um das Wachstum zu deaktivieren |
| `log.level` | string | `"info"` | Log-Level |
| `statsIntervalMs` | integer | — | periodische Ausgabe von Statistiken |

### client.json

| Feld | Typ | Standard | Beschreibung |
|---|---|---|---|
| `endpoint` | string | *erforderlich* | öffentlicher `host:port`, den frps bereitstellt |
| `identity.key`, `identity.cert` | string | *erforderlich* | Ed25519-PEM-Pfade des Clients |
| `serverFingerprint` | string | *erforderlich* | gepinnter Server-Fingerabdruck `sha256:…` |
| `compression` | string | `"auto"` | `none` / `auto` / `deflate` / `brotli` / `zstd` (zstd-Build) oder Level-Presets wie `"zstd:9"`, `"brotli:11"`, `"deflate:9"` (gilt für die sendende Seite) |
| `keepaliveSec` | integer | `30` | Keepalive-Intervall |
| `rxWindow` | integer | `262144` (256 KB) | anfängliches Empfangsfenster pro Stream (an beiden Enden einstellbar) |
| `rxWindowMax` | integer | `4194304` (4 MB) | Obergrenze des Autowachstums |
| `socks5` | string | — | lokale Adresse des SOCKS5-Frontends, z. B. `127.0.0.1:1080` |
| `httpProxy` | string | — | lokales HTTP/1.1-Proxy-Frontend (CONNECT + absolute-form) |
| `log.level` | string | `"info"` | Log-Level |

Fenster-Autowachstum: Wenn ein Stream mehr als die Hälfte seines Fensters verbraucht und es anschließend geleert hat, verdoppelt sich der Grant alle 100 ms; Streams unter Backpressure wachsen nicht. Beide Enden können `rxWindow`/`rxWindowMax` konfigurieren; `rxWindowMax = rxWindow` deaktiviert das Wachstum.

## Fehlerbehebung

- `KRYMUX_LOG=debug` für Debug-Logging.
- `KRYMUX_MUX_TRACE=1` für Frame-Level-Tracing auf stderr (einschließlich der Flags).

## Roadmap

- **Lösch-Propagation** (Tombstones: ein Verzeichnis `.sync-tombstones` mit ablaufbasierter Bereinigung).
- **zstd-Wörterbücher (`zstdd`)** — Design finalisiert: Offline-`zstd --train`, beide Seiten referenzieren dasselbe Wörterbuch, HELLO-Kompressionsaushandlung von `zstdd` mit Suffix-Prüfung des Wörterbuch-Fingerabdrucks; erwartete 2–4× kleinere erste Pakete bei kurzen Streams (HTTP/API). Die Node-Seite benötigt ein natives Binding oder einen ausgehandelten Fallback auf einfaches zstd.
- **Längen-Bucketing von PAD-Frames** mit Cover-Traffic fester Rate (in Protokoll v1.1 reserviert).
- Durchsatz für **Cluster / Multi-Core**.
- **UDP**-Unterstützung.
- **Go-/Python-SDKs**.
- **Noise-artige Schlüsselableitung** für die WS-Authentifizierung.
- **macOS**-Build & -Verifikation (FSEvents-Watcher).

## Lizenz

MIT
