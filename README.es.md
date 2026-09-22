# Krymux

Acceso seguro a servicios a través de túneles inversos.

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [Deutsch](README.de.md) | [Français](README.fr.md) | **Español**
> El SDK es multilenguaje en un solo repo: implementación de referencia en Rust (crates/krymux) + TypeScript / Go / Python (sdks/) — todos compatibles a nivel de cable y cubiertos por pruebas de interoperabilidad contra los binarios Rust.
> Pruebas y CI: tres jobs paralelos por commit — cobertura (umbral Rust 55 %, Go/Python/TS agregados), integración Linux (matriz de bordes parametrizada de 54 combinaciones + interop por lenguaje + matriz inter-lenguajes), E2E completa en Windows. Detalles en la sección Testing & CI de la versión en inglés.

`krymux` expone servicios locales a internet a través de un relé TCP en texto plano como frp — relés que no proporcionan cifrado de extremo a extremo ni control de acceso por cliente. Ejecuta un proxy inverso en la máquina del servicio y establece un **túnel cifrado TLS 1.3 con autenticación mutua** hacia el cliente (frp solo ve texto cifrado). Dentro del túnel hay un **conjunto multiplexado de streams lógicos** con **compresión por stream**, **control de flujo basado en créditos**, **half-close** y **keepalive**. El modelo de confianza sigue el patrón de WireGuard/SSH: el servidor mantiene una lista blanca de **huellas de claves públicas Ed25519** de los clientes (`sha256(SPKI)`), y el cliente **fija (pin) la huella del servidor** frente a ataques man-in-the-middle.

Este repositorio es la **implementación en Rust**: un único binario estático de ~5,3 MB que contiene todas las aplicaciones (sincronización de archivos, acceso WebSocket desde el navegador, frontends SOCKS5/HTTP). Es **compatible a nivel de protocolo de cable con la implementación de referencia en Node** ([`../ectun`](../ectun)) — mismo sistema de identidad por huellas Ed25519, mismo esquema de configuración JSON, con ambos extremos libremente intercambiables y comparados en benchmarks cruzados.

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

## Características

- **Cifrado de extremo a extremo** — solo TLS 1.3 (ALPN `krymux`), certificados Ed25519, AES-GCM/ChaCha20-Poly1305; el enlace frp transporta únicamente texto cifrado.
- **Lista blanca de claves públicas** — la huella `sha256(SPKI)` *es* la identidad; admisión con fallo cerrado (fail-closed) tras el handshake. El cliente fija (pin) la huella del servidor.
- **Multiplexación** — cientos de streams lógicos full-dúplex sobre una única conexión TLS (un navegador que abre 50 conexiones = 1 handshake).
- **Compresión por stream** — `deflate` / `brotli` / `zstd` con contextos continuos y vaciado en streaming; `none` deja pasar los datos sin tocarlos; negociación `auto`. Preajustes de nivel como `"zstd:9"`, `"brotli:11"`, `"deflate:9"`.
- **Omisión por magic bytes** — la inspección del primer chunk detecta contenido ya comprimido (gzip/zstd/zip/png/jpeg/7z/rar/pdf/bzip2/mp4) y conmuta automáticamente ese stream a `none` (ahorra CPU, evita la expansión).
- **Control de flujo basado en créditos** — ventanas por stream contabilizadas en bytes *descomprimidos*; los consumidores lentos no pueden agotar la memoria ni dejar sin servicio a otros streams. El crecimiento automático de ventana dinámica duplica la concesión cada 100 ms mientras un stream se drena: 4 → 32,4 MB/s en un solo stream con 50 ms de RTT (desde la antigua ventana fija de 256 KB hasta el tope de 4 MB).
- **Transparencia de protocolo** — semántica de flujo de bytes TCP con half-close preservado; los protocolos HTTP/WebSocket/SSH/de bases de datos pasan literalmente sin modificar.
- **Enrutado por vhost** — el cliente nombra un hostname; el servidor enruta por host / puerto / fallback / objetivo elegido por el cliente hacia diferentes upstreams.
- **Acceso desde el navegador (WebSocket)** — `wss://` con autenticación por firma P-256 en la capa de aplicación que comparte la misma lista blanca de huellas; página de lanzamiento integrada; SDK para navegador sin dependencias.
- **Sincronización bidireccional de archivos** — diff por hash SHA-1, alineación del desfase de reloj de mtime, escrituras atómicas, detección de bloqueos, daemon de watch con hints de cambios enviados por el servidor.
- **Compilación postcuántica** — `--features pq` (backend aws-lc-rs) negocia el KEM híbrido X25519MLKEM768.
- **Un único binario, sin dependencias en tiempo de ejecución** — cadena de dependencias puramente Rust en la compilación base.

## Posicionamiento de la arquitectura

> Estructura del repositorio: Krymux es un SDK (`crates/krymux`, biblioteca pura); las aplicaciones se construyen sobre él — `krymux-tunnel` (CLI de operaciones del túnel), `krymux-sync` (sincronización de archivos), `browser/` (SDK JS del navegador).

**El SDK del protocolo sigue siendo multilenguaje; las aplicaciones son exclusivamente en Rust.**

- El SDK del protocolo (tramas / multiplexación / TLS / compresión) mantiene dos implementaciones — Node (referencia) y Rust — como líneas base de regresión mutuas; Go y Python están previstos.
- Las aplicaciones de nivel superior (sincronización de archivos, extensiones del frontend WS, …) se implementan **solo en Rust** para mantener pequeña la superficie de mantenimiento.
- El paquete de Node se posiciona como una **referencia pura del protocolo** (sin aplicaciones); el despliegue en producción usa este binario de Rust.

### Notas de implementación (Rust)

- **TLS**: rustls (backend ring), solo TLS 1.3, ALPN `krymux`. El servidor exige un certificado de cliente de cualquier emisor y luego admite la conexión contra la lista blanca `sha256(SPKI)` (fail-closed). El cliente fija la huella del servidor. Los certificados los genera rcgen (Ed25519).
- **Multiplexación**: el mismo formato de tramas que la versión de Node (véase [`../ectun/docs/PROTOCOL.md`](../ectun/docs/PROTOCOL.md)) — control de flujo por créditos por stream (contabilizado en bytes descomprimidos), contextos de compresión continuos, propagación del half-close.
- **Modelo de tareas**: dos tareas por conexión (lector/escritor) + bombas de entrada/salida por stream + ticker de créditos + keepalive; los datos llegan a la aplicación mediante dúplex de tokio. Los sockets del túnel activan `TCP_NODELAY`.
- **Compresión**: `deflate` (flate2), `brotli` (crate brotli, API push de bajo nivel), `zstd` (característica opcional). La descompresión con Brotli usa la API de bajo nivel `BrotliDecompressStream` — `DecompressorWriter` estaciona la salida en un búfer interno y su flush no impulsa la decodificación, lo que pierde bytes finales en transferencias grandes entre implementaciones; la ruta de bajo nivel evita esto.
- **Corregido (postmortem archivado)**: un bug de bytes finales de EOF causado por un autointerbloqueo por doble bloqueo en `Drop` (un `Mutex` de std no reentrante bloqueado de nuevo dentro de un predicado `if let` — bloqueo permanente, el `JoinHandle` nunca retorna). También corregido: la mitad de escritura del split de tokio no enviaba EOF al hacer drop (`poll_shutdown` explícito + `stream.shutdown()` del lado del servidor), y se documentó que la contrapresión del patrón "escribir todo y luego leer" interbloquea de forma idéntica sobre TCP en bruto — el patrón correcto es escribir mientras se lee, algo que navegadores/curl hacen de forma natural.

## Compilación

```bash
cargo build --release                                # workspace: SDK + both apps, pure-Rust dependency chain
cargo build --release --features krymux/zstd         # + zstd (C compilation verified under MSVC/gcc) — recommended
cargo build --release --features krymux/pq           # + aws-lc-rs post-quantum KEM (~5.7 MB binaries)
cargo build --release --features "krymux/pq krymux/zstd"  # everything
# artifacts: target/release/krymux-tunnel and target/release/krymux-sync — no runtime dependencies
```

Compilación cruzada para Linux (despliegue en un servidor o LXD):

```bash
rustup target add x86_64-unknown-linux-gnu
# with a Linux-side linker: cargo build --release --target x86_64-unknown-linux-gnu
# or use cross / cargo-zigbuild
```

Nota: la compilación base anuncia `none`/`deflate`/`brotli` en la negociación HELLO; `zstd` requiere la característica `zstd`.

## Inicio rápido

Comandos de la CLI (misma estructura que la versión de Node):

| Comando | Propósito |
|---|---|
| `krymux-tunnel keygen --out <dir> --role server\|client [--name x] [--cn cn]` | Genera una identidad Ed25519 (clave + certificado autofirmado + huella) |
| `krymux-tunnel fingerprint <key-or-cert.pem>` | Imprime la huella de un archivo PEM |
| `krymux-tunnel probe <host:port>` | Muestra la huella de clave de un servidor (auxiliar de TOFU) |
| `krymux-tunnel server --config server.json` | Ejecuta el servidor de proxy inverso |
| `krymux-tunnel client --config client.json [--socks5 h:p] [--http-proxy h:p]` | Ejecuta el cliente (opcionalmente con frontends de proxy locales) |
| `krymux-sync sync-server --path <dir> [--port 17890] [--mode bidir\|readonly]` | Ejecuta un servidor de sincronización de archivos detrás de krymux |
| `krymux-sync sync-client --path <dir> --config client.json [--mode …] [--watch] [--interval 30]` | Ejecuta un cliente de sincronización de archivos a través del túnel |

### 1. Genera identidades en ambos extremos

```bash
./target/release/krymux-tunnel keygen --out ./keys --role server
./target/release/krymux-tunnel keygen --out ./keys --role client --name alice
```

Cada comando imprime la huella `sha256:` de la identidad.

### 2. (TOFU) Comprueba la huella del servidor

Si todavía no conoces la huella del servidor, verifícala una vez por un canal fuera de banda y escríbela en la configuración:

```bash
./target/release/krymux-tunnel probe frp.example.com:7000
```

### 3. Configuración del servidor (en la máquina del servicio — este es el puerto al que frpc reenvía)

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

### 4. Configuración del cliente (en cualquier lugar)

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

### 5. Úsalo

Apunta un navegador o curl al proxy SOCKS5 local — **el hostname se convierte en la clave de enrutado por vhost**:

```bash
curl --socks5-hostname 127.0.0.1:1080 http://nas.example/
```

`--http-proxy 127.0.0.1:8080` proporciona en su lugar un frontend de proxy HTTP/1.1 (CONNECT + forma absoluta). Los campos de configuración son idénticos a los de la versión de Node; véase [`../ectun/examples/`](../ectun/examples/) para escenarios completos.

## Sincronización de archivos

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

### Motor de sincronización

- **Bidireccional**: descarga servidor → cliente y subida cliente → servidor, impulsado por **comparación de hash SHA-1**, **alineación del desfase de reloj de mtime** entre las dos máquinas, **escrituras atómicas** (archivo temporal → renombrado) y **detección de bloqueos**.
- **El modo de solo lectura se negocia** mediante `hello_ack`: cuando el servidor está en modo de solo lectura, el cliente suprime automáticamente las subidas, y el servidor sigue rechazando `put` en cualquier caso.
- **Informe de conflictos** para ediciones concurrentes (véanse las semánticas multicliente más abajo).
- **Protección contra path traversal**: los segmentos `..`, las rutas absolutas y las letras de unidad siempre se rechazan.

### Daemon de watch (`--watch`, `apps/krymux-sync/src/sync/daemon.rs`)

- **Cambios locales** → eventos de notify con un **período de reposo por debounce de 700 ms**, omitiendo `*.sync-tmp` y los eventos de lectura (inotify notifica como cambios las lecturas de hash de nuestro propio escaneo; sin filtrar, esto se autodispara en bucle en Linux).
- **Cambios remotos** → enviados proactivamente por el servidor (`rescan_hint`): sync-server vigila su propio árbol (`apps/krymux-sync/src/sync/notify.rs`) y notifica a los daemons conectados inmediatamente al producirse un cambio — el hint llega en cuestión de segundos. Los hints se **suprimen mientras hay una sesión de sincronización activa** (para que el servidor no haga eco de las subidas que está recibiendo); un único hint fusionado se dispara al final de la sesión, que es también lo que propaga los cambios a otros clientes. Los servidores antiguos sin soporte de hints degradan silenciosamente y el intervalo toma el relevo.
- La conciliación periódica de **`--interval`** (por defecto 30 s) es ahora una **red de seguridad** (hints perdidos / servidores antiguos) y no el mecanismo principal.
- **Reconexión**: ante la pérdida del túnel, la siguiente pasada falla y reconstruye el túnel con retroceso exponencial desde 1 s, con tope de 60 s.
- **Seguro ante kill en cualquier momento**: todas las escrituras pasan por tmp+rename y los escaneos omiten los residuos.

### Semánticas multicliente

N clientes pueden sincronizar simultáneamente la misma raíz del servidor. Los cambios de un cliente se difunden a los demás en cuestión de segundos mediante el hint de fin de sesión (sin esperar al intervalo). Las ediciones concurrentes del mismo archivo convergen según **last-writer-wins por mtime** — todos los extremos acaban coincidiendo, sin contenido mixto.

### Bloqueos y conflictos de arranque (verificados por las 8 fases de `edge-e2e.sh`)

- **Exclusión mutua de la raíz**: sync-server/sync-client toman un bloqueo de archivo exclusivo del sistema operativo sobre `<root>/.sync.lock` al arrancar (API nativa de std 1.89: `LockFileEx` en Windows, `flock` en Unix). Un segundo proceso sobre la misma raíz se rechaza de plano; un proceso que se cuelga libera el bloqueo automáticamente — no hace falta recuperación de bloqueos huérfanos.
- **Comprobación de bloqueos al arrancar**: si otro proceso mantiene en exclusiva cualquier archivo de la raíz, el arranque se rechaza y se listan los archivos implicados.
- **Bloqueos en tiempo de ejecución**: los archivos bloqueados del lado del cliente se omiten en esa pasada (sin tocar). Los archivos bloqueados o ilegibles del lado del servidor (incluidos los fallos de lectura durante el escaneo = hash `None`) se tratan como *indeterminables → omitir esta pasada*, nunca se clasifican erróneamente como conflictos.
- **Residuos de cuelgue**: un `kill -9` en cualquier momento es seguro (atomicidad de tmp+rename; probado E2E con 500 MB, sin truncamientos). Los archivos `*.sync-tmp` obsoletos de ≥ 1 h se limpian al arrancar.
- **Aislamiento de fallos puntuales**: un único archivo no instalable (p. ej., un marcador de posición de directorio) se omite sin privar de recursos al resto de la pasada; una verificación de descarga fallida (tamaño/hash) se reintenta una vez dentro de la pasada.
- **Límite de la verificación**: la ruta de extremo a extremo de los bloqueos de archivo está verificada en Windows (infracciones de uso compartido reales); los contenedores Linux sin privilegios no pueden simular archivos no escribibles (root ignora chmod; chattr necesita `CAP_LINUX_IMMUTABLE`), así que el lado Linux se verifica mediante exclusión `flock` entre dos procesos más pruebas de kill y reanimación.

### Compatibilidad entre sistemas operativos (Windows ↔ Linux, probada a través de un relé simulado con proxy LXD)

- **Capa de conexión**: resolución de múltiples direcciones con intentos secuenciales y un **tiempo de espera independiente de 5 s por dirección** — los nombres mDNS/DNS con varios registros A/AAAA ya no agotan el presupuesto de conexiones cuando IPv6 está en blackhole (observado con `myhost.local` devolviendo 3×IPv6 + 2×IPv4, donde el IPv6 en blackhole provocaba tiempos de espera garantizados).
- **Nombres de archivo**: UTF-8 (nombres de archivo en chino + contenido) sin pérdida en ambas direcciones; los **nombres ilegales en Windows** (`<>:"|?*`, nombres reservados como `CON`/`COM1`, puntos/espacios finales) se omiten con una advertencia; las **colisiones de mayúsculas/minúsculas** (Linux `Foo.txt` + `foo.txt`) generan advertencia en todas las plataformas, y las plataformas que ignoran mayúsculas/minúsculas solo sincronizan el nombre visto primero (evitando el vaivén perpetuo de descarga-sobrescritura); las rutas largas funcionan (prefijo `\\?\` de Windows, probado con 212 caracteres).
- **Enlaces simbólicos**: se omiten según la semántica de `lstat` (no se siguen, no se propagan, sin riesgo de ciclos).
- **mtime entre sistemas de archivos**: los ciclos de ida y vuelta NTFS↔ext4 permanecen estables gracias al cortocircuito por hash (contenido idéntico = no-op).
- **Límite**: macOS (vigilante FSEvents) nunca se ha compilado ni ejecutado — sin verificar.

### Propagación de borrados (tombstones)

Los borrados se propagan a todos los clientes (`.sync-tombstones.json`, caducidad de 30 días, protección last-writer por mtime corregida del desfase de reloj, supresión readonly en ambos sentidos); un archivo editado en otro lugar tras el borrado gana con el contenido más reciente. `deletion-semantics-probe.sh` verifica ambas direcciones sin resurrección. Nota: los números de rendimiento hacen fe en la versión en inglés y en `bench/BASELINE.md`.

## Acceso desde el navegador (WebSocket)

El servidor atiende tres clases de conexión en el **mismo puerto TLS**, en modo dual por detección: clientes mTLS nativos (certificado Ed25519 + ALPN `krymux`) frente a todo lo que llegue sin certificado de cliente, donde un `GET` HTTP se bifurca hacia la ruta WebSocket/estática. frp simplemente sigue reenviando texto cifrado TCP — sin configuración adicional.

1. Arranca el servidor. Este genera automáticamente una identidad de navegador (`ws-p256.key.pem`, P-256) y registra su `wsFingerprint` en el log.
2. Abre `https://<frps-public-port>/` en un navegador (acepta una vez la excepción del certificado autofirmado) — se carga la página de lanzamiento integrada.
3. Añade a `auth.fingerprints` del servidor la huella de identidad mostrada en la página — la **misma lista blanca** que usan los clientes nativos.
4. Recarga, introduce un `host:port` de destino y conéctate — cualquier servicio enrutado queda al alcance de la pestaña del navegador.

La autenticación es equivalente en fuerza a mTLS: una única lista blanca `sha256(SPKI)` mezcla entradas Ed25519 (nativas) y P-256 (navegador); la firma de la capa de aplicación del cliente demuestra la identidad de la lista blanca, y la firma del servidor demuestra la identidad fijada (dentro de TLS). El servidor de Rust aplica un tiempo de espera de autenticación de 10 s y un tope de 256 conexiones WS concurrentes. El SDK es un ESM de un solo archivo y cero dependencias (`ectun-browser.mjs`, incluido en este repositorio en `browser/ectun-browser.mjs` — sírvelo o impórtalo; el protocolo de cable es idéntico):

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

El SDK v1 anuncia compresión `none` (la negociación CMPX está lista para mejoras futuras). Detalles del protocolo: [`../ectun/docs/PROTOCOL.md` §6A](../ectun/docs/PROTOCOL.md).

## Verificación

```bash
bash e2e-sync-test.sh   # file sync: 9-phase main flow
bash edge-e2e.sh        # file sync: 8 edge phases (locks / crash / conflicts)
```

- **Interoperabilidad 11/11** frente a la referencia en Node (`interop/test-interop.mjs`):
  - Cliente Node → servidor Rust: eco de 1 MB con none/deflate/brotli idéntico byte a byte, enrutado dual por vhost, objetivo sin ruta rechazado, clave fuera de la lista blanca rechazada;
  - Cliente Rust → servidor Rust: SOCKS5 + vhost (ejercitado con curl);
  - Cliente Rust → servidor Node: eco de 1 MB con none/deflate/brotli idéntico byte a byte.
- **Interoperabilidad de huellas**: el comando `fingerprint` de Node calcula el mismo valor para los certificados generados por el keygen de Rust y viceversa.
- **Plantilla de despliegue LXC**: configuración de dos contenedores en [`deploy/lxc/`](deploy/lxc/) — `server.json` / `client.json` / unidades systemd para server, sync-server y sync-client(s). Resultados en máquina real: 100 MB transferidos idénticos por md5, propagación entre clientes en ~2 s, entrega de rescan-hint en ~1 s.

## Rendimiento

Benchmarks en loopback (cifras de Node tomadas de la referencia en Node, Node 24.15, véase [`../ectun/docs/BENCHMARKS.md`](../ectun/docs/BENCHMARKS.md); cifras de Rust de `examples/bench`, eco de 16 MB):

| Configuración | Rendimiento |
|---|---|
| Rust, eco de 16 MB, sin compresión | ~405 MB/s |
| Rust, eco de 16 MB, zstd (texto compresible) | ~739 MB/s |
| Referencia Node, sin compresión (×1/×4 streams) | ~80 MB/s (techo de JS a un solo núcleo) |
| Referencia Node, zstd ×4 streams (texto) | ~319 MB/s |
| Referencia Node, brotli ×4 streams (texto) | ~285 MB/s |
| **Crecimiento automático de ventana, stream único @ 50 ms de RTT** | **4,0 → 32,4 MB/s** (fijo 256 KB → automático hasta 4 MB) |
| A través de un relé TCP (frp simulado) | sin penalización medible |
| Latencia de apertura de stream | p50 0,28 ms (dentro de una conexión establecida) |
| Handshake TLS completo | ~6 ms (loopback) |

La compresión a menudo *aumenta* el rendimiento (menos bytes por el cable); el cuello de botella de ventana en enlaces frp reales queda eliminado por el crecimiento automático, dejando el ancho de banda público y la CPU de compresión como límites.

## Referencia de configuración

JSON con claves camelCase, esquema idéntico en ambas implementaciones.

### server.json

| Campo | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `listen` | string | *obligatorio* | `host:port` en el que escuchar; el `localPort` de frpc apunta aquí |
| `identity.key`, `identity.cert` | string | *obligatorio* | rutas PEM Ed25519 procedentes de `keygen` |
| `auth.mode` | string | `"whitelist"` | modo de admisión |
| `auth.fingerprints` | string[] | `[]` | lista blanca `sha256(SPKI)` de clientes (las entradas de `auth.clients` se fusionan) |
| `routes[].host` (alias `hosts`) | string or string[] | — | claves de coincidencia de vhost; comodines como `*.example` |
| `routes[].port` (alias `ports`) | number, `"n"`, `"a-b"`, `"*"`, or array | — | patrón de puertos opcional para la ruta |
| `routes[].upstream` | `[host, port]`, `"host:port"`, `"unix:/path"`, or `{host, port}` / `{unix}` | — | destino al que se entrega el tráfico coincidente |
| `fallbackUpstream` (alias `defaultUpstream`) | upstream | — | ruta para hosts que no coinciden con ninguna ruta |
| `clientTargets.enabled` | bool | `false` | permite que los clientes especifiquen objetivos `host:port` arbitrarios |
| `clientTargets.allowHosts` | string[] | `["*"]` | patrones de host que un cliente puede elegir |
| `clientTargets.allowPorts` | pattern[] | — | patrones de puertos que un cliente puede elegir |
| `keepaliveSec` | integer | `30` | intervalo de keepalive |
| `maxStreams` | integer | `1024` | máximo de streams lógicos por conexión |
| `rxWindow` | integer | `262144` (256 KB) | ventana de recepción inicial por stream |
| `rxWindowMax` | integer | `4194304` (4 MB) | tope del crecimiento automático; fijar igual a `rxWindow` para desactivar el crecimiento |
| `log.level` | string | `"info"` | nivel de log |
| `statsIntervalMs` | integer | — | impresión periódica de estadísticas |

### client.json

| Campo | Tipo | Por defecto | Descripción |
|---|---|---|---|
| `endpoint` | string | *obligatorio* | `host:port` público expuesto por frps |
| `identity.key`, `identity.cert` | string | *obligatorio* | rutas PEM Ed25519 del cliente |
| `serverFingerprint` | string | *obligatorio* | huella fijada del servidor `sha256:…` |
| `compression` | string | `"auto"` | `none` / `auto` / `deflate` / `brotli` / `zstd` (compilación con zstd), o preajustes de nivel como `"zstd:9"`, `"brotli:11"`, `"deflate:9"` (se aplica al lado emisor) |
| `keepaliveSec` | integer | `30` | intervalo de keepalive |
| `rxWindow` | integer | `262144` (256 KB) | ventana de recepción inicial por stream (configurable en ambos extremos) |
| `rxWindowMax` | integer | `4194304` (4 MB) | tope del crecimiento automático |
| `socks5` | string | — | dirección del frontend SOCKS5 local, p. ej. `127.0.0.1:1080` |
| `httpProxy` | string | — | frontend local de proxy HTTP/1.1 (CONNECT + forma absoluta) |
| `log.level` | string | `"info"` | nivel de log |

Crecimiento automático de ventana: cuando un stream ha consumido más de la mitad de su ventana y la ha vaciado, la concesión se duplica cada 100 ms; los streams con contrapresión no crecen. Ambos extremos pueden configurar `rxWindow`/`rxWindowMax`; `rxWindowMax = rxWindow` desactiva el crecimiento.

## Solución de problemas

- `KRYMUX_LOG=debug` para logging de depuración.
- `KRYMUX_MUX_TRACE=1` para trazas a nivel de trama en stderr (incluidos los flags).

## Hoja de ruta

- **Propagación de borrados** (tombstones: un directorio `.sync-tombstones` con limpieza basada en expiración).
- **Diccionarios zstd (`zstdd`)** — diseño finalizado: entrenamiento offline con `zstd --train`, ambos lados referenciando el mismo diccionario, negociación de compresión `zstdd` en HELLO con comprobación del sufijo de huella del diccionario; se esperan primeros paquetes 2–4× más pequeños en streams cortos (HTTP/API). El lado Node necesita un binding nativo o un repliegue negociado a zstd simple.
- **Agrupación en buckets de la longitud de trama PAD** con tráfico de cobertura a ritmo fijo (reservado en el protocolo v1.1).
- Rendimiento en **clúster / multinúcleo**.
- Soporte de **UDP**.
- **SDKs de Go / Python**.
- **Derivación de claves estilo Noise** para la autenticación WS.
- Compilación y verificación en **macOS** (vigilante FSEvents).

## Licencia

MIT
